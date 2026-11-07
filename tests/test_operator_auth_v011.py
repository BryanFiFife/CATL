"""Replay, forgery and permissions tests for optional Ed25519 operator co-signing."""
from __future__ import annotations
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from catl.operator_auth import (OperatorAuthorizer, SoftwareOperatorSigner,
    CHALLENGE_TTL_SECONDS, MAX_OUTSTANDING_CHALLENGES, generate_test_software_keypair,
    signature_required)
from catl.broker import BrokerServer, OperatorClient
from catl.gateway import Gateway
from catl.store import State
from catl.policy import Policy

class Backend:
    def request(self, method, params=None):
        if method=='initialize': return {'result':{'protocolVersion':'2025-11-25','capabilities':{},'serverInfo':{'name':'fake','version':'1'}}}
        if method=='tools/list':return {'result':{'tools':[]}}
        raise RuntimeError('unused')
    def notify(self,*a,**kw):pass
    def close(self):pass

class SignedOperatorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.private=root/'operator-priv.pem';self.public=root/'operator-pub.hex'
        generate_test_software_keypair(self.private,self.public)
        self.signer=SoftwareOperatorSigner(self.private)
        self.auth=OperatorAuthorizer(self.public)
        self.command={'op':'set_feature','feature':'gateway_enabled','enabled':True}
        self.uid=os.geteuid() if os.name=='posix' else 5000

    def signed(self, command=None, uid=None):
        command=self.command if command is None else command
        uid=self.uid if uid is None else uid
        challenge=self.auth.issue(command,uid)
        return command, uid, challenge['challenge'], self.signer.sign_hex(challenge['message_hex'])

    def test_authentic_privilege_grant_exactly_once(self):
        data=self.signed()
        self.assertEqual(self.auth.verify_and_consume(*data), self.command)
        with self.assertRaisesRegex(PermissionError,'replayed'):
            self.auth.verify_and_consume(*data)

    def test_command_tampering_consumes_challenge(self):
        command, uid, token, signature=self.signed()
        modified={**command,'feature':'approvals_enabled'}
        with self.assertRaises((PermissionError,ValueError)):
            self.auth.verify_and_consume(modified,uid,token,signature)
        with self.assertRaisesRegex(PermissionError,'replayed'):
            self.auth.verify_and_consume(command,uid,token,signature)

    def test_wrong_identity_rejected(self):
        command, uid, token, signature=self.signed()
        with self.assertRaises(PermissionError):
            self.auth.verify_and_consume(command,uid+1,token,signature)

    def test_signature_forgery_fails(self):
        command, uid, token, _signature=self.signed()
        with self.assertRaisesRegex(PermissionError,'signature_invalid'):
            self.auth.verify_and_consume(command,uid,token,'00'*64)

    def test_wrong_key_fails(self):
        other=Path(self.temp.name)/'other-key.pem'
        otherpub=Path(self.temp.name)/'other-pub.hex'
        generate_test_software_keypair(other,otherpub)
        challenge=self.auth.issue(self.command,self.uid)
        with self.assertRaises(PermissionError):
            self.auth.verify_and_consume(self.command,self.uid,challenge['challenge'],
                SoftwareOperatorSigner(other).sign_hex(challenge['message_hex']))

    def test_expired_nonce_fails(self):
        start=time.monotonic()
        with patch('catl.operator_auth.time.monotonic',return_value=start):
            data=self.signed()
        with patch('catl.operator_auth.time.monotonic',return_value=start+CHALLENGE_TTL_SECONDS+1):
            with self.assertRaisesRegex(PermissionError,'expired'):
                self.auth.verify_and_consume(*data)

    def test_command_whitespace_or_extra_field_changes_signature(self):
        command, uid, token, signature=self.signed()
        modified={**command,'audit':'false'}
        with self.assertRaises(PermissionError):
            self.auth.verify_and_consume(modified,uid,token,signature)


    @unittest.skipUnless(os.name == "posix", "requires kernel operator UID")
    def test_operator_client_never_signs_arbitrary_server_bytes(self):
        """A hostile operator endpoint must not turn the client into a signing oracle."""
        command = self.command
        challenge = self.auth.issue(command, self.uid)
        forged = dict(challenge)
        # Echo a cryptographically valid message for a DIFFERENT command.
        forged['message_hex'] = OperatorAuthorizer._data(
            {'op': 'set_tool', 'tool': 'admin', 'enabled': True},
            self.uid, forged['challenge']).hex()
        client = OperatorClient(Path(self.temp.name) / 'unused.sock', signing_key=self.private)
        with patch('catl.broker._exchange', return_value={'ok': True, 'result': forged}) as exchange:
            with patch.object(client.signer, 'sign_hex') as sign:
                with self.assertRaisesRegex(PermissionError, 'challenge_command_mismatch'):
                    client._rpc(command)
                sign.assert_not_called()
                self.assertEqual(exchange.call_count, 1)

    @unittest.skipUnless(os.name == "posix", "requires kernel operator UID")
    def test_operator_client_rejects_bad_challenge_scheme_without_signing(self):
        command = self.command
        challenge = self.auth.issue(command, self.uid)
        forged = {**challenge, 'scheme': 'Ed25519/unknown'}
        client = OperatorClient(Path(self.temp.name) / 'unused.sock', signing_key=self.private)
        with patch('catl.broker._exchange', return_value={'ok': True, 'result': forged}):
            with patch.object(client.signer, 'sign_hex') as sign:
                with self.assertRaisesRegex(PermissionError, 'challenge_invalid_response'):
                    client._rpc(command)
                sign.assert_not_called()

    def test_non_grant_operations_need_no_signature(self):
        for command in ({'op':'status'},{'op':'pending'},{'op':'decide','id':'x','approve':False},
                        {'op':'set_feature','feature':'gateway_enabled','enabled':False},
                        {'op':'set_tool','tool':'danger','enabled':False},
                        {'op':'set_all_tools','enabled':False}):
            self.assertFalse(signature_required(command))
            with self.assertRaisesRegex(ValueError,'not_signable'):
                self.auth.issue(command,self.uid)
        for command in ({'op':'decide','id':'x','approve':True},
                        {'op':'reconcile_incident','action_id':'a'},
                        {'op':'set_tool','tool':'safe','enabled':True},
                        {'op':'set_feature','feature':'gateway_enabled','enabled':'true'},
                        {'op':'future_new_method'}):
            self.assertTrue(signature_required(command))

    def test_capacity_bounded(self):
        for _ in range(MAX_OUTSTANDING_CHALLENGES):
            self.auth.issue(self.command,self.uid)
        with self.assertRaisesRegex(PermissionError,'capacity'):
            self.auth.issue(self.command,self.uid)

    def test_private_key_permissions_and_symlinks(self):
        if os.name != 'posix':self.skipTest('POSIX permissions only')
        self.private.chmod(0o644)
        with self.assertRaisesRegex(PermissionError,'permissions'):
            SoftwareOperatorSigner(self.private)
        self.private.chmod(0o600)
        link=Path(self.temp.name)/'link'
        link.symlink_to(self.private)
        with self.assertRaisesRegex(PermissionError,'symlink'):
            SoftwareOperatorSigner(link)

    def test_public_key_parent_must_be_protected(self):
        if os.name != 'posix':self.skipTest('POSIX permissions only')
        root=Path(self.temp.name);root.chmod(0o777)
        with self.assertRaisesRegex(PermissionError,'parent_untrusted'):
            OperatorAuthorizer(self.public)
        root.chmod(0o700)

    def test_keygen_does_not_overwrite(self):
        with self.assertRaises(FileExistsError):
            generate_test_software_keypair(self.private,self.public)

    @unittest.skipUnless(__import__('sys').platform=='linux', 'kernel peer credentials are Linux-only')
    def test_broker_unsigned_grant_denied_and_signed_grant_succeeds(self):
        root=Path(self.temp.name)
        state=State(root/'state.sqlite3',b'S'*32)
        policy=Policy.from_dict({'agent_id':'operator-signing', 'tool_pins':{},'rules':[]})
        broker=BrokerServer(Gateway(policy,state,Backend()),state,policy,
            agent_socket=root/'agent.sock', operator_socket=root/'operator.sock',
            agent_uid=self.uid+5000,operator_uid=self.uid, allow_test_same_uid=True,
            operator_public_key=self.public)
        # This is a SAME-UID unit fixture, not the four-UID security integration.
        # The synthetic agent UID must remain different for SO_PEERCRED checks,
        # but an unprivileged CI runner cannot chown the agent socket to it.
        # Create both fixture sockets as the test UID, retaining mode 0600;
        # BrokerServer still rejects any agent connection with the wrong UID.
        # Separate-UID socket ownership is exercised in integration_rootless_e2e.py.
        from catl.broker import _prepare_socket as actual_prepare_socket
        def prepare_user_owned_fixture_socket(path, uid, gid, *, group_access=False):
            return actual_prepare_socket(path, os.geteuid(), os.getegid())
        fixture_patch = patch('catl.broker._prepare_socket',
                              side_effect=prepare_user_owned_fixture_socket)
        fixture_patch.start()
        self.addCleanup(fixture_patch.stop)
        server=threading.Thread(target=broker.serve,daemon=True);server.start()
        self.addCleanup(lambda: (broker.shutdown(),server.join(timeout=3)))
        for _ in range(150):
            if (root/'operator.sock').exists():break
            time.sleep(.01)
        self.assertTrue((root/'operator.sock').exists())
        # Attacker has the same operator UID, but no signing key.
        unsigned=OperatorClient(root/'operator.sock')
        with self.assertRaisesRegex(PermissionError,'signed_operator_authorization_required'):
            unsigned.set_feature('gateway_enabled',True,'not-human')
        self.assertFalse(unsigned.status()['controls']['gateway_enabled'])
        # Pause/deny remains available even without a signing key.
        unsigned.set_feature('gateway_enabled',False,'operator')
        signed=OperatorClient(root/'operator.sock',signing_key=self.private)
        self.assertTrue(signed.set_feature('gateway_enabled',True,'operator')['gateway_enabled'])
        self.assertFalse(unsigned.set_feature('gateway_enabled',False,'operator')['gateway_enabled'])
        # A previously intercepted signature cannot be submitted again.
        command={'op':'set_feature','feature':'gateway_enabled','enabled':True}
        reply=broker._op({'op':'challenge','command':command},self.uid)
        signature=self.signer.sign_hex(reply['message_hex'])
        accepted=broker._op({'op':'authorize','command':command,
            'challenge':reply['challenge'],'signature':signature},self.uid)
        self.assertTrue(accepted['controls']['gateway_enabled'])
        with self.assertRaisesRegex(PermissionError,'replayed'):
            broker._op({'op':'authorize','command':command,
                'challenge':reply['challenge'],'signature':signature},self.uid)
        self.assertTrue(state.verify()['valid'])

if __name__=='__main__':unittest.main()
