"""A real on-host TLS 1.3 / separate-UID witness acceptance fixture.

This is NOT an independent/off-host security witness or an external pentest.
The test is skipped when it cannot create a separate unprivileged process.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from catl.witness_protocol import WitnessClient, https_witness_transport, WitnessRejected


ROOT = Path(__file__).resolve().parents[1]


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _create_cert(ca_key, ca_cert, key, common_name, *, client=False):
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False),critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([
             ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    if not client:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
    return builder.sign(ca_key, hashes.SHA256())


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'requires root to spawn a distinct unprivileged witness UID')
class LiveMTLSWitnessTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix='catl-mtls-fixture-', dir='/tmp')
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.root.chmod(0o711)
        self.server_dir = self.root / 'witness'
        self.server_dir.mkdir(mode=0o700)
        import pwd
        account = pwd.getpwnam('nobody')
        self.server_uid, self.server_gid = account.pw_uid, account.pw_gid
        os.chown(self.server_dir, self.server_uid, self.server_gid)
        # A trust-root generated only for this disposable fixture.
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.timezone.utc)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CATL local test CA')])
        ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0),critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False),critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
            .sign(ca_key, hashes.SHA256()))
        self.ca_file = self.root/'ca.pem'
        self.ca_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        self.ca_file.chmod(0o644)
        svr_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        client_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        svr_cert = _create_cert(ca_key,ca_cert,svr_key,'localhost')
        client_cert = _create_cert(ca_key,ca_cert,client_key,'CATL broker fixture',client=True)
        stranger_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        stranger_cert = _create_cert(ca_key,ca_cert,stranger_key,'OTHER CA-authorized fixture',client=True)
        self.stranger_cert = self.root/'stranger.pem'
        self.stranger_key = self.root/'stranger-key.pem'
        self.stranger_cert.write_bytes(stranger_cert.public_bytes(serialization.Encoding.PEM))
        self.stranger_key.write_bytes(_pem(stranger_key))
        self.stranger_key.chmod(0o600)
        self.tls_cert=self.server_dir/'server-cert.pem'
        self.tls_key=self.server_dir/'server-key.pem'
        self.tls_cert.write_bytes(svr_cert.public_bytes(serialization.Encoding.PEM))
        self.tls_key.write_bytes(_pem(svr_key))
        for path in (self.tls_cert,self.tls_key):
            os.chown(path,self.server_uid,self.server_gid)
            path.chmod(0o600)
        self.client_cert=self.root/'client.pem'
        self.client_key=self.root/'client-key.pem'
        self.client_cert_sha256 = hashlib.sha256(client_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        self.client_cert.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
        self.client_key.write_bytes(_pem(client_key))
        self.client_key.chmod(0o600)
        self.witness_key=ed25519.Ed25519PrivateKey.generate()
        self.witness_key_path=self.server_dir/'witness.pem'
        self.witness_key_path.write_bytes(_pem(self.witness_key))
        os.chown(self.witness_key_path,self.server_uid,self.server_gid)
        self.witness_key_path.chmod(0o600)
        self.database=self.server_dir/'heads.db'
        self.ctx=ssl.create_default_context(cafile=str(self.ca_file))
        self.ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        self.ctx.load_cert_chain(str(self.client_cert),str(self.client_key))
        self.start_server()
        self.addCleanup(self.stop_server)

    def start_server(self, allowed_ips=None):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1',0))
            self.port=s.getsockname()[1]
        cmd=[sys.executable,str(ROOT/'tools/witness_service.py'),
             '--database',str(self.database),'--signing-key',str(self.witness_key_path),
             '--tls-cert',str(self.tls_cert),'--tls-key',str(self.tls_key),
             '--client-ca',str(self.ca_file),'--client-cert-sha256',self.client_cert_sha256,
             '--listen','127.0.0.1','--port',str(self.port)]
        for allowed in (allowed_ips or ('127.0.0.1',)):
            cmd.extend(['--allow-client-ip',allowed])
        self.server=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,user=self.server_uid,
            group=self.server_gid,extra_groups=[],cwd=str(self.server_dir),
            env={'PATH':'/usr/bin:/bin','PYTHONUNBUFFERED':'1','PYTHONDONTWRITEBYTECODE':'1'})
        for _ in range(60):
            if self.server.poll() is not None:
                _,err=self.server.communicate(timeout=1)
                self.fail(f'witness failed to start: {err.decode(errors="replace")}')
            try:
                with socket.create_connection(('127.0.0.1',self.port),timeout=.1):
                    break
            except OSError:
                time.sleep(.03)
        else:
            self.fail('witness socket failed to open')
        self.transport=https_witness_transport(f'https://localhost:{self.port}/v1/witness',
                                               ssl_context=self.ctx,timeout=2)
        self.client=WitnessClient(self.witness_key.public_key(),self.transport)

    def stop_server(self):
        if getattr(self,'server',None) is not None:
            self.server.terminate()
            try:self.server.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.communicate(timeout=3)
            self.server=None

    def test_live_signed_receipts_and_rollback_after_restart(self):
        zero={'ledger_id':'catl-live-fixture','sequence':0,'head_mac':'GENESIS'}
        self.assertEqual(self.client.witness(zero).sequence,0)
        one={'ledger_id':'catl-live-fixture','sequence':1,'head_mac':'b'*64}
        receipt=self.client.witness(one)
        self.assertEqual(receipt.sequence,1)
        self.stop_server()
        self.start_server()
        with self.assertRaises(HTTPError) as cm:
            self.client.witness(zero)
        self.assertEqual(cm.exception.code,400)
        self.assertEqual(self.client.witness(one).head_mac,'b'*64)
        with self.assertRaises(HTTPError):
            self.client.witness({'ledger_id':'catl-live-fixture','sequence':1,'head_mac':'c'*64})

    def test_other_client_signed_by_same_ca_is_denied(self):
        # CA membership alone must not grant the right to advance CATL audit
        # checkpoints. The independent witness pins the intended broker cert.
        other = ssl.create_default_context(cafile=str(self.ca_file))
        other.minimum_version = ssl.TLSVersion.TLSv1_3
        other.load_cert_chain(str(self.stranger_cert),str(self.stranger_key))
        candidate = https_witness_transport(f'https://localhost:{self.port}/v1/witness',
                                            ssl_context=other, timeout=2)
        with self.assertRaises(HTTPError) as error:
            candidate({'ledger_id':'unauthorised-client','sequence':0,'head_mac':'GENESIS'})
        self.assertEqual(error.exception.code,403)

    def test_unlisted_peer_ip_refused_before_tls_handshake(self):
        # Whitelist a different loopback source; 127.0.0.1 must be dropped by
        # the server before allocating any TLS worker or reading cert bytes.
        self.stop_server()
        self.start_server(allowed_ips=('127.0.0.2',))
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError, WitnessRejected)):
            self.client.witness({'ledger_id':'source-rejected','sequence':0,'head_mac':'GENESIS'})

    def test_tls_requires_client_certificate(self):
        no_client=ssl.create_default_context(cafile=str(self.ca_file))
        no_client.minimum_version=ssl.TLSVersion.TLSv1_3
        candidate=https_witness_transport(f'https://localhost:{self.port}/v1/witness',
                                          ssl_context=no_client, timeout=2)
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError, WitnessRejected)):
            candidate({'ledger_id':'other-ledger','sequence':0,'head_mac':'GENESIS'})

    def test_inherited_https_proxy_cannot_intercept_witness(self):
        # The proxy endpoint is deliberately unavailable. An inherited proxy
        # must not silently replace the mTLS-verified direct witness channel.
        with patch.dict(os.environ, {'HTTPS_PROXY':'http://127.0.0.1:1',
                                     'https_proxy':'http://127.0.0.1:1',
                                     'NO_PROXY':'', 'no_proxy':''}):
            received=self.client.witness({'ledger_id':'proxy-denied-ledger',
                                          'sequence':0,'head_mac':'GENESIS'})
        self.assertEqual(received.sequence,0)

    def test_tls_identity_is_pinned_to_hostname(self):
        with self.assertRaises(OSError):
            transport=https_witness_transport(
                f'https://127.0.0.1:{self.port}/v1/witness',ssl_context=self.ctx,timeout=2)
            transport({'ledger_id':'wrong-host-ledger','sequence':0,'head_mac':'GENESIS'})

    def test_held_open_plain_tcp_does_not_block_tls_accept_loop(self):
        # A malicious peer which never begins TLS must not stall get_request
        # and prevent a different authenticated client reaching the witness.
        with socket.create_connection(('127.0.0.1',self.port),timeout=2) as idle:
            started=time.monotonic()
            head={'ledger_id':'no-head-of-line-block', 'sequence':0,'head_mac':'GENESIS'}
            self.assertEqual(self.client.witness(head).sequence,0)
            self.assertLess(time.monotonic()-started, 2.0)

    def test_invalid_method_and_bounded_request_length(self):
        with socket.create_connection(('127.0.0.1',self.port),timeout=2) as sock:
            with self.ctx.wrap_socket(sock,server_hostname='localhost') as secure:
                secure.sendall(b'GET /v1/witness HTTP/1.1\r\nHost: localhost\r\n\r\n')
                self.assertIn(b'405',secure.recv(1024).split(b'\r\n',1)[0])
        bad=(b'POST /v1/witness HTTP/1.1\r\nHost: localhost\r\n'
             b'Content-Type: application/json\r\nContent-Length: 9999999\r\n\r\n')
        with socket.create_connection(('127.0.0.1',self.port),timeout=2) as sock:
            with self.ctx.wrap_socket(sock,server_hostname='localhost') as secure:
                secure.sendall(bad)
                self.assertIn(b'413',secure.recv(1024).split(b'\r\n',1)[0])

    def test_no_chunked_transfer_and_duplicate_length(self):
        raw=(b'POST /v1/witness HTTP/1.1\r\nHost: localhost\r\n'
             b'Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n'
             b'Content-Length: 2\r\n\r\n{}')
        dup=(b'POST /v1/witness HTTP/1.1\r\nHost: localhost\r\n'
             b'Content-Type: application/json\r\nContent-Length: 2\r\n'
             b'Content-Length: 2\r\n\r\n{}')
        for payload in (raw,dup):
            with self.subTest(payload=payload[:64]):
                with socket.create_connection(('127.0.0.1',self.port),timeout=2) as sock:
                    with self.ctx.wrap_socket(sock,server_hostname='localhost') as secure:
                        self.assertEqual(secure.version(),'TLSv1.3')
                        secure.sendall(payload)
                        response=secure.recv(1024)
                        self.assertIn(b'400',response.split(b'\r\n',1)[0])

if __name__=='__main__':unittest.main()
