"""Release-candidate adversarial invariants for authenticated throttle + path rules."""
from __future__ import annotations
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from catl.anchor import AnchorGuard
from catl.crypto import digest
from catl.policy import Policy
from catl.protocol import SERVER_INFO
from catl import __version__
from catl.store import State


def policy_for(condition):
    tool = {"name": "files.read", "inputSchema": {"type": "object"}}
    return Policy.from_dict({"agent_id": "test", "tool_pins": {"files.read": digest(tool)},
        "rules": [{"tool": "files.read", "effect": "allow", "conditions": [condition]}]})

class RateSecurity(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = Path(d.name)
        self.state = State(self.root / 'state.db', b'K' * 32)

    def test_legacy_sqlite_rate_row_poisoning_cannot_change_quota(self):
        self.assertTrue(self.state.acquire_rate('agent', 'tool', 2))
        with sqlite3.connect(self.state.path) as db:
            db.execute('DELETE FROM tool_rate')
            db.execute("INSERT INTO tool_rate VALUES('agent','tool',0,-10000)")
        self.assertTrue(self.state.acquire_rate('agent', 'tool', 2))
        self.assertFalse(self.state.acquire_rate('agent', 'tool', 2))
        with sqlite3.connect(self.state.path) as db:
            db.execute("UPDATE tool_rate SET count=0,window=0")
        self.assertFalse(self.state.acquire_rate('agent','tool',2))

    def test_authenticated_quota_events_are_domain_scoped(self):
        self.assertTrue(self.state.acquire_rate('a','one',1))
        self.assertFalse(self.state.acquire_rate('a','one',1))
        self.assertTrue(self.state.acquire_rate('a','two',1))
        self.assertTrue(self.state.acquire_rate('b','one',1))

    def test_tampered_quota_receipt_fails_closed(self):
        self.state.acquire_rate('a', 'one', 1)
        with sqlite3.connect(self.state.path) as db:
            db.execute("UPDATE receipts SET body='{}' WHERE seq=1")
        with self.assertRaises(PermissionError):
            self.state.acquire_rate('a','one',1)

    def test_window_rollover_is_authenticated(self):
        with patch('catl.store.time.time',return_value=60*100):
            self.assertTrue(self.state.acquire_rate('a','one',1))
            self.assertFalse(self.state.acquire_rate('a','one',1))
        with patch('catl.store.time.time',return_value=60*101):
            self.assertTrue(self.state.acquire_rate('a','one',1))

    def test_anchor_rollback_blocks_grant(self):
        path=self.root/'anchored.json'
        AnchorGuard(path,b'K'*32).bootstrap(0,'GENESIS')
        state=State(self.state.path,b'K'*32,anchor_path=path)
        self.assertTrue(state.acquire_rate('a','one',1))
        with sqlite3.connect(state.path) as db:
            db.execute('DELETE FROM receipts WHERE seq=1')
        with self.assertRaises(PermissionError):
            state.acquire_rate('a','one',1)

    def test_streamed_chain_verifier_handles_long_history(self):
        for i in range(200):
            self.state.append({'decision':'test','i':i})
        self.assertTrue(self.state.verify()['valid'])
        self.assertEqual(self.state.verify()['count'],200)

    def test_invalid_rate_bounds(self):
        for n in [0,-1,601,True,1.2]:
            with self.assertRaises(ValueError):
                self.state.acquire_rate('a','one',n)

class PathSecurity(unittest.TestCase):
    def setUp(self):
        self.policy=policy_for({'pointer':'/target','op':'path_within','value':'/safe'})

    def test_allowed_child(self):
        for path in ['/safe','/safe/x','/safe/x/y']:
            self.assertEqual(self.policy.evaluate('files.read',{'target':path}),'allow')

    def test_denied_sibling_prefix(self):
        for path in ['/safe-evil','/safety','/unsafe']:
            self.assertEqual(self.policy.evaluate('files.read',{'target':path}),'deny')

    def test_denied_escape_and_windows_paths(self):
        for path in ['/safe/../etc/shadow','../safe/x','safe/x','C:\\safe\\x',
                     '/safe\\..\\Windows','/safe//x','/safe\x00/x']:
            self.assertEqual(self.policy.evaluate('files.read',{'target':path}),'deny',path)

    def test_path_rule_requires_absolute_root(self):
        p=policy_for({'pointer':'/target','op':'path_within','value':'safe'})
        self.assertEqual(p.evaluate('files.read',{'target':'/safe/x'}),'deny')

class MetadataSecurity(unittest.TestCase):
    def test_reported_server_version_is_release_candidate(self):
        self.assertEqual(SERVER_INFO['version'],__version__)

if __name__=='__main__':
    unittest.main()


class HandshakeSecurity(unittest.TestCase):
    def test_disarmed_handshake_does_not_touch_backend(self):
        import tempfile
        from catl.gateway import Gateway
        class Spy:
            def __init__(self): self.calls=[]
            def request(self,method,params=None):
                self.calls.append(method)
                raise AssertionError('backend must remain untouched')
            def notify(self,method,params=None): self.calls.append(method)
            def close(self): pass
        with tempfile.TemporaryDirectory() as tmp:
            state=State(Path(tmp)/'db', b'Z'*32)
            spy=Spy()
            gateway=Gateway(Policy.from_dict({'agent_id':'a','tool_pins':{},'rules':[]}),state,spy)
            resp=gateway.handle({'jsonrpc':'2.0','id':1,'method':'initialize',
                'params':{'protocolVersion':'2025-11-25',
                          'clientInfo':{'name':'malicious','version':'1'},
                          'capabilities':{'sampling':{}}}})
            self.assertEqual(set(resp['result']['capabilities']),{'tools'})
            self.assertEqual(spy.calls,[])
            gateway.handle({'jsonrpc':'2.0','method':'notifications/initialized'})
            self.assertEqual(spy.calls,[])

    def test_unknown_legacy_version_rejected(self):
        from catl.gateway import Gateway
        class Spy:
            def request(self,*args,**kwargs): raise AssertionError('backend reached')
            def notify(self,*args,**kwargs): raise AssertionError('backend reached')
        with tempfile.TemporaryDirectory() as tmp:
            gw=Gateway(Policy.from_dict({'agent_id':'a','tool_pins':{},'rules':[]}),
                 State(Path(tmp)/'db',b'K'*32),Spy())
            result=gw.handle({'jsonrpc':'2.0','id':1,'method':'initialize',
                'params':{'protocolVersion':'2040-01-01'}})
            self.assertEqual(result['error']['message'],'unsupported_protocol_version')
