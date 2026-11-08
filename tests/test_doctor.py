from __future__ import annotations
import os
import sys
import stat
import tempfile
import unittest
from pathlib import Path

from catl.anchor import AnchorGuard
from catl.crypto import get_or_create_key
from catl.doctor import run_checks
from catl.store import State


@unittest.skipUnless(os.name == 'posix','requires POSIX mode checks')
class DoctorTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        import fixture_modes as fm
        fm.umask_022(self)
        self.root=Path(temp.name)
        self.state_dir=self.root/'state'
        self.anchor_dir=self.root/'anchor'
        self.state_dir.mkdir(mode=0o700)
        self.anchor_dir.mkdir(mode=0o700)
        self.anchor=self.anchor_dir/'head.json'
        self.config=self.root/'policy.json'
        self.config.write_text('{"agent_id":"example","tool_pins":{},"rules":[]}')
        self.key=get_or_create_key(self.state_dir/'audit.key')
        s=State(self.state_dir/'audit.sqlite3',self.key)
        chk=s.verify()
        AnchorGuard(self.anchor,self.key).bootstrap(chk['count'],chk['head_mac'])

    def check(self,**kw):
        opts={'config':self.config,'state_dir':self.state_dir,'anchor_path':self.anchor,
              'agent_uid':1801,'operator_uid':1802,'backend_uid':1803}
        opts.update(kw)
        actual=os.geteuid()
        # Non-root on normal CI. Privileged test environment: skip successful
        # broker identity check, which correctly treats root as a blocker.
        return run_checks(**opts)

    def test_valid_state_passes_integrity_but_warns_host_attestation(self):
        r=self.check()
        expected_failures = (2 if os.geteuid() == 0 else 0) + (0 if sys.platform == 'linux' else 1)
        self.assertEqual(r['failures'], expected_failures)
        self.assertIn('audit_chain', {x['check'] for x in r['checks'] if x['status']=='pass'})
        self.assertGreaterEqual(r['warnings'],2)
        self.assertEqual(r['ok'], expected_failures == 0)

    def test_strict_requires_host_attestation(self):
        self.assertFalse(self.check(strict=True)['ok'])

    def test_unverified_permitted_tool_is_explicit_warning(self):
        self.config.write_text('{"agent_id":"example","tool_pins":{"read":' + '"' + 'a'*64 + '"' + '},"rules":[{"tool":"read","effect":"allow","conditions":[]}]}')
        checks=self.check()['checks']
        assurance=[x for x in checks if x['check']=='tool_effect_assurance']
        self.assertEqual(len(assurance),1)
        self.assertEqual(assurance[0]['status'],'warn')

    def test_missing_anchor_fails_without_recreating(self):
        self.anchor.unlink()
        result=self.check()
        self.assertFalse(result['ok'])
        self.assertFalse(self.anchor.exists())

    def test_missing_key_fails_without_recreating(self):
        (self.state_dir/'audit.key').unlink()
        result=self.check()
        self.assertFalse(result['ok'])
        self.assertFalse((self.state_dir/'audit.key').exists())

    def test_same_uid_is_rejected(self):
        r=self.check(agent_uid=1802)
        self.assertIn('identity_separation', {i['check'] for i in r['checks'] if i['status']=='fail'})

    def test_checkpoint_inside_state_dir_rejected(self):
        copied=self.state_dir/'head.json'
        copied.write_bytes(self.anchor.read_bytes())
        copied.chmod(0o600)
        self.assertFalse(self.check(anchor_path=copied)['ok'])

    def test_tampered_anchor_blocks(self):
        self.anchor.write_text('{}')
        self.assertFalse(self.check()['ok'])

if __name__=='__main__':
    unittest.main()
