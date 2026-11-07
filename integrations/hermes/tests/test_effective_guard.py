"""Dynamic Hermes registry regression; never needs an installed Hermes Agent."""
from __future__ import annotations
import copy,hashlib,os,pathlib,sys,tempfile,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from hermes_effective_guard import inspect_snapshot,_read_snapshot,MARKER,EXPECTED_NAMES,_safe_file,verify_hermes,_run_bounded

class EffectiveGuardTests(unittest.TestCase):
    def setUp(self):
        self.home=pathlib.Path('/home/catl-agent/.hermes/profiles/catl-eval')
        self.digest='a'*64
        self.valid={'version':1,'config_sha256_before':self.digest,'config_sha256_after':self.digest,
                    'home':str(self.home),'uid':1001,'resolved_toolsets':['catl'],
                    'tool_names':sorted(EXPECTED_NAMES)}
    def check(self,payload=None,expect='armed'):
        return inspect_snapshot(self.valid if payload is None else payload,
              config_sha256=self.digest,home=self.home,expect=expect,expected_uid=1001)
    def test_reviewed_inventory_passes(self):self.assertTrue(self.check()['passed'])
    def test_paused_with_empty_tools_only(self):
        p=copy.deepcopy(self.valid);p['tool_names']=[]
        self.assertTrue(self.check(p,expect='paused')['passed']);self.assertFalse(self.check(p)['passed'])
    def test_extras_and_missing_fail_closed(self):
        for extra in ('terminal','web','file','browser','context_engine','skills','mcp-other','a2a','plugin-evil'):
            with self.subTest(extra=extra):
                p=copy.deepcopy(self.valid);p['resolved_toolsets'].append(extra)
                self.assertFalse(self.check(p)['passed'])
        for name in ('terminal_execute','file_write','mcp_other_send','tool_search',
                     'mcp_catl_approve','mcp_catl_decide','mcp_catl_operator'):
            with self.subTest(name=name):
                p=copy.deepcopy(self.valid);p['tool_names'].append(name)
                self.assertFalse(self.check(p)['passed'])
        p=copy.deepcopy(self.valid);p['resolved_toolsets']=[]
        self.assertFalse(self.check(p)['passed'])
    def test_forgeries_and_corruption(self):
        mutations=[{'uid':0},{'home':'/tmp/evil'},{'version':2},
                   {'config_sha256_before':'b'*64},{'config_sha256_after':'b'*64},
                   {'resolved_toolsets':['catl','catl']},
                   {'tool_names':sorted(EXPECTED_NAMES)+['mcp_catl_echo_safe']},
                   {'tool_names':None},{'tool_names':'mcp_catl_echo_safe'},
                   {'resolved_toolsets':None},{'error':'import_failed'}]
        for changes in mutations:
            with self.subTest(changes=changes):
                p={**self.valid,**changes}
                self.assertFalse(self.check(p)['passed'])
    def test_structural_bad_snapshot(self):
        for x in (None,[],0,'abc',{'version':2}):
            self.assertFalse(inspect_snapshot(x,config_sha256=self.digest,home=self.home,expected_uid=1001)['passed'])
    def test_invalid_modes(self):self.assertFalse(self.check(expect='unrestricted')['passed'])
    def test_json_parser_rejects_duplicated_or_ambiguous_evidence(self):
        import json
        payload=(MARKER+json.dumps(self.valid)).encode()
        self.assertEqual(_read_snapshot(payload)['uid'],1001)
        for bad in (b'',payload+b'\n'+payload,
                    (MARKER+'{"version":1,"version":1}').encode(),
                    (MARKER+'[]').encode(),
                    b'\xff'+payload,
                    b'no evidence',
                    (MARKER+'{}'*70000).encode()):
            with self.subTest(bad=bad[:50]):
                with self.assertRaises(ValueError): _read_snapshot(bad)
    def test_bounded_subprocess_nonzero(self):
        rc,out=_run_bounded([sys.executable,'-c','print("test")'],env=dict(os.environ),timeout=3)
        self.assertEqual(rc,0);self.assertIn(b'test',out)
        rc,_=_run_bounded([sys.executable,'-c','import sys;sys.exit(22)'],env=dict(os.environ),timeout=3)
        self.assertEqual(rc,22)
    def test_bounded_subprocess_flood(self):
        with self.assertRaises(ValueError):
            _run_bounded([sys.executable,'-c',"import sys;sys.stdout.buffer.write(b'a'*200000)"],env=dict(os.environ),timeout=3)
    def test_bounded_subprocess_timeout(self):
        with self.assertRaises(TimeoutError):
            _run_bounded([sys.executable,'-c','import time;time.sleep(15)'],env=dict(os.environ),timeout=1)
    @unittest.skipUnless(sys.platform=='linux','Linux-only filesystem')
    def test_file_trust_rejects_world_writable_or_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);f=root/'trusted';f.write_text('#!/bin/sh\n');f.chmod(0o700)
            # /tmp is world writable; caller must use non-writable parent.
            self.assertTrue(_safe_file(f))
            symlink=root/'linked';symlink.symlink_to(f)
            self.assertTrue(any('symlink' in x for x in _safe_file(symlink)))
    def test_unsafe_runtime_cannot_be_claimed_as_safe(self):
        # Real runtime probe refuses root and missing binaries before executing children.
        if sys.platform=='linux' and os.geteuid()==0:
            r=verify_hermes(python=pathlib.Path('/missing/python'),home=self.home,
                            expected_uid=1001)
            self.assertFalse(r['passed']);self.assertIn('must_not_run_as_root',r['errors'])
    def test_probe_compilation_uses_raw_tool_schema_enumeration(self):
        from hermes_effective_guard import SNAPSHOT_CODE
        self.assertIn('skip_tool_search_assembly=True', SNAPSHOT_CODE)
        self.assertIn('_get_platform_tools(config, "cli")',SNAPSHOT_CODE)

if __name__=='__main__':unittest.main()
