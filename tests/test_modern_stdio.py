"""Real subprocess / real JSON-RPC traffic against modern 2026-07-28 subset."""
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class TestModernStdio(unittest.TestCase):
    def test_discover_list_tool_call_and_refusal(self):
        with tempfile.TemporaryDirectory() as td:
            home=Path(td)/'private'
            command=[sys.executable,'-m','catl','run','--config',str(ROOT/'examples/policy.json'),
                     '--state-dir',str(home),'--allow-unsandboxed','--',sys.executable,str(ROOT/'examples/mock_server.py')]
            meta={'io.modelcontextprotocol/protocolVersion':'2026-07-28',
                  'io.modelcontextprotocol/clientCapabilities':{},
                  'io.modelcontextprotocol/clientInfo':{'name':'integration-test','version':'1.0'}}
            def packet(method, data=None, n=1):
                return {'jsonrpc':'2.0','method':method,'id':n,'params':{**(data or {}),'_meta':meta}}
            msgs=[packet('server/discover',n=1),packet('tools/list',n=2),
                  packet('tools/call',{'name':'echo_safe','arguments':{'message':'hello real stdio'}},3),
                  packet('tools/call',{'name':'echo_safe','arguments':{'message':'not permitted'}},4)]
            env={**os.environ,'PYTHONPATH':str(ROOT/'src')}
            from catl.crypto import get_or_create_key
            from catl.store import State
            boot = State(home/'audit.sqlite3', get_or_create_key(home/'audit.key'))
            self.assertFalse(boot.controls()['gateway_enabled'])
            boot.set_feature('gateway_enabled', True, 'test-bootstrap')
            run=subprocess.run(command,input=('\n'.join(json.dumps(m) for m in msgs)+'\n').encode(),
                               capture_output=True,timeout=20,env=env)
            self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace'))
            responses=[json.loads(x) for x in run.stdout.splitlines()]
            self.assertEqual([r['id'] for r in responses],[1,2,3,4])
            for r in responses[:3]:
                self.assertEqual(r['result']['resultType'],'complete')
                self.assertIn('io.modelcontextprotocol/serverInfo',r['result']['_meta'])
            self.assertEqual(responses[2]['result']['content'][0]['text'],'hello real stdio')
            self.assertEqual(responses[3]['error']['message'],'policy_denied')

    def test_cli_rejects_unsandboxed_default(self):
        with tempfile.TemporaryDirectory() as td:
            env={**os.environ,'PYTHONPATH':str(ROOT/'src')}
            run=subprocess.run([sys.executable,'-m','catl','run','--config',str(ROOT/'examples/policy.json'),
                        '--state-dir',str(Path(td)/'private'),'--',sys.executable,str(ROOT/'examples/mock_server.py')],
                        input=b'',capture_output=True,timeout=10,env=env)
            self.assertNotEqual(run.returncode,0)
            self.assertIn(b'isolation_required',run.stderr)

class TestRealPostcondition(unittest.TestCase):
    def test_real_child_file_digest_and_approval(self):
        from hashlib import sha256
        sys.path.insert(0, str(ROOT/'src'))
        from catl.store import State
        from catl.crypto import digest
        sys.path.insert(0,str(ROOT/'examples'))
        from mock_server import TOOLS
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            policy={'agent_id':'e2e-protected','tool_pins': {t['name']:digest(t) for t in TOOLS},
                    'rules':[{'tool':'write_demo','effect':'approve','conditions':[]}],
                    'postconditions':{'write_demo':{'kind':'file_sha256','root':str(root),
                                'path_pointer':'/filename','digest_pointer':'/sha256'}}}
            path=root/'policy.json';path.write_text(json.dumps(policy))
            out=root/'side-effect.txt'
            state_dir=root/'state'
            key=b'M'*32
            env={**os.environ,'PYTHONPATH':str(ROOT/'src'),'CATL_DEMO_OUTPUT':str(out)}
            command=[sys.executable,'-m','catl','run','--config',str(path),'--state-dir',str(state_dir),
                     '--allow-unsandboxed','--pass-env','CATL_DEMO_OUTPUT','--',sys.executable,str(ROOT/'examples/mock_server.py')]
            args={'name':'write_demo','arguments':{'message':'verified','filename':out.name,'sha256':sha256(b'verified\n').hexdigest()}}
            msg={'jsonrpc':'2.0','id':1,'method':'tools/call','params':args}
            def invoke():
                r=subprocess.run(command,input=(json.dumps(msg)+'\n').encode(),capture_output=True,env=env,timeout=15)
                self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'))
                return json.loads(r.stdout)
            from catl.crypto import get_or_create_key
            boot = State(state_dir/'audit.sqlite3', get_or_create_key(state_dir/'audit.key'))
            self.assertFalse(boot.controls()['gateway_enabled'])
            boot.set_feature('gateway_enabled', True, 'test-bootstrap')
            first=invoke()
            self.assertEqual(first['error']['message'],'human_approval_required')
            state=State(state_dir/'audit.sqlite3',(state_dir/'audit.key').read_bytes())
            self.assertTrue(state.decide(first['error']['data']['approval_id'],'real-human', True))
            second=invoke()
            self.assertIn('result',second)
            self.assertEqual(out.read_bytes(),b'verified\n')
            self.assertTrue(state.verify()['valid'])
            self.assertGreaterEqual(state.verify()['count'],4)
            self.assertEqual(invoke()['error']['message'],'human_approval_required')
