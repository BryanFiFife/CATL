"""Real JSON-RPC child process through modern MCP adapter and CATL gateway.

This tests the stdio integration boundary, not Windows/macOS kernel isolation.
"""
from __future__ import annotations
import json
import sys
import tempfile
import unittest
from pathlib import Path

from catl.gateway import Gateway, SubprocessBackend
from catl.mcp_modern_upstream import ModernToolsBackend
from catl.policy import Policy
from catl.store import State

ROOT=Path(__file__).resolve().parents[1]
MODERN='2026-07-28'
TOOL={
    'name':'echo_safe',
    'description':'Returns an echoed string, no external effect.',
    'inputSchema':{'type':'object','properties':{'message':{'type':'string'}},'required':['message']}
}

SCRIPT='''import json,sys
TOOL={tool}
M='2026-07-28'
for line in sys.stdin:
 try:
  request=json.loads(line)
  params=request.get('params',{{}})
  meta=params.get('_meta',{{}})
  if meta.get('io.modelcontextprotocol/protocolVersion')!=M:
   response={{'error':{{'code':-32602,'message':'missing modern metadata'}}}}
  elif request['method']=='server/discover':
   response={{'result':{{'supportedVersions':[M],'capabilities':{{'tools':{{}}}}}}}}
  elif request['method']=='tools/list':
   response={{'result':{{'tools':[TOOL], 'resultType':'complete'}}}}
  elif request['method']=='tools/call':
   a=params.get('arguments',{{}})
   response={{'result':{{'content':[{{'type':'text','text':a.get('message','')}}], 'resultType':'complete'}}}}
  else:
   response={{'error':{{'code':-32601,'message':'unsupported'}}}}
  response.update({{'jsonrpc':'2.0','id':request['id']}})
  print(json.dumps(response,separators=(',',':')),flush=True)
 except (ValueError,KeyError,TypeError):
  print('{{"jsonrpc":"2.0","id":null,"error":{{"code":-32700,"message":"malformed"}}}}',flush=True)
'''.format(tool=repr(TOOL))

class ModernBackendSubprocessE2E(unittest.TestCase):
    def setUp(self):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root=Path(td.name)
        import fixture_modes as fm
        fm.umask_022(self)
        fm.trust_repo_fixture(ROOT / 'examples' / 'policy.json')
        import fixture_modes as fm
        fm.umask_022(self)
        fm.trust_repo_fixture(ROOT / 'examples' / 'policy.json')
        self.policy=Policy.from_file(ROOT/'examples'/'policy.json')
        self.state=State(self.root/'audit.sqlite3',b'R'*32)
        self.state.set_feature('gateway_enabled',True,'test-modern-process')

    def _gateway(self, path):
        backend=SubprocessBackend([sys.executable,'-u',str(path)],timeout=6,allow_unsandboxed=True)
        self.addCleanup(backend.close)
        return Gateway(self.policy,self.state,ModernToolsBackend(backend))

    def test_successful_discovery_catalogue_and_tool_dispatch(self):
        path=self.root/'modern_server.py';path.write_text(SCRIPT)
        gateway=self._gateway(path)
        reply=gateway.handle({'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})
        self.assertEqual([x['name'] for x in reply['result']['tools']],['echo_safe'])
        call=gateway.handle({'jsonrpc':'2.0','id':2,'method':'tools/call',
                             'params':{'name':'echo_safe','arguments':{'message':'hello modern backend'}}})
        self.assertEqual(call['result']['content'][0]['text'],'hello modern backend')
        denied=gateway.handle({'jsonrpc':'2.0','id':3,'method':'tools/call',
                               'params':{'name':'echo_safe','arguments':{'message':'policy denied'}}})
        self.assertEqual(denied['error']['message'],'policy_denied')
        self.assertTrue(self.state.verify()['valid'])

    def test_legacy_backend_does_not_silently_downgrade(self):
        gateway=self._gateway(ROOT/'examples'/'mock_server.py')
        reply=gateway.handle({'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})
        self.assertIn('catalogue_unavailable',reply['error']['message'])
        self.assertFalse(gateway.backend_ready)
        self.assertFalse(gateway.available)

if __name__=='__main__':unittest.main()
