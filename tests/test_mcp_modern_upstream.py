import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from catl.mcp_modern_upstream import ModernToolsBackend,ModernMCPRejected,VERSION_KEY,MODERN
class Fake:
 def __init__(self):self.calls=[];self.responses=[];self.notifications=[];self.closed=False
 def request(self,m,p=None):
  self.calls.append((m,p))
  if self.responses:return self.responses.pop(0)
  if m=='server/discover':return {'result':{'supportedVersions':[MODERN],'capabilities':{'tools':{}}}}
  if m=='tools/list':return {'result':{'tools':[]}}
  return {'result':{'content':[]}}
 def notify(self,m,p=None):self.notifications.append((m,p))
 def close(self):self.closed=True
class TestModern(unittest.TestCase):
 def setUp(self):self.up=Fake();self.adapter=ModernToolsBackend(self.up)
 def initialise(self):return self.adapter.request('initialize',{})
 def test_discovery_modern(self):
  self.assertEqual(self.initialise()['result']['protocolVersion'],'2025-11-25')
  self.assertEqual(self.up.calls[0][0],'server/discover')
 def test_no_upstream_legacy_initialize(self):
  self.initialise();self.adapter.notify('notifications/initialized')
  self.assertEqual(self.up.notifications,[])
 def test_tool_metadata_on_each(self):
  self.initialise();self.adapter.request('tools/list');self.adapter.request('tools/call',{'name':'x','arguments':{}})
  self.assertTrue(all(p['_meta'][VERSION_KEY]==MODERN for _,p in self.up.calls))
 def test_no_pre_discovery(self):
  with self.assertRaises(ModernMCPRejected):self.adapter.request('tools/list')
 def test_unknown_method_denied(self):
  self.initialise()
  with self.assertRaises(ModernMCPRejected):self.adapter.request('resources/read')
 def test_untrusted_meta_denied(self):
  self.initialise()
  with self.assertRaises(ModernMCPRejected):self.adapter.request('tools/call',{'_meta':{'elevate':True}})
 def test_missing_capabilities_denied(self):
  self.up.responses.append({'result':{'supportedVersions':[MODERN],'capabilities':{}}})
  with self.assertRaises(ModernMCPRejected):self.initialise()
 def test_wrong_version_denied(self):
  self.up.responses.append({'result':{'supportedVersions':['2025-11-25'],'capabilities':{'tools':{}}}})
  with self.assertRaises(ModernMCPRejected):self.initialise()
 def test_mrtr_denied(self):
  self.initialise();self.up.responses.append({'result':{'resultType':'input_required','inputRequests':{}}})
  with self.assertRaises(ModernMCPRejected):self.adapter.request('tools/call',{'name':'x'})
 def test_ambiguous_denied(self):
  self.initialise();self.up.responses.append({'result':{},'error':{'code':1}})
  with self.assertRaises(ModernMCPRejected):self.adapter.request('tools/list')
 def test_error_sanitized(self):
  self.initialise();self.up.responses.append({'error':{'code':-3000,'message':'sensitive token'}})
  self.assertEqual(self.adapter.request('tools/list')['error']['message'],'upstream_error')
 def test_unsupported_notification(self):
  with self.assertRaises(ModernMCPRejected):self.adapter.notify('danger')
if __name__=='__main__':unittest.main()
