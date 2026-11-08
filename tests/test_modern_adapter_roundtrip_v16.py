"""Modern-upstream-to-legacy-bridge-to-modern-client tested adapter round trip.

No broker/OS confinement is claimed; actual CATL protocol adapters run here.
"""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from catl.mcp_modern_upstream import ModernToolsBackend, ModernMCPRejected, MODERN
from catl.protocol import modernize

class RecordingUpstream:
    def __init__(self, result_type='complete'):
        self.calls=[]
        self.result_type=result_type
    def request(self, method, params):
        self.calls.append((method, params))
        if method == 'server/discover':
            return {'result': {'supportedVersions': [MODERN], 'capabilities': {'tools': {}}}}
        if method == 'tools/list':
            return {'result': {'resultType':'complete', 'tools': [{'name':'echo_safe'}], 'ttlMs':9000, 'cacheScope':'public'}}
        if method == 'tools/call':
            return {'result': {'resultType':self.result_type,
                               'content':[{'type':'text','text':params['arguments']['message']}],
                               'ttlMs':9000, 'cacheScope':'public'}}
        raise AssertionError('unexpected request')
    def notify(self, method, params=None):
        self.calls.append((method, params))
    def close(self): pass

class TestModernToLegacyToModern(unittest.TestCase):
    def test_roundtrip_discovery_listing_and_call(self):
        wire=RecordingUpstream()
        backend=ModernToolsBackend(wire)
        self.assertEqual(backend.request('initialize')['result']['protocolVersion'], '2025-11-25')
        backend.notify('notifications/initialized')
        listed=backend.request('tools/list',{})
        modern_list=modernize({'jsonrpc':'2.0','id':11,'result':listed['result']})
        self.assertEqual(modern_list['result']['ttlMs'],0)
        self.assertEqual(modern_list['result']['cacheScope'],'private')
        tool=backend.request('tools/call',{'name':'echo_safe','arguments':{'message':'hello'}})
        modern_tool=modernize({'jsonrpc':'2.0','id':12,'result':tool['result']})
        self.assertEqual(modern_tool['result']['content'][0]['text'],'hello')
        self.assertEqual(modern_tool['result']['resultType'],'complete')
        self.assertEqual(modern_tool['result']['ttlMs'],0)
        self.assertEqual(modern_tool['result']['cacheScope'],'private')
        self.assertEqual([x[0] for x in wire.calls],['server/discover','tools/list','tools/call'])
        self.assertTrue(all(x[1]['_meta']['io.modelcontextprotocol/protocolVersion']==MODERN for x in wire.calls))

    def test_mrtr_result_refused(self):
        wire=RecordingUpstream(result_type='input_required')
        backend=ModernToolsBackend(wire)
        backend.request('initialize')
        with self.assertRaisesRegex(ModernMCPRejected,'multi_round_trip'):
            backend.request('tools/call',{'name':'echo_safe','arguments':{'message':'hi'}})

    def test_pre_discovery_is_fail_closed(self):
        wire=RecordingUpstream()
        backend=ModernToolsBackend(wire)
        with self.assertRaisesRegex(ModernMCPRejected,'discovery_required'):
            backend.request('tools/call',{'name':'echo_safe','arguments':{'message':'hi'}})
        self.assertEqual(wire.calls,[])

if __name__=='__main__':unittest.main()
