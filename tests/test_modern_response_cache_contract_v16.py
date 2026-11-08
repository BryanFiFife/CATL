"""CATL MCP 2026-07-28 successful response contract regressions.

The schema requires ttlMs, cacheScope and resultType for *every* result,
not just server/discover and tools/list. No protected tool result is cacheable.
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from catl.protocol import MODERN, SERVER_INFO_KEY, discovery, modernize

class ModernResultContract(unittest.TestCase):
    def assert_no_cache(self, response):
        result = response['result']
        self.assertEqual(result['resultType'], 'complete')
        self.assertEqual(result['ttlMs'], 0)
        self.assertEqual(result['cacheScope'], 'private')
        self.assertEqual(result['_meta'][SERVER_INFO_KEY]['name'], 'caledapt-agent-trust')

    def test_tools_call_has_required_cache_metadata(self):
        response = {'jsonrpc': '2.0', 'id': 4, 'result': {'content': [{'type': 'text', 'text': 'ok'}]}}
        self.assert_no_cache(modernize(response))

    def test_tools_call_structured_result_has_required_metadata(self):
        response = {'jsonrpc': '2.0', 'id': 5, 'result': {'content': [], 'structuredContent': {'ok': True}}}
        self.assert_no_cache(modernize(response))

    def test_untrusted_cache_hints_are_overridden(self):
        response = {'jsonrpc': '2.0', 'id': 6,
                    'result': {'content': [], 'ttlMs': 86_400_000, 'cacheScope': 'public'}}
        self.assert_no_cache(modernize(response))

    def test_tools_list_contract_preserved(self):
        response = {'jsonrpc': '2.0', 'id': 7, 'result': {'tools': [{'name': 'safe'}]}}
        self.assert_no_cache(modernize(response))

    def test_discovery_contract_preserved(self):
        resp = discovery(8)
        self.assert_no_cache(resp)
        self.assertEqual(resp['result']['supportedVersions'], [MODERN])

    def test_rpc_error_remains_error(self):
        error = {'jsonrpc': '2.0', 'id': 9, 'error': {'code': -32602, 'message': 'bad'}}
        self.assertEqual(modernize(error), error)

    def test_noncomplete_result_refused(self):
        result = modernize({'jsonrpc': '2.0', 'id': 10, 'result': {'resultType':'input_required'}})
        self.assertEqual(result['error']['message'], 'unsupported_backend_result_type')

    def test_meta_server_identity_overrides_backend(self):
        response = {'jsonrpc': '2.0', 'id': 11,
                    'result': {'content': [], '_meta': {SERVER_INFO_KEY: {'name': 'forged', 'version': '99'}}}}
        self.assert_no_cache(modernize(response))

if __name__ == '__main__':
    unittest.main()
