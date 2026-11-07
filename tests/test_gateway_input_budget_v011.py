"""Oversized untrusted MCP tool names must never reach signed ledger work."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from catl.gateway import Gateway


class NameBounds(unittest.TestCase):
    def test_very_long_name_returns_immediate_error_without_state_or_backend(self):
        gw = object.__new__(Gateway)
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': {'name': 'X' * 700000, 'arguments': {}}}
        result = gw.handle(request)
        self.assertEqual(result['error']['code'], -32602)
        self.assertEqual(result['error']['message'], 'invalid_tool_call')

    def test_policy_max_name_length_is_enforced(self):
        gw = object.__new__(Gateway)
        request = {'jsonrpc': '2.0', 'id': 'c', 'method': 'tools/call',
                   'params': {'name': 'X' * 129, 'arguments': {}}}
        result = gw.handle(request)
        self.assertEqual(result['error']['message'], 'invalid_tool_call')

    def test_non_string_name_is_denied(self):
        gw = object.__new__(Gateway)
        for name in (None, 1000, True, [], {}):
            with self.subTest(name=name):
                request = {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                           'params': {'name': name, 'arguments': {}}}
                self.assertEqual(gw.handle(request)['error']['message'], 'invalid_tool_call')


if __name__ == '__main__':
    unittest.main()
