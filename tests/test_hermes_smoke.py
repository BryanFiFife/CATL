"""Hermes stdio smoke checker must reject silent/failed and bypassed responses."""
from __future__ import annotations

import unittest
from tools.hermes_mcp_smoke import validate_replies


def sample(call):
    return [
        {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-11-25"}},
        {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "echo_safe"},
                                                    {"name": "write_demo"}]}},
        {"jsonrpc": "2.0", "id": 3, **call},
    ]


class HermesSmokeValidationTests(unittest.TestCase):
    def test_disarmed_denial_is_required(self):
        halted = sample({"error": {"message": "operator_disabled_gateway_or_audit"}})
        halted[1]["result"]["tools"] = []
        self.assertTrue(validate_replies(
            halted, tool="echo_safe", expect="disarmed")["passed"])
        with self.assertRaises(AssertionError):
            validate_replies(sample({"error": {"message": "operator_disabled_gateway_or_audit"}}),
                             tool="echo_safe", expect="disarmed")
        unexpected = sample({"result": {"content": [{"type": "text", "text": "oops"}]}})
        unexpected[1]["result"]["tools"] = []
        with self.assertRaises(AssertionError):
            validate_replies(unexpected, tool="echo_safe", expect="disarmed")

    def test_armed_and_approval_paths(self):
        self.assertTrue(validate_replies(sample(
            {"result": {"content": [{"type": "text", "text": "hello"}]}}),
            tool="echo_safe", expect="armed")["passed"])
        self.assertTrue(validate_replies(sample(
            {"error": {"message": "human_approval_required"}}),
            tool="write_demo", expect="approval-required")["passed"])

    def test_error_text_must_not_pass_as_success(self):
        with self.assertRaises(AssertionError):
            validate_replies(sample(
                {"result": {"isError": True,
                            "content": [{"type": "text", "text": "failed"}]}}),
                tool="echo_safe", expect="armed")
        with self.assertRaises(AssertionError):
            validate_replies(sample(
                {"result": {"content": [{"type": "text", "text": "wrong echo"}]}}),
                tool="echo_safe", expect="armed", expected_text="hello")

    def test_missing_tool_and_handshake_rejected(self):
        with self.assertRaises(AssertionError):
            validate_replies(sample({"result": {}}), tool="unreviewed", expect="armed")
        data = sample({"result": {}})
        data[0]["result"]["protocolVersion"] = "2024-11-05"
        with self.assertRaises(AssertionError):
            validate_replies(data, tool="echo_safe", expect="armed")

    def test_malformed_envelope_and_missing_response_rejected(self):
        with self.assertRaises(AssertionError):
            validate_replies(sample({"result": {}})[:2], tool="echo_safe", expect="armed")
        data = sample({"result": {}})
        data[2]["id"] = 2
        with self.assertRaises(AssertionError):
            validate_replies(data, tool="echo_safe", expect="armed")


if __name__ == "__main__":
    unittest.main()
