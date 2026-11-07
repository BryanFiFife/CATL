import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from catl.crypto import canonical, digest, get_or_create_key, parse_json
from catl.policy import Policy

TOOL = {"name": "payment.send", "description": "A sensitive tool", "inputSchema": {"type": "object"}}
BASE = {"agent_id": "trusted-user-1", "tool_pins": {"payment.send": digest(TOOL)},
        "rules": [{"tool": "payment.send", "effect": "approve", "conditions": [{"pointer": "/amount", "op": "lte", "value": 20}]},
                  {"tool": "payment.send", "effect": "deny", "conditions": [{"pointer": "/recipient", "op": "eq", "value": "blocked"}]}]}


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = Policy.from_dict(copy.deepcopy(BASE))

    def test_allow_not_implicit(self):
        self.assertEqual(self.policy.evaluate("payment.send", {"amount": 100}), "deny")

    def test_approval_small_amount(self):
        self.assertEqual(self.policy.evaluate("payment.send", {"amount": 15}), "approve")

    def test_deny_dominates_approval(self):
        self.assertEqual(self.policy.evaluate("payment.send", {"amount": 10, "recipient": "blocked"}), "deny")

    def test_negative_amount_not_implied_safe(self):
        self.assertEqual(self.policy.evaluate("payment.send", {"amount": -100}), "approve")
        # This shows that security policies MUST constrain lower bounds in the backend.

    def test_bad_boolean_not_number(self):
        self.assertEqual(self.policy.evaluate("payment.send", {"amount": True}), "deny")

    def test_missing_arg_denied(self):
        self.assertEqual(self.policy.evaluate("payment.send", {}), "deny")

    def test_unpinned_tool_denied(self):
        self.assertEqual(self.policy.evaluate("unexpected", {"amount": 1}), "deny")

    def test_pin_exact(self):
        self.assertTrue(self.policy.pinned(TOOL))
        mutated = {**TOOL, "description": "now unsafe"}
        self.assertFalse(self.policy.pinned(mutated))

    def test_pin_order_independent(self):
        reverse = dict(reversed(list(TOOL.items())))
        self.assertEqual(digest(TOOL), digest(reverse))

    def test_unknown_config_rejected(self):
        data = copy.deepcopy(BASE); data["unexpected"] = "magic"
        with self.assertRaises(ValueError): Policy.from_dict(data)

    def test_wildcard_rules_rejected(self):
        data = copy.deepcopy(BASE); data["rules"][0]["tool"] = "*"
        with self.assertRaises(ValueError): Policy.from_dict(data)

    def test_empty_conditions_can_allow_specific_tool(self):
        data = copy.deepcopy(BASE); data["rules"] = [{"tool": "payment.send", "effect": "allow", "conditions": []}]
        self.assertEqual(Policy.from_dict(data).evaluate("payment.send", {}), "allow")

    def test_json_pointer_escape(self):
        data = copy.deepcopy(BASE); data["rules"] = [{"tool": "payment.send", "effect": "allow", "conditions": [{"pointer": "/a~1b/~0x", "op": "eq", "value": "yes"}]}]
        self.assertEqual(Policy.from_dict(data).evaluate("payment.send", {"a/b": {"~x": "yes"}}), "allow")

    def test_one_of_type_strict(self):
        data = copy.deepcopy(BASE); data["rules"] = [{"tool": "payment.send", "effect": "allow", "conditions": [{"pointer": "/x", "op": "one_of", "value": [1, "1"]}]}]
        p = Policy.from_dict(data)
        self.assertEqual(p.evaluate("payment.send", {"x": True}), "deny")
        self.assertEqual(p.evaluate("payment.send", {"x": "1"}), "allow")

    def test_rule_field_unknown_rejected(self):
        data = copy.deepcopy(BASE); data["rules"][0]["priority"] = 999
        with self.assertRaises(ValueError): Policy.from_dict(data)

    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(ValueError): parse_json(b'{"jsonrpc":"2.0","jsonrpc":"1.0"}')

    def test_gte_prevents_negative_numbers(self):
        data = copy.deepcopy(BASE); data["rules"] = [{"tool": "payment.send", "effect": "allow", "conditions": [{"pointer": "/amount", "op": "lte", "value": 20}, {"pointer": "/amount", "op": "gte", "value": 0}]}]
        p = Policy.from_dict(data)
        self.assertEqual(p.evaluate("payment.send", {"amount": -1}), "deny")
        self.assertEqual(p.evaluate("payment.send", {"amount": 19}), "allow")

    def test_non_finite_json_rejected_on_wire(self):
        with self.assertRaises(ValueError): parse_json(b'{"n":NaN}')

    def test_message_size_cap(self):
        with self.assertRaises(ValueError): parse_json(b'x' * (1024 * 1024 + 1))

    def test_bad_wire_type(self):
        with self.assertRaises(ValueError): parse_json(b'[1,2,3]')

    def test_invalid_utf8(self):
        with self.assertRaises(UnicodeDecodeError): parse_json(b'\xff')

    def test_key_creation_and_reuse(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state" / "secret"
            k1 = get_or_create_key(p)
            self.assertEqual(len(k1), 32)
            self.assertEqual(k1, get_or_create_key(p))
            if os.name == "posix":
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX file permission model")
    def test_weak_key_permissions_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "key"; p.write_bytes(b'x' * 32); p.chmod(0o644)
            with self.assertRaises(PermissionError): get_or_create_key(p)

    @unittest.skipUnless(os.name == "posix", "POSIX symbolic links")
    def test_key_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "key"; p.write_bytes(b'x' * 32); p.chmod(0o600)
            link = Path(d) / "link"; link.symlink_to(p)
            with self.assertRaises(PermissionError): get_or_create_key(link)
