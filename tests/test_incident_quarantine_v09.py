"""Adversarial checks for crash-persistent, ledger-backed action quarantine."""
from __future__ import annotations
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from catl.crypto import digest
from catl.gateway import Gateway
from catl.policy import Policy
from catl.store import State

TOOL = {"name": "send_once", "inputSchema": {"type": "object", "properties": {
    "recipient": {"type": "string"}}, "required": ["recipient"]}}

class Backend:
    def __init__(self):
        self.calls = 0
        self.mode = "success"
    def request(self, method, params=None):
        if method == "initialize":
            return {"result": {"protocolVersion": "2025-11-25"}}
        if method == "tools/list":
            return {"result": {"tools": [TOOL]}}
        if method == "tools/call":
            self.calls += 1
            if self.mode == "transport":
                raise TimeoutError("did_it_send")
            if self.mode == "bad_reply":
                return {"result": {"resultType": "input_required", "content": []}}
            if self.mode == "rpc_error":
                return {"error": {"code": -32000, "message": "upstream_uncertain"}}
            if self.mode == "tool_error":
                return {"result": {"isError": True, "content": [{"type": "text", "text": "unknown"}]}}
            return {"result": {"content": [{"type": "text", "text": "reported_sent"}]}}
        raise AssertionError(method)
    def notify(self, method, params=None):
        pass
    def close(self):
        pass

class TestIncidentQuarantine(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/"state.db"
        self.state = State(self.path, b"I"*32)
        self.state.set_feature("gateway_enabled", True, "operator")
        self.policy = Policy.from_dict({"agent_id": "agent-A", "tool_pins": {"send_once": digest(TOOL)},
            "rules": [{"tool": "send_once", "effect": "allow", "conditions": []}]})
        self.backend = Backend()
        self.gateway = Gateway(self.policy, self.state, self.backend)

    def call(self):
        return self.gateway.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "send_once", "arguments": {"recipient": "test@example.invalid"}}})

    def test_reported_success_not_quarantined(self):
        self.assertIn("result", self.call())
        self.assertEqual(self.state.open_incidents(), [])
        self.assertIn("result", self.call())
        self.assertEqual(self.backend.calls, 2)

    def test_transport_timeout_blocks_replay_even_after_restart(self):
        self.backend.mode = "transport"
        first = self.call()
        self.assertEqual(first["error"]["message"], "tool_transport_failure")
        self.backend.mode = "success"
        self.gateway = Gateway(self.policy, State(self.path, b"I"*32), self.backend)
        second = self.call()
        self.assertEqual(second["error"]["message"], "tool_quarantined_pending_reconciliation")
        self.assertEqual(self.backend.calls, 1)
        self.assertEqual(len(self.state.open_incidents()), 1)
        self.assertNotIn("send_once", [x['name'] for x in self.gateway.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/list"})['result']['tools']])

    def test_bad_reply_rpc_and_business_errors_quarantine(self):
        for mode in ("bad_reply", "rpc_error", "tool_error"):
            with self.subTest(mode=mode):
                self.backend.mode = mode
                first = self.call()
                self.assertTrue("result" in first or "error" in first)
                incident = self.state.open_incidents()[-1]
                self.assertEqual(incident['tool'], 'send_once')
                self.backend.mode = 'success'
                self.assertEqual(self.call()['error']['message'], 'tool_quarantined_pending_reconciliation')
                self.state.reconcile_incident(incident['action_id'], 'operator',
                    'ticket:confirmed-outcome-by-operator', 'I_HAVE_RECONCILED_THE_EXTERNAL_EFFECT')

    def test_operator_toggle_cannot_bypass_quarantine(self):
        self.backend.mode = 'transport'
        self.call()
        self.state.set_tool('send_once', False, 'operator', {'send_once'})
        self.state.set_tool('send_once', True, 'operator', {'send_once'})
        self.backend.mode = 'success'
        self.assertEqual(self.call()['error']['message'], 'tool_quarantined_pending_reconciliation')

    def test_crash_after_intent_recovers_as_unknown_and_blocks_call(self):
        action_id = 'a'*32
        self.state.append({"decision": "allow", "outcome": "dispatch_intent", "action_id": action_id,
                           "tool": "send_once", "binding": "B", "at": 1})
        self.assertEqual(self.state.open_incidents()[0]['status'], 'dispatch_outcome_unknown')
        self.assertEqual(self.call()['error']['message'], 'tool_quarantined_pending_reconciliation')
        self.assertEqual(self.backend.calls, 0)

    def test_reconciliation_requires_evidence_and_only_operator_api(self):
        self.backend.mode = 'bad_reply'
        self.call()
        incident = self.state.open_incidents()[0]
        aid = incident['action_id']
        for ref, ack in (("short", 'I_HAVE_RECONCILED_THE_EXTERNAL_EFFECT'),
                         ('ticket:123456789', 'wrong_ack'), ('', 'wrong_ack')):
            with self.subTest(reference=ref,ack=ack), self.assertRaises(ValueError):
                self.state.reconcile_incident(aid, 'operator', ref, ack)
        self.assertTrue(self.state.reconcile_incident(aid, 'operator', 'ticket:read-back-from-provider',
            'I_HAVE_RECONCILED_THE_EXTERNAL_EFFECT'))
        self.assertEqual(self.state.open_incidents(), [])
        self.assertFalse(self.state.reconcile_incident(aid, 'operator', 'ticket:read-back-from-provider',
            'I_HAVE_RECONCILED_THE_EXTERNAL_EFFECT'))
        self.backend.mode = 'success'
        self.assertIn('result', self.call())
        self.assertEqual(self.backend.calls, 2)

    def test_tamper_or_rollback_fails_closed(self):
        self.backend.mode = 'bad_reply'
        self.call()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE receipts SET body='{}' WHERE seq=(SELECT MAX(seq) FROM receipts)")
        with self.assertRaises(PermissionError):
            self.state.open_incidents()
        response = self.call()
        self.assertEqual(response['error']['message'], 'preflight_failed')
        self.assertEqual(self.backend.calls, 1)

    def test_duplicate_or_orphan_terminal_fails_closed(self):
        aid = 'b'*32
        self.state.append({'tool':'send_once','action_id':aid,'outcome':'backend_reported_result'})
        with self.assertRaises(PermissionError):
            self.state.open_incidents()

    def test_legacy_dispatch_migration_fails_closed_without_terminal(self):
        self.state.append({'tool':'send_once','binding':'legacy','outcome':'dispatch_intent','at':1})
        incident = self.state.open_incidents()[0]
        self.assertEqual(incident['status'], 'dispatch_outcome_unknown')
        self.assertEqual(len(incident['action_id']), 32)
        self.assertEqual(self.call()['error']['message'], 'tool_quarantined_pending_reconciliation')

    def test_legacy_completed_and_uncertain_migration(self):
        self.state.append({'tool':'send_once','binding':'legacy','outcome':'dispatch_intent','at':1})
        self.state.append({'tool':'send_once','binding':'legacy','outcome':'backend_reported_result','at':2})
        self.assertEqual(self.state.open_incidents(), [])
        self.state.append({'tool':'send_once','binding':'legacy2','outcome':'dispatch_intent','at':3})
        self.state.append({'tool':'send_once','binding':'legacy2','outcome':'invalid_backend_result_side_effect_possible','at':4})
        self.assertEqual(len(self.state.open_incidents()), 1)
        incident = self.state.open_incidents()[0]
        self.state.reconcile_incident(incident['action_id'], 'operator', 'ticket:legacy-readback-verified',
                                     'I_HAVE_RECONCILED_THE_EXTERNAL_EFFECT')
        self.assertEqual(self.state.open_incidents(), [])

    def test_agent_rpc_cannot_reconcile_its_incident(self):
        self.backend.mode = 'transport'
        self.call()
        incident = self.state.open_incidents()[0]
        forged = self.gateway.handle({'jsonrpc':'2.0','id':99,'method':'reconcile_incident',
            'params':{'action_id':incident['action_id'],
                      'reference':'ticket:agent-forged-12345',
                      'acknowledgement':'I_HAVE_RECONCILED_THE_EXTERNAL_EFFECT'}})
        self.assertEqual(forged['error']['message'], 'method_not_allowed')
        self.assertEqual(len(self.state.open_incidents()),1)

    @unittest.skipUnless(__import__('sys').platform == 'linux', 'Linux broker IPC requires SO_PEERCRED')
    def test_operator_rpc_is_the_only_supported_clear_path(self):
        from catl.broker import BrokerServer
        self.backend.mode='bad_reply'
        self.call()
        incident=self.state.open_incidents()[0]
        supervisor=BrokerServer(self.gateway,self.state,self.policy,
            agent_socket=Path(self.temp.name)/'agent.sock',
            operator_socket=Path(self.temp.name)/'operator.sock',
            agent_uid=10001,operator_uid=10002,allow_test_same_uid=True)
        visible=supervisor._op({'op':'incidents'},10002)
        self.assertEqual(visible['incidents'][0]['action_id'],incident['action_id'])
        with self.assertRaises(ValueError):
            supervisor._op({'op':'reconcile_incident','action_id':incident['action_id'],
                'reference':'ticket:readback-checked-001','acknowledgement':'fake'},10002)
        cleared=supervisor._op({'op':'reconcile_incident','action_id':incident['action_id'],
            'reference':'readback:provider-confirmation-1',
            'acknowledgement':'I_HAVE_RECONCILED_THE_EXTERNAL_EFFECT'},10002)
        self.assertTrue(cleared['accepted'])
        self.assertEqual(self.state.open_incidents(),[])

    def test_incident_records_have_no_raw_arguments(self):
        self.backend.mode='bad_reply'
        self.call()
        incident=self.state.open_incidents()[0]
        self.assertNotIn('arguments', incident)
        self.assertTrue(self.state.verify()['valid'])

if __name__ == '__main__':
    unittest.main()
