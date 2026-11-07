"""Native CATL broker regression tests: executed against catl.broker in repo.
These are not in the local reference suite until the native CATL source is available.
"""
from __future__ import annotations
import io
import json
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from catl.broker import AgentRequestBudget, BrokerServer, MAX_AGENT_REQUESTS_PER_MINUTE


class AdmissionBudgetTests(unittest.TestCase):
    def test_default_limit(self):
        self.assertEqual(MAX_AGENT_REQUESTS_PER_MINUTE, 600)
        self.assertEqual(AgentRequestBudget().limit, 600)

    def test_exhaustion_is_broker_wide(self):
        budget = AgentRequestBudget(limit=3)
        self.assertEqual([budget.admit() for _ in range(7)], [True, True, True, False, False, False, False])

    def test_concurrency_is_atomic(self):
        budget = AgentRequestBudget(limit=63)
        with ThreadPoolExecutor(max_workers=64) as pool:
            results = list(pool.map(lambda _: budget.admit(), range(2000)))
        self.assertEqual(sum(results), 63)

    def test_out_of_order_clock_reads_cannot_reopen_exhausted_budget(self):
        # A clock value read before taking the mutex could be scheduled
        # *after* a later time reset the window and allow extra attempts.
        import time
        import threading
        started = threading.Event()
        budget = AgentRequestBudget(limit=1, window_seconds=60)
        budget._window_start = 0.0
        observed = []

        def fake_clock():
            if threading.current_thread().name == 'first-reader':
                started.set()
                time.sleep(0.075)
                return 100.0
            return 101.0

        def first():
            observed.append(budget.admit())

        with patch('catl.broker.time.monotonic', side_effect=fake_clock):
            one = threading.Thread(target=first, name='first-reader')
            one.start()
            self.assertTrue(started.wait(2))
            two = threading.Thread(target=first, name='second-reader')
            two.start()
            one.join(3); two.join(3)
            self.assertFalse(one.is_alive() or two.is_alive())
        self.assertEqual(sum(observed), 1)

    def test_monotonic_window_reset(self):
        with patch('catl.broker.time.monotonic', return_value=100.0):
            budget = AgentRequestBudget(limit=2, window_seconds=60)
        with patch('catl.broker.time.monotonic', return_value=101.0):
            self.assertTrue(budget.admit())
            self.assertTrue(budget.admit())
            self.assertFalse(budget.admit())
        with patch('catl.broker.time.monotonic', return_value=160.0):
            self.assertTrue(budget.admit())
            self.assertTrue(budget.admit())
            self.assertFalse(budget.admit())

    def test_bad_limits_refused(self):
        for value in (None, True, False, 0, -1, 10001, '100', 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                AgentRequestBudget(limit=value)

    def test_bad_windows_refused(self):
        for value in (None, True, False, 0, -2, 3601, '30'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                AgentRequestBudget(window_seconds=value)

    def test_new_broker_has_own_budget(self):
        a, b = AgentRequestBudget(limit=1), AgentRequestBudget(limit=1)
        self.assertTrue(a.admit())
        self.assertFalse(a.admit())
        self.assertTrue(b.admit())


class _DuplexStream:
    def __init__(self, incoming):
        self.input = io.BytesIO(incoming)
        self.output = io.BytesIO()

    def readline(self, n=-1):
        return self.input.readline(n)

    def write(self, data):
        return self.output.write(data)

    def flush(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class _FakeConnection:
    def __init__(self, messages):
        self.stream = _DuplexStream(b''.join(json.dumps(message).encode() + b'\n' for message in messages))
        self.closed = False

    def settimeout(self, _):
        pass

    def makefile(self, *_args, **_kwargs):
        return self.stream

    def close(self):
        self.closed = True


class BrokerIngressTests(unittest.TestCase):
    @staticmethod
    def new_server(limit=1):
        broker = object.__new__(BrokerServer)
        broker.agent_uid = 30021
        broker.operator_uid = 30022
        broker._agent_budget = AgentRequestBudget(limit=limit)
        broker._gate_lock = threading.RLock()
        broker.stop = threading.Event()
        broker.gateway = Mock()
        broker.gateway.handle.return_value = {'jsonrpc': '2.0', 'id': 1, 'result': {}}
        return broker

    def test_real_ingress_refuses_second_request_before_gateway(self):
        broker = self.new_server(limit=1)
        messages = [dict(jsonrpc='2.0', id=i, method='ping') for i in (1, 2)]
        connection = _FakeConnection(messages)
        with patch('catl.broker._peer_uid', return_value=broker.agent_uid):
            broker._client(connection, 'agent')
        self.assertEqual(broker.gateway.handle.call_count, 1)
        self.assertTrue(connection.closed)
        lines = [json.loads(line) for line in connection.stream.output.getvalue().splitlines()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[-1]['error']['message'], 'agent_request_budget_exceeded')

    def test_reconnect_does_not_reset_budget(self):
        broker = self.new_server(limit=1)
        with patch('catl.broker._peer_uid', return_value=broker.agent_uid):
            broker._client(_FakeConnection([dict(jsonrpc='2.0', id=1, method='ping')]), 'agent')
            second = _FakeConnection([dict(jsonrpc='2.0', id=2, method='ping')])
            broker._client(second, 'agent')
        self.assertEqual(broker.gateway.handle.call_count, 1)
        self.assertIn(b'agent_request_budget_exceeded', second.stream.output.getvalue())

    def test_malformed_frame_still_consumes_request_credit(self):
        broker = self.new_server(limit=1)
        conn = _FakeConnection([])
        conn.stream = _DuplexStream(b'{not-json}\n' + b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n')
        with patch('catl.broker._peer_uid', return_value=broker.agent_uid):
            broker._client(conn, 'agent')
        self.assertEqual(broker.gateway.handle.call_count, 0)
        self.assertIn(b'agent_request_budget_exceeded', conn.stream.output.getvalue())

    def test_operator_channel_not_charged_against_agent_budget(self):
        broker = self.new_server(limit=1)
        broker._agent_budget.admit()
        broker._op = Mock(return_value={'ok': True})
        conn = _FakeConnection([{'op': 'status'}])
        with patch('catl.broker._peer_uid', return_value=broker.operator_uid):
            broker._client(conn, 'operator')
        self.assertEqual(broker._op.call_count, 1)
        self.assertIn(b'"ok":true', conn.stream.output.getvalue())


if __name__ == '__main__':
    unittest.main()
