"""Adversarial network-local and backend-channel resource-exhaustion tests.

These reproduce live attempts; they are not a substitute for host-level review.
"""
from __future__ import annotations

import io
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock

from catl.broker import MAX_AGENT_CLIENTS, MAX_OPERATOR_CLIENTS, BrokerServer
from catl.gateway import SubprocessBackend


class CICredentialBoundaryTests(unittest.TestCase):
    def test_privileged_linux_runner_ignores_fork_pull_requests(self):
        path = Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml'
        workflow = path.read_text()
        protected = workflow.split('  linux-graphical-and-identity:',1)[1].split('  security-scans:',1)[0]
        self.assertIn("github.event_name != 'pull_request'",protected)
        self.assertIn('github.event.pull_request.head.repo.full_name == github.repository',protected)
        self.assertIn('sudo ',protected)


class BackendFloodTests(unittest.TestCase):
    def test_malicious_backend_notification_flood_never_blocks_reader(self):
        # A backend could emit unsolicited progress indefinitely. Once the
        # bounded queue is full, the reader must STOP without blocking in put().
        flood = (b'{"jsonrpc":"2.0","method":"notifications/progress"}\n' * 40)
        backend = object.__new__(SubprocessBackend)
        backend.events = queue.Queue(maxsize=3)
        backend._overflow = threading.Event()
        backend.proc = Mock(stdout=io.BytesIO(flood))
        backend.timeout = 0.1
        backend.seq = 0
        backend._send = Mock()
        backend.close = Mock()
        pump = threading.Thread(target=backend._pump, daemon=True)
        pump.start()
        pump.join(timeout=1)
        self.assertFalse(pump.is_alive(), 'untrusted backend can permanently pin pump thread')
        self.assertTrue(backend._overflow.is_set())
        with self.assertRaisesRegex(RuntimeError, 'backend_event_queue_overflow'):
            backend.request('tools/call', {'name': 'sink', 'arguments': {}})
        backend.close.assert_called_once()
    def test_malformed_backend_flood_fails_closed_without_infinite_spin(self):
        backend = object.__new__(SubprocessBackend)
        backend.events = queue.Queue(maxsize=3)
        backend._overflow = threading.Event()
        backend.proc = Mock(stdout=io.BytesIO(b'not-json\n' * 1000))
        backend.timeout = 0.1
        backend.seq = 0
        backend._send = Mock()
        backend.close = Mock()
        pump = threading.Thread(target=backend._pump, daemon=True)
        pump.start()
        pump.join(timeout=1)
        self.assertFalse(pump.is_alive())
        self.assertTrue(backend._overflow.is_set())
        with self.assertRaisesRegex(RuntimeError, 'backend_event_queue_overflow'):
            backend.request('tools/call', {'name':'sink'})


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'requires root on Linux to prove SO_PEERCRED separation')
class OperatorFloodTests(unittest.TestCase):
    def test_agent_saturates_its_budget_but_operator_status_stays_available(self):
        # Reuse the existing real-UID setup, but run an agent that deliberately
        # keeps more AF_UNIX clients idle than the agent reservation allows.
        from test_broker_anchor import TestBrokerIdentity
        target = TestBrokerIdentity(methodName='test_agent_cannot_use_operator_channel')
        target.setUp()
        try:
            self.assertGreater(MAX_AGENT_CLIENTS, 0)
            self.assertGreater(MAX_OPERATOR_CLIENTS, 0)
            script = r'''import socket, sys, time
socks=[]
for x in range(int(sys.argv[2])):
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    try: s.connect(sys.argv[1]); socks.append(s)
    except OSError: s.close()
print('READY', flush=True)
time.sleep(4)
'''
            proc = subprocess.Popen([sys.executable, '-c', script, str(target.agent_socket),
                                     str(MAX_AGENT_CLIENTS + MAX_OPERATOR_CLIENTS)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    preexec_fn=lambda: os.setuid(target.AGENT))
            try:
                self.assertEqual(proc.stdout.readline().strip(), 'READY')
                time.sleep(0.3)  # Let the agent accept thread slots fill.
                t0 = time.monotonic()
                reply = target._client(target.OPERATOR, '{"op":"status"}', target.operator_socket)
                self.assertIn('"ok":true', reply.stdout.replace(' ', ''))
                self.assertLess(time.monotonic()-t0, 3, 'agent flood blocked emergency operator')
            finally:
                proc.terminate()
                try: proc.communicate(timeout=3)
                except subprocess.TimeoutExpired: proc.kill(); proc.communicate(timeout=3)
        finally:
            target._shutdown()


if __name__ == '__main__':
    unittest.main()
