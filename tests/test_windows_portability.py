"""Explicit regression gates: unsupported Windows broker must fail closed.

These tests run on all platforms using a simulated Windows platform marker.
They do NOT establish a safe Windows backend security boundary.
"""
from __future__ import annotations
import unittest
from pathlib import Path
from unittest.mock import patch

from catl.broker import BrokerServer, _exchange
from catl.external_backend import SocketBackend


class UnsupportedWindowsSafety(unittest.TestCase):
    def test_broker_server_rejects_windows(self):
        with patch("catl.broker.sys.platform", "win32"):
            with self.assertRaisesRegex(PermissionError, "broker_requires_linux_so_peercred"):
                BrokerServer(None, None, None, agent_socket=Path("agent.sock"),
                             operator_socket=Path("operator.sock"), agent_uid=1101, operator_uid=1102)

    def test_broker_client_rejects_windows(self):
        with patch("catl.broker.sys.platform", "win32"):
            with self.assertRaisesRegex(PermissionError, "broker_client_linux_only"):
                _exchange(Path("operator.sock"), {"op": "status"})

    def test_external_backend_rejects_windows(self):
        with patch("catl.external_backend.sys.platform", "win32"):
            with self.assertRaisesRegex(PermissionError, "external_backend_requires_linux_peercred"):
                SocketBackend(Path("backend.sock"), backend_uid=1103)

if __name__ == "__main__":
    unittest.main()
