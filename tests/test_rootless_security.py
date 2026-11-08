"""Rootless broker security invariants. These tests don't certify OS sandboxing."""
from __future__ import annotations
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from catl.external_backend import (ALLOWED_NOTIFICATION_METHODS, ALLOWED_REQUEST_METHODS,
    SocketBackend, BackendService, validate_service_environment, _check_socket_path)
from catl.broker import _prepare_socket, BrokerServer


@unittest.skipUnless(sys.platform=='linux', 'Linux SO_PEERCRED required')
class TestRootlessSecurity(unittest.TestCase):
    def setUp(self):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.folder=Path(td.name)

    def test_distinct_backend_uid_required(self):
        with self.assertRaises(PermissionError):
            SocketBackend(self.folder/'missing.sock', backend_uid=os.geteuid())

    def test_backend_uid_cannot_be_root(self):
        with self.assertRaises(PermissionError):
            SocketBackend(self.folder/'missing.sock', backend_uid=0)

    def test_backend_timeout_bounded(self):
        for bad in (-1,0,121,float('nan')):
            with self.assertRaises(ValueError):
                SocketBackend(self.folder/'missing.sock', backend_uid=27899, timeout=bad)

    def test_unknown_backend_request_not_forwarded(self):
        b=SocketBackend(self.folder/'missing.sock',backend_uid=27899)
        with self.assertRaises(PermissionError):
            b.request('prompts/get',{})
        with self.assertRaises(PermissionError):
            b.request('resources/read',{})

    def test_unknown_notifications_not_forwarded(self):
        b=SocketBackend(self.folder/'missing.sock',backend_uid=27899)
        with self.assertRaises(PermissionError):
            b.notify('tools/call',{})

    def test_backend_method_allowlist_exact(self):
        # The external socket must support the explicit modern MCP adapter's
        # server/discover method, alongside the existing legacy operations.
        # This is an exact allowlist: resource, prompt and arbitrary RPC
        # methods remain prohibited at the broker/backend boundary.
        self.assertEqual(ALLOWED_REQUEST_METHODS, {
            'initialize', 'server/discover', 'tools/list', 'tools/call'})
        self.assertEqual(ALLOWED_NOTIFICATION_METHODS,{'notifications/initialized'})

    def test_backend_parent_symlink_denied(self):
        real=self.folder/'real';real.mkdir()
        proxy=self.folder/'proxy';proxy.symlink_to(real,target_is_directory=True)
        with self.assertRaises(PermissionError):
            _check_socket_path(proxy/'fake.sock')

    def test_backend_service_refuses_privileged_uid(self):
        if os.geteuid()!=0:
            self.skipTest('requires root to test root refusal')
        with self.assertRaises(PermissionError):
            validate_service_environment(self.folder/'tool.sock', broker_uid=12345, broker_gid=12346)

    def test_backend_service_refuses_same_broker_identity(self):
        with patch('catl.external_backend.os.geteuid', return_value=1500), patch('catl.external_backend.os.getgroups', return_value=[1600]),patch('catl.external_backend.os.getegid',return_value=1600):
            with self.assertRaises(PermissionError):
                validate_service_environment(self.folder/'tool.sock', broker_uid=1500,broker_gid=1600)

    def test_backend_service_refuses_group_not_granted(self):
        with patch('catl.external_backend.os.geteuid', return_value=1500), patch('catl.external_backend.os.getgroups', return_value=[1600]),patch('catl.external_backend.os.getegid',return_value=1600):
            with self.assertRaises(PermissionError):
                validate_service_environment(self.folder/'tool.sock', broker_uid=1700,broker_gid=1800)

    def test_backend_service_refuses_world_writable_parent(self):
        self.folder.chmod(0o777)
        with patch('catl.external_backend.os.geteuid', return_value=os.geteuid() or 1500),patch('catl.external_backend.os.getgroups',return_value=[1600]),patch('catl.external_backend.os.getegid',return_value=1600):
            try:
                validate_service_environment(self.folder/'tool.sock', broker_uid=1700,broker_gid=1600)
            except PermissionError:
                pass
            else:
                self.fail('writable parent accepted')

    def test_preexisting_backend_path_is_rejected(self):
        marker=self.folder/'tool.sock';marker.write_text('occupied')
        with patch('catl.external_backend.os.geteuid', return_value=os.geteuid() or 1500),patch('catl.external_backend.os.getgroups',return_value=[1600]),patch('catl.external_backend.os.getegid',return_value=1600):
            with self.assertRaises((FileExistsError,PermissionError)):
                validate_service_environment(marker,broker_uid=1700,broker_gid=1600)
        self.assertEqual(marker.read_text(),'occupied')

    def test_group_socket_cannot_change_owner(self):
        with self.assertRaises(PermissionError):
            _prepare_socket(self.folder/'socket', 12451, os.getegid(), group_access=True)

    def test_group_socket_requires_membership(self):
        with self.assertRaises(PermissionError):
            _prepare_socket(self.folder/'socket', os.geteuid(), 29812, group_access=True)

    def test_root_backend_service_cli_does_not_launch_tool(self):
        if os.geteuid()!=0:
            self.skipTest('root refusal test')
        marker=self.folder/'root-child-should-never-exist'
        root=Path(__file__).resolve().parents[1]
        proc=subprocess.run([sys.executable,'-m','catl','backend-service',
                             '--socket',str(self.folder/'tool.sock'), '--broker-uid','20111',
                             '--broker-gid','20112','--',sys.executable,'-c',
                             f'open({str(marker)!r},"w").write("unsafe")'],
                            env={**os.environ,'PYTHONPATH':str(root/'src')},
                            text=True,capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,2)
        self.assertFalse(marker.exists())

    def test_nonroot_backend_writes_no_supervisor_secrets(self):
        from catl.isolation import child_environment
        os.environ['CATL_FAKE_SECRET_TEST']='test-secret'
        try:
            env=child_environment()
            self.assertNotIn('CATL_FAKE_SECRET_TEST',env)
        finally:
            del os.environ['CATL_FAKE_SECRET_TEST']

if __name__ == '__main__':
    unittest.main()
