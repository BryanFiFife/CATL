"""Security sanity exceptions must not become broad network escape hatches."""
from __future__ import annotations
import importlib.util
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('catl_static_sanity', ROOT / 'tools' / 'security_sanity.py')
sanity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sanity)

class SecuritySanityBoundaryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root/'src'/'catl').mkdir(parents=True)
        self.patch = patch.object(sanity, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def write(self, name, source):
        (self.root/'src'/'catl'/name).write_text(source, encoding='utf-8')
        return sanity.check_runtime()

    def test_windows_token_ctypes_only_in_platform_evidence(self):
        self.assertEqual(self.write('platform_proofs.py', 'import ctypes\nfrom ctypes import wintypes\n'), [])
        self.assertTrue(self.write('broker.py', 'import ctypes\n'))

    def test_witness_transport_symbols_explicit_only(self):
        allowed = ('from urllib.request import Request, build_opener, HTTPSHandler, '
                   'HTTPRedirectHandler, ProxyHandler\n')
        self.assertEqual(self.write('witness_protocol.py', allowed), [])
        self.assertTrue(self.write('broker.py', allowed))
        self.assertTrue(self.write('witness_protocol.py', 'from urllib.request import urlopen\n'))
        self.assertTrue(self.write('witness_protocol.py', 'import urllib.request\n'))

    def test_tcp_socket_family_forbidden_even_in_platform_module(self):
        self.assertTrue(self.write('platform_proofs.py', 'import socket\nsocket.AF_INET\n'))

    def test_subprocess_shell_escape_denied(self):
        self.assertTrue(self.write('platform_proofs.py', 'import subprocess\nsubprocess.Popen(["echo"], shell=True)\n'))

    def test_dynamic_exec_forbidden(self):
        self.assertTrue(self.write('witness_protocol.py', 'exec("print(1)")\n'))

if __name__ == '__main__': unittest.main()
