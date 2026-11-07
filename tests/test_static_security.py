"""Small, explicit static regressions; NOT a substitute for external code audit."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / "src" / "catl"
NETWORK_IMPORTS = {"socket", "requests", "urllib", "http", "httpx", "aiohttp", "ftplib", "smtplib", "websocket", "websockets"}
DYNAMIC = {"eval", "exec", "compile", "__import__"}

class TestStaticSecurity(unittest.TestCase):
    def test_no_network_client_or_server_imports_in_supervisor(self):
        for file in ROOT.glob("*.py"):
            node=ast.parse(file.read_text(encoding="utf-8"))
            for item in ast.walk(node):
                if isinstance(item, ast.Import):
                    for part in item.names:
                        if file.name in ("broker.py", "external_backend.py") and part.name == "socket":
                            continue  # audited AF_UNIX-only local IPC, no TCP/IP endpoints
                        self.assertNotIn(part.name.split(".")[0],NETWORK_IMPORTS,f"{file.name}:{item.lineno}")
                if isinstance(item, ast.ImportFrom) and item.module:
                    # urllib.parse.urlsplit is a pure parser; urllib.request,
                    # urllib.error and every other network-capable submodule
                    # remain forbidden. This exception cannot open sockets.
                    if item.module == "urllib.parse" and {n.name for n in item.names} == {"urlsplit"}:
                        continue
                    self.assertNotIn(item.module.split(".")[0],NETWORK_IMPORTS,f"{file.name}:{item.lineno}")
    def test_broker_is_local_unix_only(self):
        for file in ("broker.py", "external_backend.py"):
            source = (ROOT / file).read_text(encoding="utf-8")
            self.assertIn("AF_UNIX", source)
            self.assertNotIn("AF_INET", source)
            self.assertNotIn("AF_INET6", source)
            self.assertNotIn("multiprocessing.connection", source)
            self.assertNotIn("pickle", source)
    def test_no_eval_exec_or_shell_true(self):
        for file in ROOT.glob("*.py"):
            node=ast.parse(file.read_text(encoding="utf-8"))
            for item in ast.walk(node):
                if isinstance(item, ast.Call):
                    if isinstance(item.func,ast.Name):
                        self.assertNotIn(item.func.id,DYNAMIC,f"{file.name}:{item.lineno}")
                    for k in item.keywords:
                        if k.arg=="shell":
                            self.assertFalse(isinstance(k.value,ast.Constant) and k.value.value is True,
                                             f"{file.name}:{item.lineno}")
