"""Native Linux regression for orphaned MCP backend process groups.

This is a focused subset; the full 11-case adversarial suite is distributed
with the CATL v10 security bundle. No shell or network tool is required.
"""
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

if os.environ.get('CATL_V10_TEST_GATEWAY_SOURCE'):
    import importlib.util
    spec=importlib.util.spec_from_file_location('catl_test_gateway',os.environ['CATL_V10_TEST_GATEWAY_SOURCE'])
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    Backend=module.SubprocessBackend
else:
    from catl.gateway import SubprocessBackend as Backend


def living(pid):
    try:
        return Path('/proc') .joinpath(str(pid),'stat').read_text().split()[2] != 'Z'
    except FileNotFoundError:
        return False


@unittest.skipUnless(sys.platform=='linux','Linux process-group test')
class BackendGroupTest(unittest.TestCase):
    def test_exited_leader_does_not_leave_child(self):
        with tempfile.TemporaryDirectory() as td:
            pidfile=Path(td)/'child'
            script=("import subprocess,sys\n"
                    "x=subprocess.Popen([sys.executable,'-c','import signal,time;"
                    "signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(90)'],"
                    "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                    "open(sys.argv[1],'w').write(str(x.pid))\n")
            p=subprocess.Popen([sys.executable,'-c',script,str(pidfile)],start_new_session=True,
                               stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            child=None
            try:
                limit=time.monotonic()+3
                while not pidfile.exists() and time.monotonic()<limit:time.sleep(.02)
                self.assertTrue(pidfile.exists())
                child=int(pidfile.read_text());p.wait(timeout=3)
                self.assertTrue(living(child))
                obj=Backend.__new__(Backend)
                obj.proc=p;obj._close_lock=threading.Lock();obj._closed=False
                obj.close()
                limit=time.monotonic()+2
                while living(child) and time.monotonic()<limit:time.sleep(.02)
                self.assertFalse(living(child))
                obj.close()  # idempotent
            finally:
                if child and living(child):
                    try:os.kill(child,signal.SIGKILL)
                    except ProcessLookupError:pass
                if p.poll() is None:p.kill();p.wait(timeout=2)

    def test_eof_reaps_child_without_next_request(self):
        with tempfile.TemporaryDirectory() as td:
            pidfile=Path(td)/'child'
            script=("import subprocess,sys\n"
                    "x=subprocess.Popen([sys.executable,'-c','import time;time.sleep(90)'],"
                    "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                    "open(sys.argv[1],'w').write(str(x.pid))\n")
            obj=Backend([sys.executable,'-c',script,str(pidfile)],allow_unsandboxed=True,timeout=1)
            child=None
            try:
                limit=time.monotonic()+3
                while not pidfile.exists() and time.monotonic()<limit:time.sleep(.02)
                self.assertTrue(pidfile.exists())
                child=int(pidfile.read_text())
                limit=time.monotonic()+3
                while living(child) and time.monotonic()<limit:time.sleep(.02)
                self.assertFalse(living(child))
            finally:
                obj.close()
                if child and living(child):
                    try:os.kill(child,signal.SIGKILL)
                    except ProcessLookupError:pass

    def test_normal_backend_request_still_works(self):
        script=("import sys,json\n"
                "for line in sys.stdin:\n"
                " m=json.loads(line)\n"
                " print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'ok':True}}),flush=True)\n")
        obj=Backend([sys.executable,'-c',script],allow_unsandboxed=True,timeout=2)
        try:self.assertEqual(obj.request('tools/list',{})['result'],{'ok':True})
        finally:obj.close()
        self.assertIsNotNone(obj.proc.poll())

if __name__ == '__main__':unittest.main()
