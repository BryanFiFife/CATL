"""Process-lifecycle adversarial regression for CATL's subprocess backend.

Tests spawn only disposable Python children in a private Linux process group.
Never sends a signal to the test runner's process group.
"""
from __future__ import annotations
import os, signal, subprocess, sys, tempfile, threading, time, unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

# An explicitly selected fixture is allowed for the offline before/after
# repro. Normal CATL tests MUST import the production gateway implementation.
source=os.environ.get('CATL_V10_TEST_GATEWAY_SOURCE')
if source:
    spec=spec_from_file_location('catl_subprocess_fixture',Path(source))
    module=module_from_spec(spec);spec.loader.exec_module(module)
    Backend=module.SubprocessBackend
else:
    from catl.gateway import SubprocessBackend as Backend


def live(pid):
    try:return Path(f'/proc/{pid}/stat').read_text().split()[2]!='Z'
    except (FileNotFoundError, ProcessLookupError):return False


def mkobj(proc):
    obj=Backend.__new__(Backend)
    obj.proc=proc
    obj._close_lock=threading.Lock()
    obj._closed=False
    return obj


def spawn_group(child_code, *, parent_exits=True):
    """Return parent process, named grandchild PID and fresh isolated group."""
    td=tempfile.TemporaryDirectory()
    pidfile=Path(td.name)/'pid'
    text=("import subprocess,sys,time\n"
          f"c=subprocess.Popen([sys.executable, '-c', {child_code!r}],"
          "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
          "open(sys.argv[1],'w').write(str(c.pid))\n"
          + ("" if parent_exits else "time.sleep(120)\n"))
    proc=subprocess.Popen([sys.executable,'-c',text,str(pidfile)],start_new_session=True,
                          stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    deadline=time.monotonic()+4
    while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.02)
    if not pidfile.exists():
        os.killpg(proc.pid,signal.SIGKILL)
        proc.wait(timeout=2)
        td.cleanup()
        raise AssertionError('grandchild failed to start')
    pid=int(pidfile.read_text())
    return proc,pid,td


@unittest.skipUnless(sys.platform=='linux','POSIX process-group coverage')
class DescendantCleanupTests(unittest.TestCase):
    def _close_and_assert(self,proc,pid,td, *, leader_exits):
        self.addCleanup(td.cleanup)
        self.addCleanup(lambda:proc.poll() is None and proc.kill())
        if leader_exits:proc.wait(timeout=3)
        self.assertTrue(live(pid),'test grandchild did not survive setup')
        obj=mkobj(proc)
        try:
            obj.close()
            deadline=time.monotonic()+2
            while live(pid) and time.monotonic()<deadline:time.sleep(.02)
            self.assertFalse(live(pid),'orphaned child survived close()')
            return obj
        finally:
            if live(pid):
                try:os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass

    def test_exited_backend_leader_cannot_leave_descendant(self):
        p,pid,td=spawn_group('import time;time.sleep(120)')
        self._close_and_assert(p,pid,td,leader_exits=True)

    def test_exited_leader_ignoring_term_cannot_leave_descendant(self):
        p,pid,td=spawn_group('import time,signal;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(120)')
        self._close_and_assert(p,pid,td,leader_exits=True)

    def test_running_backend_leader_and_descendant_both_terminated(self):
        p,pid,td=spawn_group('import time;time.sleep(120)',parent_exits=False)
        self._close_and_assert(p,pid,td,leader_exits=False)
        self.assertIsNotNone(p.poll())

    def test_close_is_idempotent(self):
        p,pid,td=spawn_group('import time;time.sleep(120)')
        obj=self._close_and_assert(p,pid,td,leader_exits=True)
        obj.close()
        self.assertTrue(obj._closed)

    def test_concurrent_close_is_serialized(self):
        p,pid,td=spawn_group('import time;time.sleep(120)')
        self.addCleanup(td.cleanup)
        p.wait(timeout=3)
        obj=mkobj(p)
        errs=[]
        def close():
            try:obj.close()
            except Exception as e:errs.append(e)
        try:
            threads=[threading.Thread(target=close) for _ in range(8)]
            for t in threads:t.start()
            for t in threads:t.join(4)
            self.assertFalse(any(t.is_alive() for t in threads))
            self.assertEqual(errs,[])
            deadline=time.monotonic()+2
            while live(pid) and time.monotonic()<deadline:time.sleep(.02)
            self.assertFalse(live(pid))
        finally:
            if live(pid):
                try:os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass

    def test_reader_eof_reaps_orphan_without_next_request(self):
        with tempfile.TemporaryDirectory() as td:
            pidfile=Path(td)/'childpid'
            program=("import subprocess,sys\n"
                     "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'],"
                     "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                     "open(sys.argv[1],'w').write(str(c.pid))\n")
            backend=Backend([sys.executable,'-c',program,str(pidfile)],allow_unsandboxed=True,timeout=1)
            pid=None
            try:
                deadline=time.monotonic()+3
                while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.02)
                self.assertTrue(pidfile.exists())
                pid=int(pidfile.read_text())
                backend.proc.wait(timeout=2)
                deadline=time.monotonic()+3
                while live(pid) and time.monotonic()<deadline:time.sleep(.02)
                self.assertFalse(live(pid),'reader EOF left orphaned grandchild without request')
            finally:
                backend.close()
                if pid and live(pid):
                    try:os.kill(pid,signal.SIGKILL)
                    except ProcessLookupError:pass

    def test_send_after_exited_backend_reaps_orphan(self):
        p,pid,td=spawn_group('import time;time.sleep(120)')
        self.addCleanup(td.cleanup)
        p.wait(timeout=2)
        obj=mkobj(p)
        try:
            with self.assertRaises(RuntimeError):
                obj._send({'jsonrpc':'2.0','method':'ping'})
            deadline=time.monotonic()+2
            while live(pid) and time.monotonic()<deadline:time.sleep(.02)
            self.assertFalse(live(pid),'sending to exited backend did not reap child')
        finally:
            if live(pid):
                try:os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass

    def test_invalid_stdout_flood_reaps_orphan_without_request(self):
        with tempfile.TemporaryDirectory() as td:
            pidfile=Path(td)/'childpid'
            program=("import subprocess,sys\n"
                     "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'],"
                     "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                     "open(sys.argv[1],'w').write(str(c.pid))\n"
                     "sys.stdout.write('not-json\\n'*40);sys.stdout.flush()\n"
                     "import time;time.sleep(120)\n")
            backend=Backend([sys.executable,'-c',program,str(pidfile)],allow_unsandboxed=True,timeout=1)
            pid=None
            try:
                deadline=time.monotonic()+3
                while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.02)
                self.assertTrue(pidfile.exists())
                pid=int(pidfile.read_text())
                deadline=time.monotonic()+3
                while live(pid) and time.monotonic()<deadline:time.sleep(.02)
                self.assertFalse(live(pid),'malformed response flood left child')
            finally:
                backend.close()
                if pid and live(pid):
                    try:os.kill(pid,signal.SIGKILL)
                    except ProcessLookupError:pass

    def test_valid_request_response_still_works(self):
        program=("import sys,json\n"
                 "for line in sys.stdin:\n"
                 "    msg=json.loads(line)\n"
                 "    print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{'ok':True}}),flush=True)\n")
        backend=Backend([sys.executable,'-c',program],allow_unsandboxed=True,timeout=2)
        try:
            response=backend.request('tools/list',{})
            self.assertEqual(response['result'],{'ok':True})
        finally:backend.close()
        self.assertIsNotNone(backend.proc.poll())

    def test_stalled_stdin_writer_is_time_bounded_and_reaped(self):
        backend=Backend([sys.executable,'-c','import time;time.sleep(120)'],allow_unsandboxed=True,timeout=.4)
        started=time.monotonic()
        try:
            with self.assertRaises((TimeoutError,RuntimeError)):
                backend._send({'jsonrpc':'2.0','id':'x','method':'x','params':{'data':'z'*500000}})
            self.assertLess(time.monotonic()-started,4,'blocking pipe write pinned broker')
            self.assertIsNotNone(backend.proc.poll())
        finally:backend.close()

    def test_ordinary_running_backend_terminated(self):
        p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'],
                            start_new_session=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            obj=mkobj(p)
            obj.close()
            self.assertIsNotNone(p.poll())
            self.assertTrue(obj._closed)
        finally:
            if p.poll() is None:p.kill();p.wait(timeout=2)

if __name__=='__main__':unittest.main()
