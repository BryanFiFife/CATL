"""Real Linux kernel UID/group/socket ACL tests without CATL source or services.

Use anonymous synthetic UIDs and disposable /tmp sockets. They prove kernel
primitives, NOT production CATL account membership or broker authorisation.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0 and shutil.which('setpriv'),
                     'Requires isolated root Linux test host with setpriv')
class KernelSocketAclTests(unittest.TestCase):
    BROKER=60451;AGENT=60452;OPERATOR=60453;BACKEND=60454
    AGENT_G=61451;OPERATOR_G=61452;BACKEND_G=61453

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='catl-real-uid-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o755)
        self.stop=threading.Event();self.threads=[];self.server_sockets=[]
        self.observed={name:[] for name in ('agent','operator','backend')}
        specs={
            'agent':(self.BROKER,self.AGENT_G),
            'operator':(self.BROKER,self.OPERATOR_G),
            'backend':(self.BACKEND,self.BACKEND_G),
        }
        self.paths={}
        for name,(owner,gid) in specs.items():
            directory=self.root/name
            directory.mkdir();os.chown(directory,owner,gid);directory.chmod(0o710)
            path=directory/'service.sock';self.paths[name]=path
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(path));os.chown(path,owner,gid);os.chmod(path,0o660)
            listener.listen(32);listener.setblocking(False)
            self.server_sockets.append(listener)
            thread=threading.Thread(target=self.accept_loop,args=(name,listener),daemon=True)
            thread.start();self.threads.append(thread)
        self.addCleanup(self.cleanup_listeners)

    def cleanup_listeners(self):
        self.stop.set()
        for sock in self.server_sockets:sock.close()
        for t in self.threads:t.join(timeout=2)

    def accept_loop(self,name,listener):
        while not self.stop.is_set():
            try:
                readable,_,_=select.select([listener],[],[],0.15)
                if not readable:continue
                client,_=listener.accept()
                uid=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
                self.observed[name].append(uid)
                client.close()
            except (OSError,ValueError):return

    def attempt(self,uid,groups,target):
        code='''import errno,json,socket,sys\np=sys.argv[1]\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\ntry:\n s.connect(p)\n print("connected")\nexcept OSError as e:\n print("errno:"+str(e.errno))\nfinally:\n s.close()\n'''
        args=['setpriv',f'--reuid={uid}',f'--regid={uid}',
              '--groups='+','.join(map(str,groups)),'--',sys.executable,
              '-c',code,str(self.paths[target])]
        run=subprocess.run(args,capture_output=True,text=True,timeout=5)
        if run.returncode:
            self.fail(f'setpriv failed (host not suitable): {run.stderr}')
        return run.stdout.strip()

    def test_real_socket_acl_and_peer_credential_matrix(self):
        matrix={
            self.AGENT:([self.AGENT_G], {'agent'}),
            self.OPERATOR:([self.OPERATOR_G], {'operator'}),
            self.BACKEND:([self.BACKEND_G], {'backend'}),
            self.BROKER:([self.AGENT_G,self.OPERATOR_G,self.BACKEND_G], {'agent','operator','backend'}),
        }
        for uid,(groups,permitted) in matrix.items():
            for target in self.paths:
                with self.subTest(uid=uid,target=target):
                    result=self.attempt(uid,groups,target)
                    if target in permitted:
                        self.assertEqual(result,'connected')
                    else:
                        self.assertIn(result,(f'errno:{errno.EACCES}',f'errno:{errno.EPERM}'))
        deadline=time.monotonic()+2
        while time.monotonic()<deadline and sum(map(len,self.observed.values()))<6:
            time.sleep(.03)
        # Each endpoint sees the correct, real process UIDs, not a label
        # supplied by an untrusted JSON-RPC client.
        self.assertEqual(set(self.observed['agent']),{self.AGENT,self.BROKER})
        self.assertEqual(set(self.observed['operator']),{self.OPERATOR,self.BROKER})
        self.assertEqual(set(self.observed['backend']),{self.BACKEND,self.BROKER})

if __name__=='__main__':unittest.main()
