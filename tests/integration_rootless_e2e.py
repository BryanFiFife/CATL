"""Root-only Linux integration, separate identities and real Unix sockets.

RUN ONLY inside a disposable privileged test environment:
  PYTHONPATH=src python tests/integration_rootless_e2e.py
This uses synthetic UIDs/GIDs and never creates system users.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import socket
import signal
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
UID_BROKER = 26101
UID_AGENT = 26102
UID_OPERATOR = 26103
UID_BACKEND = 26104
G_AGENT = 26202
G_OPERATOR = 26203
G_BACKEND = 26204
PYTHONPATH = str(ROOT / 'src')
ENV = {**os.environ, 'PYTHONPATH': PYTHONPATH, 'PYTHONDONTWRITEBYTECODE': '1'}


def as_identity(uid, groups, cmd):
    return ['setpriv', f'--reuid={uid}', f'--regid={uid}', f'--groups={",".join(str(g) for g in groups) or "0"}', *cmd]


def run_as(uid, groups, cmd, *, timeout=20):
    return subprocess.run(as_identity(uid, groups, cmd), capture_output=True, text=True, env=ENV, timeout=timeout)


def subprocess_as(uid, groups, cmd):
    return subprocess.Popen(as_identity(uid, groups, cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=ENV, start_new_session=True)


def wait_socket(path, proc, timeout=8):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        if path.is_socket():
            return
        if proc.poll() is not None:
            raise AssertionError(f'service died {proc.returncode}: {proc.stderr.read()}')
        time.sleep(0.03)
    raise AssertionError(f'timed out waiting for {path}: {proc.poll()}')


def ipc(uid, groups, path, payload):
    snippet = '''import json,socket,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(7)
try:
 s.connect(sys.argv[1]);s.sendall((sys.argv[2]+"\\n").encode())
 data=b""
 while not data.endswith(b"\\n"):
  chunk=s.recv(65536)
  if not chunk:break
  data+=chunk
 print(data.decode().strip())
finally:s.close()'''
    return run_as(uid, groups, [sys.executable, '-c', snippet, str(path), json.dumps(payload)])


def ensure_permissions(root):
    root.chmod(0o755)
    def directory(name, owner, group, mode):
        p=root/name;p.mkdir(mode=0o700);os.chown(p,owner,group);p.chmod(mode);return p
    return {
      'state':directory('state', UID_BROKER, UID_BROKER, 0o700),
      'anchor':directory('anchor', UID_BROKER, UID_BROKER, 0o700),
      'agent':directory('agent-channel',UID_BROKER,G_AGENT,0o710),
      'operator':directory('operator-channel',UID_BROKER,G_OPERATOR,0o710),
      'backend':directory('backend-channel',UID_BACKEND,G_BACKEND,0o710),
      'workdir':directory('backend-workspace',UID_BACKEND,UID_BACKEND,0o700),
    }


def main():
    if sys.platform != 'linux' or os.geteuid()!=0 or not shutil.which('setpriv'):
        print('SKIP: needs disposable Linux root test host and setpriv')
        return 77
    from catl.crypto import digest
    from catl.operator_auth import generate_test_software_keypair
    from importlib.util import spec_from_file_location, module_from_spec
    spec=spec_from_file_location('mock',ROOT/'examples/mock_server.py'); mod=module_from_spec(spec);spec.loader.exec_module(mod)
    with tempfile.TemporaryDirectory(prefix='catl-rootless-') as td:
        root=Path(td); paths=ensure_permissions(root)
        policy={'agent_id':'rootless-smoke','tool_pins':{t['name']:digest(t) for t in mod.TOOLS},
                'rules':[{'tool':'echo_safe','effect':'allow','conditions':[]},
                         {'tool':'write_demo','effect':'approve','conditions':[]}]}
        config=root/'policy.json';config.write_text(json.dumps(policy));config.chmod(0o644)
        signing_dir=root/'operator-keys';signing_dir.mkdir(mode=0o700)
        signing_dir.chmod(0o700)
        private_key=signing_dir/'operator-private.pem'
        public_key=root/'broker-operator-public.hex'
        generate_test_software_keypair(private_key,public_key)
        os.chown(private_key,UID_OPERATOR,UID_OPERATOR)
        os.chown(signing_dir,UID_OPERATOR,UID_OPERATOR)
        anchor=paths['anchor']/'head.json'
        backend_sock=paths['backend']/'tools.sock'
        agent_sock=paths['agent']/'agent.sock';op_sock=paths['operator']/'operator.sock'
        # Initialize protected DB and separately anchored head under the dedicated broker identity.
        init=run_as(UID_BROKER,[G_AGENT,G_OPERATOR,G_BACKEND],
                 [sys.executable,'-m','catl','anchor-init','--state-dir',str(paths['state']),
                  '--anchor-path',str(anchor),'--accept-current-verified-head'])
        assert init.returncode==0,(init.stderr,init.stdout)
        external=subprocess_as(UID_BACKEND,[G_BACKEND], [sys.executable,'-m','catl','backend-service',
                  '--socket',str(backend_sock),'--broker-uid',str(UID_BROKER),
                  '--broker-gid',str(G_BACKEND),'--backend-workdir',str(paths['workdir']),'--',sys.executable,str(ROOT/'examples/mock_server.py')])
        broker=None
        try:
            wait_socket(backend_sock, external)
            broker=subprocess_as(UID_BROKER,[G_AGENT,G_OPERATOR,G_BACKEND],
                 [sys.executable,'-m','catl','broker', '--config',str(config),
                  '--state-dir',str(paths['state']), '--anchor-path',str(anchor),
                  '--agent-socket',str(agent_sock),'--operator-socket',str(op_sock),
                  '--agent-uid',str(UID_AGENT),'--operator-uid',str(UID_OPERATOR),
                  '--operator-public-key',str(public_key),
                  '--agent-gid',str(G_AGENT),'--operator-gid',str(G_OPERATOR),
                  '--backend-socket',str(backend_sock),'--backend-uid',str(UID_BACKEND)])
            wait_socket(agent_sock, broker); wait_socket(op_sock,broker)
            def op(payload):
                # The real operator CLI signs one-time challenges; no software
                # private key is readable by the broker, tool, or agent UID.
                script = """import json,sys
from catl.broker import OperatorClient
from pathlib import Path
client=OperatorClient(Path(sys.argv[1]),signing_key=Path(sys.argv[2]))
print(json.dumps({'ok':True,'result':client._rpc(json.loads(sys.argv[3]))}))"""
                out=run_as(UID_OPERATOR,[G_OPERATOR],
                           [sys.executable,'-c',script,str(op_sock),str(private_key),json.dumps(payload)])
                assert out.returncode==0,(out.stderr,out.stdout)
                return json.loads(out.stdout)
            def call(name,message):
                out=ipc(UID_AGENT,[G_AGENT],agent_sock,{'jsonrpc':'2.0','id':123,'method':'tools/call',
                               'params':{'name':name,'arguments':{'message':message}}})
                assert out.returncode==0,(out.stderr,out.stdout)
                return json.loads(out.stdout)
            forged = ipc(UID_OPERATOR,[G_OPERATOR],op_sock,
                {'op':'set_feature','feature':'gateway_enabled','enabled':True})
            assert forged.returncode==0 and json.loads(forged.stdout)['ok'] is False, forged
            assert op({'op':'set_feature','feature':'gateway_enabled','enabled':True})['ok']
            allowed=call('echo_safe','hello rootless');assert allowed['result']['content'][0]['text']=='hello rootless',allowed
            pending=call('write_demo','safe test data');assert pending['error']['message']=='human_approval_required',pending
            req=op({'op':'pending'})['result']['requests'];assert len(req)==1,req
            assert op({'op':'decide','id':req[0]['id'],'approve':True})['result']['accepted']
            done=call('write_demo','safe test data');assert done.get('result',{}).get('content',[{}])[0].get('text')=='written',done
            reused=call('write_demo','safe test data');assert reused['error']['message']=='human_approval_required',reused
            blocked=ipc(UID_AGENT,[G_AGENT],op_sock,{'op':'set_feature','feature':'gateway_enabled','enabled':False})
            assert blocked.returncode != 0 or not blocked.stdout.strip(),blocked
            blocked=ipc(UID_OPERATOR,[G_OPERATOR],agent_sock,{'jsonrpc':'2.0','id':8,'method':'ping'})
            assert blocked.returncode != 0 or not blocked.stdout.strip(),blocked
            assert op({'op':'verify'})['result']['valid']
            unpriv=run_as(UID_BACKEND,[G_BACKEND],[sys.executable,'-c','import pathlib,sys;pathlib.Path(sys.argv[1]).read_bytes()',str(paths['state']/'audit.key')])
            assert unpriv.returncode!=0,unpriv
            print('PASS rootless Linux 4-UID signed E2E: unsigned-forgery denial, tool call, approval/replay, audit, channel isolation, key denial', flush=True)
            return 0
        finally:
            # No communicate(): backend descendants might inherit a pipe and block EOF.
            for child in (broker,external):
                if child is not None:
                    if child.poll() is None:
                        try:os.killpg(child.pid, signal.SIGTERM)
                        except ProcessLookupError:pass
                    try:child.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        try:os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:pass
                        child.wait(timeout=3)
                    for pipe in (child.stdout,child.stderr):
                        if pipe is not None:
                            pipe.close()

if __name__=='__main__':
    try:
        code = main()
    except Exception:
        traceback.print_exc()
        code = 1
    raise SystemExit(code)
