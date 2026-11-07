from __future__ import annotations
import os,sys,json,time,tempfile,subprocess,signal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if sys.platform != 'linux' or os.geteuid() != 0:
  raise SystemExit('SKIP: this exercise requires a disposable Linux root test environment')
ENV=os.environ | {'PYTHONPATH': str(ROOT/'src')}
AGENT=21002
OPERATOR=21001

def run(*args, uid=None, input=None, timeout=15):
  return subprocess.run([sys.executable,'-m','catl.cli',*map(str,args)],env=ENV,text=True,input=input,capture_output=True,timeout=timeout,
    preexec_fn=(lambda:os.setuid(uid)) if uid is not None else None)

with tempfile.TemporaryDirectory(prefix='catl-v04-e2e-') as d:
  p=Path(d);p.chmod(0o755)
  state=p/'state'; anchor_dir=p/'anchors';anchor_dir.mkdir(mode=0o700)
  socket_dir=p/'sockets';socket_dir.mkdir(mode=0o755)
  agent_sock=socket_dir/'agent.sock';op_sock=socket_dir/'operator.sock';anchor=anchor_dir/'audit.json'
  policy=ROOT/'examples/policy.json'; backend=ROOT/'examples/mock_server.py'
  demo=p/'demo'; demo.mkdir(mode=0o777); demo.chmod(0o777)
  ENV['CATL_DEMO_OUTPUT']=str(demo/'output.txt')
  # cold start database disarmed, missing anchor before admin bootstrap
  from catl.crypto import get_or_create_key
  from catl.store import State
  st=State(state/'audit.sqlite3',get_or_create_key(state/'audit.key'))
  print('COLD_START_ARMED',st.controls()['gateway_enabled'])
  bootstrap=run('anchor-init','--state-dir',state,'--anchor-path',anchor,'--accept-current-verified-head')
  assert bootstrap.returncode==0,(bootstrap.stdout,bootstrap.stderr)
  cmd=[sys.executable,'-m','catl.cli','broker','--config',str(policy),'--state-dir',str(state),'--anchor-path',str(anchor),
       '--agent-socket',str(agent_sock),'--operator-socket',str(op_sock),'--agent-uid',str(AGENT),'--operator-uid',str(OPERATOR),
       '--backend-user','nobody','--pass-env','CATL_DEMO_OUTPUT','--',sys.executable,str(backend)]
  server=subprocess.Popen(cmd,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
  try:
    for i in range(500):
      if server.poll() is not None:raise RuntimeError('BROKER EXITED:'+server.communicate()[1])
      if agent_sock.exists() and op_sock.exists():break
      time.sleep(.01)
    assert agent_sock.exists() and op_sock.exists()
    op=run('operator','--operator-socket',op_sock,'status',uid=OPERATOR)
    assert op.returncode==0,(op.stdout,op.stderr)
    print('PROTECTED_OPERATOR_STATUS',json.loads(op.stdout)['controls']['gateway_enabled'])
    bad=run('operator','--operator-socket',op_sock,'status',uid=AGENT)
    print('AGENT_OPERATOR_DENIED',bad.returncode!=0)
    start=run('operator','--operator-socket',op_sock,'feature','gateway_enabled','on',uid=OPERATOR)
    assert start.returncode==0,(start.stdout,start.stderr)
    msg={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'echo_safe','arguments':{'message':'hello broker!'}}}
    response=run('shim','--agent-socket',agent_sock,uid=AGENT,input=json.dumps(msg)+'\n')
    assert response.returncode==0,(response.stdout,response.stderr)
    reply=json.loads(response.stdout)
    print('AGENT_ALLOWED_RESULT',reply)
    assert reply.get('result',{}).get('content',[{}])[0].get('text')=='hello broker!'
    msg['params']['name']='write_demo'
    restricted=run('shim','--agent-socket',agent_sock,uid=AGENT,input=json.dumps(msg)+'\n')
    assert restricted.returncode==0,(restricted.stdout,restricted.stderr)
    r=json.loads(restricted.stdout)
    print('SENSITIVE_BLOCKED',r['error']['message'])
    approval_id=r['error']['data']['approval_id']
    pending=run('operator','--operator-socket',op_sock,'pending',uid=OPERATOR)
    assert approval_id in pending.stdout
    # operator CLI requires an interactive TTY for consent; for automated test
    # verify private broker's distinct UID approve route through trusted socket.
    approval_script='''import json,socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall((json.dumps({"op":"decide","id":sys.argv[2],"approve":True})+"\\n").encode());print(s.recv(4000).decode());s.close()'''
    decision=subprocess.run([sys.executable,'-c',approval_script,str(op_sock),approval_id],preexec_fn=lambda:os.setuid(OPERATOR),capture_output=True,text=True,timeout=10)
    assert '"accepted":true' in decision.stdout,(decision.stdout,decision.stderr)
    approved=run('shim','--agent-socket',agent_sock,uid=AGENT,input=json.dumps(msg)+'\n')
    print('APPROVED_ONCE',approved.stdout, approved.stderr)
    assert 'result' in json.loads(approved.stdout)
    replay=run('shim','--agent-socket',agent_sock,uid=AGENT,input=json.dumps(msg)+'\n')
    assert json.loads(replay.stdout)['error']['message']=='human_approval_required'
    print('REPLAY_BLOCKED',True)
    audit=run('operator','--operator-socket',op_sock,'verify',uid=OPERATOR)
    print('ANCHORED_AUDIT',json.loads(audit.stdout))
    assert json.loads(audit.stdout)['valid']
  finally:
    try:os.killpg(server.pid,signal.SIGTERM)
    except ProcessLookupError:pass
    try:server.communicate(timeout=3)
    except subprocess.TimeoutExpired:
      os.killpg(server.pid,signal.SIGKILL);server.communicate()
