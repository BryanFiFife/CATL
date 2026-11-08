#!/usr/bin/env python3
"""Disposable Linux *kernel* isolation matrix, not CATL application acceptance.
Does not create user accounts, write permanent configs, or open network ports.
"""
import grp, json, os, pwd, signal, socket, subprocess, sys, tempfile, time
from pathlib import Path

UID = {'broker':26101,'agent':26102,'operator':26103,'backend':26104}
GID = {'agent':26202,'operator':26203,'backend':26204}
BASE_ENV={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1',
          'PYTHONNOUSERSITE':'1','PYTHONSAFEPATH':'1'}
SERVER=r'''import json,os,selectors,socket,struct,sys,time
root=sys.argv[1]; endpoints=[('agent',26202,26102),('operator',26203,26103)]; fds={}
for name,gid,uid in endpoints:
 path=root+'/'+name+'/endpoint.sock'
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(path)
 os.chown(path,-1,gid);os.chmod(path,0o660);s.listen(8);s.setblocking(False)
 fds[s.fileno()]=(s,name,uid)
sel=selectors.DefaultSelector()
for s,name,uid in fds.values():sel.register(s,selectors.EVENT_READ)
print('READY',flush=True)
end=time.monotonic()+12
while time.monotonic()<end:
 for key,_ in sel.select(.2):
  s,name,uid=fds[key.fileobj.fileno()];conn,_=s.accept()
  with conn:
   cred=conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i'))
   _pid,actual,gid=struct.unpack('3i',cred)
   conn.sendall(json.dumps({'allowed':actual==uid,'uid':actual,'endpoint':name}).encode()+b'\n')
'''
CLIENT=r'''import json,os,socket,sys
try:
 s=socket.socket(socket.AF_UNIX);s.settimeout(2);s.connect(sys.argv[1]);
 data=s.recv(512);print(json.dumps({'connected':True,'reply':json.loads(data)}))
except (OSError,ValueError) as e:print(json.dumps({'connected':False,'error_type':type(e).__name__}))
'''
KEY_READ=r'''import pathlib,sys
try:
 pathlib.Path(sys.argv[1]).read_bytes();print('READ_ALLOWED')
except PermissionError: print('READ_DENIED')
'''

def command(uid,groups,code,args):
    return ['/usr/bin/setpriv',f'--reuid={uid}',f'--regid={uid}',
            f'--groups={",".join(map(str,groups)) or "0"}',sys.executable,'-c',code,*map(str,args)]

def main():
    if not __debug__:
        raise RuntimeError('kernel_identity_matrix_assertions_disabled')
    if sys.platform!='linux' or os.geteuid()!=0 or not Path('/usr/bin/setpriv').is_file():
        return {'status':'SKIP','reason':'requires disposable Linux root container'}
    if os.environ.get('CATL_DISPOSABLE_LINUX_TEST_HOST') != 'YES':
        return {'status':'NO_GO','reason':'explicit_disposable_host_acknowledgement_required'}
    for uid in UID.values():
        try: pwd.getpwuid(uid)
        except KeyError: pass
        else: return {'status':'NO_GO','reason':'synthetic_uid_collides_with_existing_user'}
    for gid in GID.values():
        try: grp.getgrgid(gid)
        except KeyError: pass
        else: return {'status':'NO_GO','reason':'synthetic_gid_collides_with_existing_group'}
    with tempfile.TemporaryDirectory(prefix='catl-uid-matrix-') as tmp:
        root=Path(tmp);root.chmod(0o711)
        for name in ('agent','operator'):
            p=root/name;p.mkdir(mode=0o700);os.chown(p,UID['broker'],GID[name]);p.chmod(0o710)
        protected=root/'state';protected.mkdir(mode=0o700)
        os.chown(protected,UID['broker'],UID['broker'])
        key=protected/'audit.key';key.write_text('fake-key-only');os.chown(key,UID['broker'],UID['broker']);key.chmod(0o600)
        env={**BASE_ENV}
        proc=subprocess.Popen(command(UID['broker'],[GID['agent'],GID['operator']],SERVER,[root]),
                              env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              text=True,start_new_session=True)
        cases=[]
        try:
            import select
            if proc.stdout is None or not select.select([proc.stdout], [], [], 4)[0]:
                raise RuntimeError('UID broker fixture readiness timed out')
            if proc.stdout.readline().strip()!='READY':
                raise RuntimeError('UID broker fixture did not start')
            for actor,ep,want in [
                ('agent','agent',True),('operator','operator',True),
                ('agent','operator',False),('operator','agent',False),
                ('backend','agent',False),('backend','operator',False)]:
                groups=[GID[actor]]
                r=subprocess.run(command(UID[actor],groups,CLIENT,[root/ep/'endpoint.sock']),
                                 env=env,capture_output=True,text=True,timeout=4)
                reply=json.loads(r.stdout)
                passed=(r.returncode==0 and (reply.get('connected',False)==want)
                        and (not want or (reply['reply']['allowed'] and reply['reply']['uid']==UID[actor])))
                cases.append({'case':f'{actor}_to_{ep}','passed':passed,'connected':reply.get('connected',False)})
            for actor in ('broker','agent','operator','backend'):
                groups=[GID[x] for x in GID] if actor=='broker' else [GID[actor]]
                r=subprocess.run(command(UID[actor],groups,KEY_READ,[key]),env=env,
                                 capture_output=True,text=True,timeout=4)
                want='READ_ALLOWED' if actor=='broker' else 'READ_DENIED'
                cases.append({'case':f'{actor}_read_broker_key','passed':r.returncode==0 and r.stdout.strip()==want})
            # Run a child under the agent UID and prove parent secrets cannot cross.
            was_set='CATL_E2E_CANARY' in os.environ
            previous=os.environ.get('CATL_E2E_CANARY')
            try:
                os.environ['CATL_E2E_CANARY']='private-parent-secret'
                child=subprocess.run(command(UID['agent'],[GID['agent']],
                                      'import os;print(os.getenv("CATL_E2E_CANARY","NO_PARENT_SECRET"))',[]),
                                      env=env,capture_output=True,text=True,timeout=4)
            finally:
                if was_set:os.environ['CATL_E2E_CANARY']=previous
                else:os.environ.pop('CATL_E2E_CANARY',None)
            cases.append({'case':'agent_environment_canary_not_inherited',
                          'passed':child.returncode==0 and child.stdout.strip()=='NO_PARENT_SECRET'})
            return {'status':'PASS' if all(x['passed'] for x in cases) else 'FAIL',
                    'scope':'kernel_4_uid_socket_acl_peer_credential_and_key_access_fixture_not_CATL_E2E',
                    'cases':cases}
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid,signal.SIGTERM)
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=2)
            if proc.stdout:proc.stdout.close()
            if proc.stderr:proc.stderr.close()

if __name__=='__main__':
    report=main();print(json.dumps(report,indent=2));sys.exit(0 if report['status']=='PASS' else 1)
