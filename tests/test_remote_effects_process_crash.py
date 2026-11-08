"""Cross-process crash/restart checks for a simulated provider.

Never uses a real email/payment provider. Uses OS process death and real SQLite
file locks, not thread mocks. Production provider read-back remains a gate.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from catl.remote_effects import RemoteEffectLedger, ExternalEffectUncertain

ROOT=Path(__file__).resolve().parents[1]
KEY=b'T'*32
AID='1'*32
PAYLOAD={'amount':57,'currency':'GBP','recipient':'test@example.invalid'}

class SharedProvider:
    def __init__(self,root):
        self.root=Path(root)
        self.sends=self.root/'send-count.log'
        self.payload=self.root/'provider.json'
    def read_by_idempotency_key(self,key):
        if not self.payload.exists():return None
        val=json.loads(self.payload.read_text())
        if val.get('key') !=key:return None
        return val['payload']
    def submit(self,key,payload):
        with self.sends.open('a') as f:f.write('1\n');f.flush();os.fsync(f.fileno())
        intermediate=self.root/'provider.tmp'
        intermediate.write_text(json.dumps({'key':key,'payload':payload}))
        os.replace(intermediate,self.payload)

@unittest.skipUnless(sys.platform=='linux', 'uses Linux process termination')
class RemoteCrashRestartTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='catl-remote-process-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.db=self.root/'effects.sqlite3'
        self.ledger=RemoteEffectLedger(self.db,KEY)
        self.provider=SharedProvider(self.root)
    def child(self,phase):
        script='''\
import os, sys, json
from pathlib import Path
from catl.remote_effects import RemoteEffectLedger
root=Path(sys.argv[1]); mode=sys.argv[2]
ledger=RemoteEffectLedger(root/'effects.sqlite3',b'T'*32)
payload={'amount':57,'currency':'GBP','recipient':'test@example.invalid'}
class Provider:
 def read_by_idempotency_key(self,key):
  p=root/'provider.json'
  if not p.exists():return None
  v=json.loads(p.read_text())
  return v['payload'] if v['key']==key else None
 def submit(self,key,payload):
  if mode=='pre_submit':os._exit(79)
  f=(root/'send-count.log').open('a');f.write('1\\n');f.flush();os.fsync(f.fileno());f.close()
  p=root/'provider.tmp';p.write_text(json.dumps({'key':key,'payload':payload}));p.replace(root/'provider.json')
  if mode=='post_submit':os._exit(80)
ledger.execute_once('1'*32,'payments',payload,Provider())
'''
        return subprocess.run([sys.executable,'-c',script,str(self.root),phase],
            env={'PYTHONPATH':str(ROOT/'src'),'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},
            capture_output=True,timeout=8)
    def test_killed_before_send_must_not_auto_retry(self):
        c=self.child('pre_submit')
        self.assertEqual(c.returncode,79,c.stderr)
        self.assertFalse(self.provider.sends.exists())
        with self.assertRaisesRegex(ExternalEffectUncertain,'no_automatic_retry'):
            RemoteEffectLedger(self.db,KEY).execute_once(AID,'payments',PAYLOAD,self.provider)
        with self.assertRaisesRegex(ExternalEffectUncertain,'operator_review_required'):
            RemoteEffectLedger(self.db,KEY).reconcile_by_readback(AID,'payments',PAYLOAD,self.provider)
        self.assertFalse(self.provider.sends.exists())
    def test_killed_after_send_needs_authoritative_readback(self):
        c=self.child('post_submit')
        self.assertEqual(c.returncode,80,c.stderr)
        self.assertEqual(self.provider.sends.read_text().splitlines(),['1'])
        with self.assertRaises(ExternalEffectUncertain):
            RemoteEffectLedger(self.db,KEY).execute_once(AID,'payments',PAYLOAD,self.provider)
        result=RemoteEffectLedger(self.db,KEY).reconcile_by_readback(AID,'payments',PAYLOAD,self.provider)
        self.assertEqual(result.status,'confirmed')
        self.assertEqual(self.provider.sends.read_text().splitlines(),['1'])
    def test_two_independent_processes_same_action_submit_once(self):
        # Two distinct processes acquire the same durable fcntl lock.
        with subprocess.Popen([sys.executable,'-c',self._concurrent_script(),str(self.root)],
             env={'PYTHONPATH':str(ROOT/'src'),'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},stdout=subprocess.PIPE,stderr=subprocess.PIPE) as a:
            with subprocess.Popen([sys.executable,'-c',self._concurrent_script(),str(self.root)],
                 env={'PYTHONPATH':str(ROOT/'src'),'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},stdout=subprocess.PIPE,stderr=subprocess.PIPE) as b:
                ea=a.communicate(timeout=8)[1];eb=b.communicate(timeout=8)[1]
                self.assertEqual((a.returncode,b.returncode),(0,0),(ea,eb))
        self.assertEqual(self.provider.sends.read_text().splitlines(),['1'])
    @staticmethod
    def _concurrent_script():
        return '''\
import os,sys,json,time
from pathlib import Path
from catl.remote_effects import RemoteEffectLedger
root=Path(sys.argv[1]); l=RemoteEffectLedger(root/'effects.sqlite3',b'T'*32)
payload={'amount':57,'currency':'GBP','recipient':'test@example.invalid'}
class Provider:
 def read_by_idempotency_key(self,key):
  f=root/'provider.json'
  if not f.exists():return None
  data=json.loads(f.read_text())
  return data['payload'] if data['key']==key else None
 def submit(self,key,payload):
  with (root/'send-count.log').open('a') as f: f.write('1\\n'); f.flush(); os.fsync(f.fileno())
  tmp=root/'provider.tmp';tmp.write_text(json.dumps({'key':key,'payload':payload}));tmp.replace(root/'provider.json')
  time.sleep(0.1)
l.execute_once('1'*32,'payments',payload,Provider())
'''
