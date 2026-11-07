import os,sys,sqlite3,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from catl.remote_effects import RemoteEffectLedger,ExternalEffectUncertain
class FakeProvider:
 def __init__(self):self.saved={};self.reads=0;self.submits=0;self.mode='ok'
 def read_by_idempotency_key(self,key):
  self.reads+=1
  if self.mode=='read_timeout':raise TimeoutError()
  return self.saved.get(key)
 def submit(self,key,payload):
  self.submits+=1
  if self.mode=='submit_timeout':raise TimeoutError()
  if self.mode=='diverge':self.saved[key]={'wrong':True}
  elif self.mode!='missing':self.saved[key]=payload
class TestRemote(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.path=Path(self.tmp.name)/'ledger.db';self.ledger=RemoteEffectLedger(self.path,b'S'*32)
  self.id='a'*32;self.provider=FakeProvider();self.payload={'to':'test@example.invalid','message':'ok'}
 def execute(self):return self.ledger.execute_once(self.id,'email',self.payload,self.provider)
 def test_success_only_after_readback(self):
  self.assertEqual(self.execute().status,'confirmed');self.assertEqual(self.provider.submits,1);self.assertGreaterEqual(self.provider.reads,2)
 def test_no_duplicate_on_restart(self):
  self.execute();later=RemoteEffectLedger(self.path,b'S'*32)
  self.assertEqual(later.execute_once(self.id,'email',self.payload,self.provider).status,'confirmed');self.assertEqual(self.provider.submits,1)
 def test_failed_submit_quarantines(self):
  self.provider.mode='submit_timeout'
  with self.assertRaises(ExternalEffectUncertain):self.execute()
  self.provider.mode='ok'
  with self.assertRaisesRegex(ExternalEffectUncertain,'no_automatic_retry'):self.execute()
  self.assertEqual(self.provider.submits,1)
 def test_provider_readback_timeout_quarantines_without_send(self):
  self.provider.mode='read_timeout'
  with self.assertRaises(ExternalEffectUncertain):self.execute()
  self.assertEqual(self.provider.submits,0)
 def test_missing_readback_cannot_claim_success(self):
  self.provider.mode='missing'
  with self.assertRaisesRegex(ExternalEffectUncertain,'without_confirmed_readback'):self.execute()
 def test_divergence_is_quarantined(self):
  self.provider.mode='diverge'
  with self.assertRaisesRegex(ExternalEffectUncertain,'differs'):self.execute()
  with self.assertRaises(ExternalEffectUncertain):self.execute()
 def test_await_manual_readback(self):
  self.provider.mode='submit_timeout'
  with self.assertRaises(ExternalEffectUncertain):self.execute()
  self.provider.mode='ok'
  key=self.ledger._prepare(self.id,'email',self.payload).idempotency_key
  self.provider.saved[key]=self.payload
  self.assertEqual(self.ledger.reconcile_by_readback(self.id,'email',self.payload,self.provider).status,'confirmed')
  self.assertEqual(self.provider.submits,1)
 def test_no_manual_clear_if_absent(self):
  self.provider.mode='missing'
  with self.assertRaises(ExternalEffectUncertain):self.execute()
  with self.assertRaises(ExternalEffectUncertain):self.ledger.reconcile_by_readback(self.id,'email',self.payload,self.provider)
 def test_action_id_collision_denied(self):
  self.execute()
  with self.assertRaisesRegex(ExternalEffectUncertain,'reuse'):self.ledger.execute_once(self.id,'email',{'amount':100},self.provider)
 def test_tamper_status_fails_closed(self):
  self.execute()
  with sqlite3.connect(self.path) as db:db.execute("UPDATE effects SET status='planned'")
  with self.assertRaisesRegex(ExternalEffectUncertain,'tampered'):self.execute()
 def test_tamper_hash_fails_closed(self):
  self.execute()
  with sqlite3.connect(self.path) as db:db.execute("UPDATE effects SET expected_hash='00'")
  with self.assertRaisesRegex(ExternalEffectUncertain,'tampered'):self.execute()
 def test_world_writable_db_denied(self):
  self.path.chmod(0o666)
  with self.assertRaises(PermissionError):RemoteEffectLedger(self.path,b'S'*32)
 def test_service_id_required(self):
  with self.assertRaises(ValueError):self.ledger.execute_once('zzz','email',{},self.provider)
if __name__=='__main__':unittest.main()

class TestConcurrentRemote(unittest.TestCase):
 def test_only_one_submit_across_threads(self):
  from concurrent.futures import ThreadPoolExecutor
  with tempfile.TemporaryDirectory() as td:
   store=RemoteEffectLedger(Path(td)/'ledger.sqlite3',b'R'*32)
   p=FakeProvider();action='c'*32;value={'amount':500}
   with ThreadPoolExecutor(max_workers=16) as pool:
    statuses=list(pool.map(lambda _:store.execute_once(action,'payments',value,p).status,range(30)))
   self.assertEqual(statuses,['confirmed']*30)
   self.assertEqual(p.submits,1)
