import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from catl.witness_protocol import InMemoryWitnessLog,WitnessClient,WitnessRejected,witness_sign_head,verify_witness
class TestWitness(unittest.TestCase):
 def setUp(self):
  self.private=Ed25519PrivateKey.generate();self.public=self.private.public_key();self.log=InMemoryWitnessLog(self.private)
  self.head={'ledger_id':'caledapt-fixture','sequence':2,'head_mac':'f'*64}
  self.client=WitnessClient(self.public,self.log.receive)
 def test_signed_receipt(self):self.assertEqual(self.client.witness(self.head).sequence,2)
 def test_reconfirm_same(self):self.client.witness(self.head);self.assertEqual(self.client.witness(self.head).sequence,2)
 def test_new_sequence(self):
  self.client.witness(self.head)
  self.assertEqual(self.client.witness({**self.head,'sequence':3,'head_mac':'a'*64}).sequence,3)
 def test_rollback_refused(self):
  self.client.witness(self.head)
  with self.assertRaisesRegex(WitnessRejected,'rollback'):self.client.witness({**self.head,'sequence':1})
 def test_fork_refused(self):
  self.client.witness(self.head)
  with self.assertRaisesRegex(WitnessRejected,'fork'):self.client.witness({**self.head,'head_mac':'e'*64})
 def test_forged_head_refused(self):
  receipt=self.log.receive(self.head)
  with self.assertRaisesRegex(WitnessRejected,'mismatch'):verify_witness(self.public,receipt,expected={**self.head,'sequence':3})
 def test_forged_signature_refused(self):
  receipt=witness_sign_head(self.private,self.head);receipt['signature']='00'*64
  with self.assertRaisesRegex(WitnessRejected,'signature'):verify_witness(self.public,receipt,expected=self.head)
 def test_wrong_public_key_refused(self):
  receipt=witness_sign_head(self.private,self.head)
  with self.assertRaisesRegex(WitnessRejected,'signature'):verify_witness(Ed25519PrivateKey.generate().public_key(),receipt,expected=self.head)
 def test_bad_head_refused(self):
  with self.assertRaises(WitnessRejected):self.client.witness({**self.head,'head_mac':'../x'})
if __name__=='__main__':unittest.main()

class TestDurableWitness(unittest.TestCase):
 def test_restart_and_fork(self):
  import tempfile
  from catl.witness_protocol import DurableWitnessLog
  with tempfile.TemporaryDirectory() as root:
   key=Ed25519PrivateKey.generate();p=Path(root)/'heads.sqlite3'
   service=DurableWitnessLog(p,key);head={'ledger_id':'ledger-123','sequence':1,'head_mac':'a'*64}
   receipt=service.receive(head)
   verify_witness(key.public_key(),receipt,expected=head)
   restarted=DurableWitnessLog(p,key)
   with self.assertRaisesRegex(WitnessRejected,'rollback'):restarted.receive({**head,'sequence':0,'head_mac':'GENESIS'})
   with self.assertRaisesRegex(WitnessRejected,'fork'):restarted.receive({**head,'head_mac':'b'*64})
   self.assertEqual(restarted.receive(head)['sequence'],1)
 def test_invalid_url_scheme(self):
  from catl.witness_protocol import https_witness_transport
  with self.assertRaises(WitnessRejected):https_witness_transport('http://local/submit',ssl_context=object())

class TestWitnessIntegration(unittest.TestCase):
 def test_state_witness_requires_anchor(self):
  from catl.witness_protocol import witness_catl_state
  class FakeState:
   def verify(self):return {'valid':True,'externally_anchored':False,'count':1,'head_mac':'a'*64}
  key=Ed25519PrivateKey.generate()
  with self.assertRaises(WitnessRejected):witness_catl_state(FakeState(),'ledger-123',WitnessClient(key.public_key(),InMemoryWitnessLog(key).receive))
 def test_state_witness_verified(self):
  from catl.witness_protocol import witness_catl_state
  class FakeState:
   def verify(self):return {'valid':True,'externally_anchored':True,'count':12,'head_mac':'a'*64}
  key=Ed25519PrivateKey.generate()
  self.assertEqual(witness_catl_state(FakeState(),'ledger-123',WitnessClient(key.public_key(),InMemoryWitnessLog(key).receive)).sequence,12)
 def test_tls_client_fail_closed(self):
  from catl.witness_protocol import https_witness_transport
  import ssl
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
  with self.assertRaisesRegex(WitnessRejected,'tls'):https_witness_transport('https://example.com/v1/witness',ssl_context=ctx)
 def test_tls_scheme_denied(self):
  from catl.witness_protocol import https_witness_transport
  import ssl
  with self.assertRaises(WitnessRejected):https_witness_transport('http://local/submit',ssl_context=ssl.create_default_context())
