import base64,hashlib,json,os,sys,unittest
from dataclasses import replace
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes,serialization
from catl.hardware_presence import Credential,PresenceRejected,verify_assertion

class TestPresence(unittest.TestCase):
 def setUp(self):
  self.key=ec.generate_private_key(ec.SECP256R1());self.challenge=b'X'*32
  self.cred=Credential('credentials','', 'caledapt.example','https://caledapt.example',0)
  self.cred=replace(self.cred,public_key_pem=self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
 def b(self,data):return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
 def make(self,flags=5,count=1,origin='https://caledapt.example',challenge=None):
  c={'type':'webauthn.get','challenge':self.b(challenge if challenge is not None else self.challenge),'origin':origin,'crossOrigin':False}
  client=json.dumps(c,separators=(',',':')).encode()
  auth=hashlib.sha256(self.cred.rp_id.encode()).digest()+bytes([flags])+count.to_bytes(4,'big')
  signature=self.key.sign(auth+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
  return {'credential_id':self.cred.credential_id,'client_data_json':self.b(client), 'authenticator_data':self.b(auth),'signature':self.b(signature)}
 def test_valid_presence(self):self.assertEqual(verify_assertion(self.cred,self.make(),challenge=self.challenge),1)
 def test_no_up(self):
  with self.assertRaisesRegex(PresenceRejected,'presence'):verify_assertion(self.cred,self.make(flags=4),challenge=self.challenge)
 def test_no_uv(self):
  with self.assertRaisesRegex(PresenceRejected,'presence'):verify_assertion(self.cred,self.make(flags=1),challenge=self.challenge)
 def test_origin_forgery(self):
  with self.assertRaisesRegex(PresenceRejected,'origin'):verify_assertion(self.cred,self.make(origin='https://evil.test'),challenge=self.challenge)
 def test_wrong_challenge(self):
  with self.assertRaisesRegex(PresenceRejected,'challenge'):verify_assertion(self.cred,self.make(challenge=b'Y'*32),challenge=self.challenge)
 def test_counter_replay(self):
  with self.assertRaisesRegex(PresenceRejected,'counter'):verify_assertion(replace(self.cred,sign_count=2),self.make(count=2),challenge=self.challenge)
 def test_wrong_credential(self):
  a=self.make();a['credential_id']='other'
  with self.assertRaisesRegex(PresenceRejected,'credential'):verify_assertion(self.cred,a,challenge=self.challenge)
 def test_wrong_rpid(self):
  with self.assertRaisesRegex(PresenceRejected,'rp_id'):verify_assertion(replace(self.cred,rp_id='evil.test'),self.make(),challenge=self.challenge)
 def test_signature_tampering(self):
  a=self.make();a['signature']=self.b(b'a'*64)
  with self.assertRaisesRegex(PresenceRejected,'signature'):verify_assertion(self.cred,a,challenge=self.challenge)
 def test_backup_flag_invalid(self):
  with self.assertRaisesRegex(PresenceRejected,'backup'):verify_assertion(self.cred,self.make(flags=5|16),challenge=self.challenge)
 def test_noncanonical_b64(self):
  a=self.make();a['signature']+='='
  with self.assertRaisesRegex(PresenceRejected,'base64'):verify_assertion(self.cred,a,challenge=self.challenge)
 def test_zero_counter_compatible(self):self.assertEqual(verify_assertion(self.cred,self.make(count=0),challenge=self.challenge),0)
 def test_extensions_rejected(self):
  with self.assertRaisesRegex(PresenceRejected,'flags'):verify_assertion(self.cred,self.make(flags=5|128),challenge=self.challenge)
if __name__=='__main__': unittest.main()

class TestPresenceHardening(TestPresence):
 def test_attested_data_flag_not_silently_accepted(self):
  with self.assertRaisesRegex(PresenceRejected,'flags'):
   verify_assertion(self.cred,self.make(flags=5|0x40),challenge=self.challenge)
 def test_short_challenge(self):
  with self.assertRaisesRegex(PresenceRejected,'challenge'):
   verify_assertion(self.cred,self.make(),challenge=b'X'*8)
 def test_malformed_client_data_b64(self):
  a=self.make();a['client_data_json']='?'*8
  with self.assertRaisesRegex(PresenceRejected,'base64'):
   verify_assertion(self.cred,a,challenge=self.challenge)
