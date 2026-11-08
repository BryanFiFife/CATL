"""Real TLS1.3, separate Linux UID, certificate pinning and durable witness proof.

Disposable local test CA, process and database. Not an independent off-host witness.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from catl.witness_protocol import WitnessClient, https_witness_transport, WitnessRejected


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
             serialization.PrivateFormat.PKCS8,serialization.NoEncryption())


def _generate_ca():
    now=dt.datetime.now(dt.timezone.utc)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'CATL disposable test CA')])
    crt=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(hours=1))
         .not_valid_after(now+dt.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),critical=False)
         .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,
             key_encipherment=False,data_encipherment=False,key_agreement=False,
             key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
         .sign(key,hashes.SHA256()))
    return key,crt


def _cert(ca_key,ca,key,cn,*,client=False):
    now=dt.datetime.now(dt.timezone.utc)
    builder=(x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)]))
        .issuer_name(ca.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(hours=1)).not_valid_after(now+dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,
            data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,
            encipher_only=False,decipher_only=False),critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]),critical=False))
    if not client:
        builder=builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
    return builder.sign(ca_key,hashes.SHA256())


@unittest.skipUnless(sys.platform=='linux' and hasattr(os,'geteuid') and os.geteuid()==0,
   'needs disposable root-capable Linux environment to start a separate non-root UID')
class RealMTLSKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='catl-mtls-',dir='/tmp')
        cls.root=Path(cls.tmp.name)
        cls.root.chmod(0o711)
        nobody=pwd.getpwnam('nobody')
        cls.uid=nobody.pw_uid;cls.gid=nobody.pw_gid
        cls.server_dir=cls.root/'witness';cls.server_dir.mkdir(mode=0o700)
        os.chown(cls.server_dir,cls.uid,cls.gid)
        cls.key=ed25519.Ed25519PrivateKey.generate()
        cls.signer=cls.server_dir/'sign.pem';cls.signer.write_bytes(_pem(cls.key))
        cls.ca_key,cls.ca=_generate_ca()
        cls.ca_path=cls.root/'testca.pem';cls.ca_path.write_bytes(cls.ca.public_bytes(serialization.Encoding.PEM))
        cls.ca_path.chmod(0o644)
        server_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        svr_cert=_cert(cls.ca_key,cls.ca,server_key,'localhost')
        cls.server_crt=cls.server_dir/'tls.crt';cls.server_crt.write_bytes(svr_cert.public_bytes(serialization.Encoding.PEM))
        cls.server_key=cls.server_dir/'tls.key';cls.server_key.write_bytes(_pem(server_key))
        client_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        client_cert=_cert(cls.ca_key,cls.ca,client_key,'signed-client',client=True)
        cls.client_crt=cls.root/'client.crt';cls.client_crt.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
        cls.client_key=cls.root/'client.key';cls.client_key.write_bytes(_pem(client_key))
        cls.cert_pin=hashlib.sha256(client_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        cls.stranger_key=cls.root/'stranger.key'
        key2=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.stranger_key.write_bytes(_pem(key2))
        cls.stranger_crt=cls.root/'stranger.crt'
        cls.stranger_crt.write_bytes(_cert(cls.ca_key,cls.ca,key2,'stranger',client=True).public_bytes(serialization.Encoding.PEM))
        for p in (cls.signer,cls.server_crt,cls.server_key):
            os.chown(p,cls.uid,cls.gid);p.chmod(0o600)
        cls.db=cls.server_dir/'heads.db'
        cls.ctx=ssl.create_default_context(cafile=str(cls.ca_path))
        cls.ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        cls.ctx.load_cert_chain(str(cls.client_crt),str(cls.client_key))
        cls.server=None
        cls.start()

    @classmethod
    def tearDownClass(cls):
        cls.stop()
        cls.tmp.cleanup()

    @classmethod
    def stop(cls):
        if cls.server is not None:
            cls.server.terminate()
            try:cls.server.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                cls.server.kill();cls.server.communicate(timeout=3)
            cls.server=None

    @classmethod
    def start(cls,*,allowed='127.0.0.1'):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1',0));cls.port=s.getsockname()[1]
        cmd=[sys.executable,str(ROOT/'tools/witness_service.py'), '--database',str(cls.db),
             '--signing-key',str(cls.signer), '--tls-cert',str(cls.server_crt),
             '--tls-key',str(cls.server_key),'--client-ca',str(cls.ca_path),
             '--client-cert-sha256',cls.cert_pin,'--allow-client-ip',allowed,
             '--listen','127.0.0.1','--port',str(cls.port)]
        cls.server=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,user=cls.uid,group=cls.gid,extra_groups=[],
            cwd=str(cls.server_dir),env={'PATH':'/usr/bin:/bin','PYTHONUNBUFFERED':'1','PYTHONDONTWRITEBYTECODE':'1'})
        for _ in range(100):
            if cls.server.poll() is not None:
                stdout,err=cls.server.communicate(timeout=1)
                raise AssertionError('witness server startup failed: '+err.decode(errors='replace'))
            try:
                with socket.create_connection(('127.0.0.1',cls.port),timeout=.1):break
            except OSError:time.sleep(.03)
        else:raise AssertionError('witness did not bind')
        cls.transport=https_witness_transport(f'https://localhost:{cls.port}/v1/witness',ssl_context=cls.ctx,timeout=4)
        cls.client=WitnessClient(cls.key.public_key(),cls.transport)

    def _raw_tls(self,body):
        with socket.create_connection(('127.0.0.1',self.port),timeout=3) as client:
            with self.ctx.wrap_socket(client,server_hostname='localhost') as secure:
                self.assertEqual(secure.version(),'TLSv1.3')
                secure.sendall(body)
                return secure.recv(4096)

    def test_01_signed_progress_and_refusal_of_rollback_after_restart(self):
        head={'ledger_id':'mtls-test-ledger','sequence':0,'head_mac':'GENESIS'}
        self.assertEqual(self.client.witness(head).sequence,0)
        newer={'ledger_id':'mtls-test-ledger','sequence':1,'head_mac':'e'*64}
        self.assertEqual(self.client.witness(newer).sequence,1)
        self.stop();self.start()
        with self.assertRaises(HTTPError):self.client.witness(head)
        with self.assertRaises(HTTPError):self.client.witness({**newer,'head_mac':'f'*64})
        self.assertEqual(self.client.witness(newer).sequence,1)

    def test_02_wrong_client_cert_from_trusted_ca_refused(self):
        ctx=ssl.create_default_context(cafile=str(self.ca_path));ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(str(self.stranger_crt),str(self.stranger_key))
        wrong=https_witness_transport(f'https://localhost:{self.port}/v1/witness',ssl_context=ctx,timeout=3)
        with self.assertRaises(HTTPError) as e:
            wrong({'ledger_id':'other-ledger-123','sequence':0,'head_mac':'GENESIS'})
        self.assertEqual(e.exception.code,403)

    def test_03_missing_client_certificate_refused(self):
        ctx=ssl.create_default_context(cafile=str(self.ca_path));ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        wrong=https_witness_transport(f'https://localhost:{self.port}/v1/witness',ssl_context=ctx,timeout=3)
        with self.assertRaises((OSError,ssl.SSLError,ConnectionError,WitnessRejected)):
            wrong({'ledger_id':'no-cert-ledger','sequence':0,'head_mac':'GENESIS'})

    def test_04_duplicate_content_type_rejected_on_wire(self):
        payload=json.dumps({'ledger_id':'dup-type-ledger','sequence':0,'head_mac':'GENESIS'}).encode()
        response=self._raw_tls(b'POST /v1/witness HTTP/1.1\r\nHost: localhost\r\n'
            b'Content-Type: application/json\r\nContent-Type: application/json\r\n'
            +f'Content-Length: {len(payload)}\r\n\r\n'.encode()+payload)
        self.assertIn(b'400',response.split(b'\r\n',1)[0])

    def test_05_chunked_transfer_refused_on_wire(self):
        response=self._raw_tls(b'POST /v1/witness HTTP/1.1\r\nHost: localhost\r\n'
                 b'Content-Type: application/json\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}')
        self.assertIn(b'400',response.split(b'\r\n',1)[0])

    def test_06_plain_idle_tcp_does_not_starve_accept_loop(self):
        with socket.create_connection(('127.0.0.1',self.port),timeout=2):
            self.assertEqual(self.client.witness({'ledger_id':'idle-block-ledger','sequence':0,
                                                 'head_mac':'GENESIS'}).sequence,0)

    def test_07_wrong_hostname_refused(self):
        transport=https_witness_transport(f'https://127.0.0.1:{self.port}/v1/witness',ssl_context=self.ctx,timeout=3)
        with self.assertRaises((OSError,ssl.SSLError)):
            transport({'ledger_id':'wrong-host-ledger','sequence':0,'head_mac':'GENESIS'})

    def test_08_disallowed_ip_rejected_before_tls(self):
        self.stop();self.start(allowed='127.0.0.2')
        try:
            with self.assertRaises((OSError,ssl.SSLError,ConnectionError,WitnessRejected)):
                self.client.witness({'ledger_id':'ip-rejected-ledger','sequence':0,'head_mac':'GENESIS'})
        finally:
            self.stop();self.start()
        self.assertEqual(self.client.witness({'ledger_id':'recovery-ledger','sequence':0,'head_mac':'GENESIS'}).sequence,0)


if __name__=='__main__':unittest.main()
