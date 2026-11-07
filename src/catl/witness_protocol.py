"""Remote signed head-witness protocol for CATL receipt ledger.

A separate trusted host and pinned witness public key are REQUIRED for security.
Local fixture signatures or two processes on the same host do not stop a
privileged attacker controlling both the ledger and signing key.
"""
from __future__ import annotations
import hashlib
import json
import re
import hmac
from dataclasses import dataclass
from typing import Any, Callable
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class WitnessRejected(PermissionError):
    pass


def _canon(data: dict[str, Any]) -> bytes:
    if not isinstance(data,dict):
        raise WitnessRejected("witness_data_not_object")
    try:
        raw=json.dumps(data,sort_keys=True,allow_nan=False,separators=(',',':')).encode()
    except (ValueError,TypeError) as exc:
        raise WitnessRejected('witness_data_invalid') from exc
    if len(raw)>4096:raise WitnessRejected('witness_data_too_large')
    return raw


def _head(head: dict[str, Any]) -> None:
    if not isinstance(head,dict) or set(head)!={'ledger_id','sequence','head_mac'}:
        raise WitnessRejected('head_shape_invalid')
    if (not isinstance(head['ledger_id'],str) or not re.fullmatch('[a-zA-Z0-9._-]{6,64}',head['ledger_id'])
            or type(head['sequence']) is not int or not 0 <= head['sequence'] <= 2**63-1
            or not isinstance(head['head_mac'],str)
            or not (head['head_mac']=='GENESIS' or re.fullmatch('[0-9a-f]{64}',head['head_mac']))):
        raise WitnessRejected('head_fields_invalid')


@dataclass(frozen=True)
class WitnessReceipt:
    ledger_id: str
    sequence: int
    head_mac: str
    signature: str


def witness_sign_head(private_key: Ed25519PrivateKey,head:dict[str,Any])->dict[str,Any]:
    """Server primitive; only run on a truly independent witness host."""
    _head(head)
    body=dict(head)
    signature=private_key.sign(b'CATL/WITNESS/v1\0'+_canon(body)).hex()
    return {**body,'signature':signature,'scheme':'Ed25519/CATL-WITNESS-v1'}


def verify_witness(public_key: Ed25519PublicKey,receipt: dict[str, Any],
                   *, expected: dict[str, Any]) -> WitnessReceipt:
    _head(expected)
    if not isinstance(receipt,dict) or set(receipt)!={'ledger_id','sequence','head_mac','signature','scheme'}:
        raise WitnessRejected('witness_receipt_shape_invalid')
    if receipt['scheme']!='Ed25519/CATL-WITNESS-v1':
        raise WitnessRejected('witness_scheme_invalid')
    actual={k:receipt[k] for k in ('ledger_id','sequence','head_mac')}
    _head(actual)
    if actual!=expected:
        raise WitnessRejected('witness_head_mismatch')
    signature=receipt['signature']
    if not isinstance(signature,str) or not re.fullmatch('[0-9a-f]{128}',signature):
        raise WitnessRejected('witness_signature_invalid')
    try:
        public_key.verify(bytes.fromhex(signature),b'CATL/WITNESS/v1\0'+_canon(actual))
    except InvalidSignature as exc:
        raise WitnessRejected('witness_signature_invalid') from exc
    return WitnessReceipt(actual['ledger_id'],actual['sequence'],actual['head_mac'],signature)


class InMemoryWitnessLog:
    """Deterministic append-or-reconfirm witness fixture; NOT an off-host service.

    A production service must durably persist sequence+head under transactional
    lock, separate keys, TLS and independent operator control.
    """
    def __init__(self, private_key:Ed25519PrivateKey):
        self.private_key=private_key
        self.heads:dict[str,dict[str,Any]]={}
    def receive(self,head:dict[str,Any]) -> dict[str,Any]:
        _head(head)
        prior=self.heads.get(head['ledger_id'])
        if prior is not None:
            if head['sequence']<prior['sequence']:
                raise WitnessRejected('witness_head_rollback')
            if head['sequence']==prior['sequence'] and head['head_mac']!=prior['head_mac']:
                raise WitnessRejected('witness_head_fork')
            if head['sequence']==prior['sequence']:
                return witness_sign_head(self.private_key,head)
        self.heads[head['ledger_id']]=dict(head)
        return witness_sign_head(self.private_key,head)


class WitnessClient:
    def __init__(self,public_key:Ed25519PublicKey,
                 transport:Callable[[dict[str,Any]],dict[str,Any]]):
        self.public_key=public_key
        self.transport=transport
    def witness(self,head:dict[str,Any]) -> WitnessReceipt:
        _head(head)
        response=self.transport(dict(head))
        return verify_witness(self.public_key,response,expected=head)


class DurableWitnessLog:
    """Durable independent witness signer, for deployment on a SEPARATE machine.

    The signing key never belongs on the CATL broker host. Database and key
    ownership/counterrollback protection require a separately managed host.
    """
    def __init__(self, path,private_key: Ed25519PrivateKey):
        import os,stat,sqlite3
        from pathlib import Path
        self.path=Path(path)
        if os.name!='posix':raise WitnessRejected('durable_witness_requires_posix')
        parent=self.path.parent
        st=parent.stat()
        if parent.is_symlink() or st.st_uid!=os.geteuid() or st.st_mode & 0o077:
            raise WitnessRejected('witness_db_directory_untrusted')
        if not self.path.exists():
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
            os.close(fd)
        info=self.path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o077 or info.st_nlink!=1:
            raise WitnessRejected('witness_db_permissions_invalid')
        self.private_key=private_key
        self.lock_path=self.path.with_name(self.path.name+'.lock')
        with sqlite3.connect(self.path) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE IF NOT EXISTS witnesses ('
                       'ledger_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, head_mac TEXT NOT NULL)')
    def receive(self,head:dict[str,Any])->dict[str,Any]:
        import os,stat,sqlite3,fcntl
        _head(head)
        fd=os.open(self.lock_path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o077:
                raise WitnessRejected('witness_lock_file_untrusted')
            fcntl.flock(fd,fcntl.LOCK_EX)
            with sqlite3.connect(self.path,isolation_level=None,timeout=10) as db:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('BEGIN IMMEDIATE')
                prior=db.execute('SELECT sequence,head_mac FROM witnesses WHERE ledger_id=?',
                                 (head['ledger_id'],)).fetchone()
                if prior:
                    if head['sequence']<prior[0]:raise WitnessRejected('witness_head_rollback')
                    if head['sequence']==prior[0] and head['head_mac']!=prior[1]:
                        raise WitnessRejected('witness_head_fork')
                db.execute('INSERT INTO witnesses(ledger_id,sequence,head_mac) VALUES(?,?,?) '
                           'ON CONFLICT(ledger_id) DO UPDATE SET sequence=excluded.sequence,head_mac=excluded.head_mac',
                           (head['ledger_id'],head['sequence'],head['head_mac']))
                db.commit()
            return witness_sign_head(self.private_key,head)
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN)
            os.close(fd)


def https_witness_transport(url:str, *, ssl_context, timeout:float=5.0):
    """Explicit HTTPS endpoint; redirect and non-JSON responses refused.

    ssl_context MUST authenticate the independent server by a trusted CA or
    pin. Deploy with mutual TLS / client auth or equivalent access controls.
    """
    from urllib.parse import urlsplit
    from urllib.request import Request,build_opener,HTTPSHandler,HTTPRedirectHandler,ProxyHandler
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):
            raise WitnessRejected('witness_redirect_denied')
    import ssl
    if not isinstance(ssl_context,ssl.SSLContext) or not ssl_context.check_hostname or ssl_context.verify_mode!=ssl.CERT_REQUIRED:
        raise WitnessRejected('witness_tls_peer_verification_required')
    parsed=urlsplit(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise WitnessRejected('witness_url_must_be_https')
    if not (0<timeout<=20):raise WitnessRejected('witness_timeout_invalid')
    # Inherited HTTPS_PROXY/HTTP_PROXY is not trusted broker configuration.
    # Use direct TLS to the explicitly configured witness endpoint.
    opener=build_opener(ProxyHandler({}),HTTPSHandler(context=ssl_context),NoRedirect())
    def submit(head:dict[str,Any])->dict[str,Any]:
        _head(head)
        req=Request(url,data=_canon(head),headers={'Content-Type':'application/json','Accept':'application/json'},method='POST')
        with opener.open(req,timeout=timeout) as response:
            if response.status!=200 or not response.headers.get('Content-Type','').lower().startswith('application/json'):
                raise WitnessRejected('witness_response_type_invalid')
            raw=response.read(4097)
            if len(raw)>4096:raise WitnessRejected('witness_response_oversized')
        try:
            return json.loads(raw,object_pairs_hook=_unique_pairs)
        except (ValueError,UnicodeError) as exc:
            raise WitnessRejected('witness_response_invalid_json') from exc
    return submit


def _unique_pairs(pairs):
    doc={}
    for key,value in pairs:
        if key in doc:raise WitnessRejected('witness_response_duplicate_key')
        doc[key]=value
    return doc


def witness_catl_state(state, ledger_id: str, client: WitnessClient) -> WitnessReceipt:
    """Witness exactly the anchored CATL State.verify() snapshot; never auto-heal.

    A subsequent state change is a NEW head and needs a NEW witness receipt.
    The caller stores returned receipts outside the local broker's trust domain.
    """
    if not isinstance(ledger_id,str) or not re.fullmatch(r'[a-zA-Z0-9._-]{6,64}',ledger_id):
        raise WitnessRejected('ledger_identity_invalid')
    report=state.verify()
    if (not isinstance(report,dict) or report.get('valid') is not True
            or report.get('externally_anchored') is not True):
        raise WitnessRejected('state_not_locally_anchored_and_valid')
    count=report.get('count')
    mac=report.get('head_mac')
    head={'ledger_id':ledger_id,'sequence':count,'head_mac':mac}
    _head(head)
    return client.witness(head)
