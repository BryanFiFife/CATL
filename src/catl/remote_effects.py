"""Crash-conservative idempotency and provider read-back for consequential actions.

This service-side component must be invoked only after CATL Gateway policy,
operator approval and signed dispatch intent. It NEVER retries a possibly
transmitted mutation without independent provider read-back.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import sqlite3
import threading
import os
import stat
import fcntl
from contextlib import contextmanager, closing
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Any


class ExternalEffectUncertain(PermissionError):
    pass

class Provider(Protocol):
    def read_by_idempotency_key(self, key: str) -> dict[str, Any] | None: ...
    def submit(self, key: str, payload: dict[str, Any]) -> None: ...


def _canonical(value: dict[str, Any]) -> bytes:
    if not isinstance(value, dict):
        raise ValueError("remote_payload_must_be_object")
    raw=json.dumps(value,allow_nan=False,sort_keys=True,separators=(",", ":")).encode("utf-8")
    if len(raw)>65536:
        raise ValueError("remote_payload_too_large")
    return raw

@dataclass(frozen=True)
class EffectState:
    action_id: str
    status: str
    idempotency_key: str
    expected_hash: str

class RemoteEffectLedger:
    """Single-process serialised SQLite intent log. The caller must restrict DB access.

    A separate anchored CATL receipt is still required for rollback detection.
    Host-level fcntl locking is required before multi-process access.
    """
    def __init__(self, path: Path, secret: bytes):
        if not isinstance(secret,bytes) or len(secret)<32:
            raise ValueError("remote_effect_secret_too_short")
        if os.name != 'posix':
            raise PermissionError('remote_effects_requires_posix_locking_and_permissions')
        self.path=Path(path)
        self.secret=secret
        self._lock=threading.RLock()
        self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        parent = self.path.parent.stat()
        if self.path.parent.is_symlink() or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise PermissionError('remote_effect_parent_untrusted')
        if self.path.is_symlink():
            raise PermissionError("remote_effect_database_symlink")
        if not self.path.exists():
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
            os.close(fd)
        st=os.stat(self.path)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077 or st.st_nlink!=1:
            raise PermissionError('remote_effect_db_untrusted')
        self._lock_path=self.path.with_name(self.path.name+'.lock')
        with closing(self._conn()) as db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS effects (
                action_id TEXT PRIMARY KEY, service TEXT NOT NULL,
                key TEXT NOT NULL UNIQUE, expected_hash TEXT NOT NULL,
                seal TEXT NOT NULL, status TEXT NOT NULL
                  CHECK(status IN ('planned','uncertain','confirmed','divergent'))
              );
            """)
    @contextmanager
    def _guard(self):
        with self._lock:
            fd=os.open(self._lock_path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
            try:
                st=os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077 or st.st_nlink!=1:
                    raise PermissionError('remote_effect_lock_untrusted')
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
    def _conn(self):
        db=sqlite3.connect(self.path, isolation_level=None,timeout=10)
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('PRAGMA synchronous=FULL')
        return db
    def _seal(self, aid: str,service: str,key: str,digest: str,status: str) -> str:
        msg=json.dumps([aid,service,key,digest,status],separators=(',',':')).encode()
        return hmac.new(self.secret,msg,hashlib.sha256).hexdigest()
    def _get(self,db: sqlite3.Connection,aid:str) -> tuple[str,str,str,str] | None:
        row=db.execute('SELECT service,key,expected_hash,seal,status FROM effects WHERE action_id=?',(aid,)).fetchone()
        if row is None: return None
        service,key,expected,seal,status=row
        if not hmac.compare_digest(self._seal(aid,service,key,expected,status),seal):
            raise ExternalEffectUncertain("remote_effect_ledger_tampered")
        return service,key,expected,status
    def _prepare(self, aid:str,service:str,payload:dict[str,Any]) -> EffectState:
        if (not isinstance(aid,str) or len(aid)!=32 or any(c not in '0123456789abcdef' for c in aid)
                or not isinstance(service,str) or not 1<=len(service)<=80):
            raise ValueError('remote_action_identity_invalid')
        content=_canonical(payload)
        digest=hashlib.sha256(content).hexdigest()
        key=hmac.new(self.secret,b'CATL/REMOTE-KEY/v1/'+aid.encode()+b'/'+service.encode(),hashlib.sha256).hexdigest()
        with closing(self._conn()) as db:
            db.execute('BEGIN IMMEDIATE')
            existing=self._get(db,aid)
            if existing is None:
                db.execute('INSERT INTO effects VALUES(?,?,?,?,?,?)',
                           (aid,service,key,digest,self._seal(aid,service,key,digest,'planned'),'planned'))
                status='planned'
            else:
                found_service,found_key,found_digest,status=existing
                if (found_service,found_key,found_digest)!=(service,key,digest):
                    raise ExternalEffectUncertain('action_id_reuse_with_different_payload')
            db.commit()
            return EffectState(aid,status,key,digest)
    def _set(self,aid:str,status:str)->None:
        with closing(self._conn()) as db:
            db.execute('BEGIN IMMEDIATE')
            if self._get(db,aid) is None:
                raise ExternalEffectUncertain('remote_action_missing')
            service,key,digest,_=self._get(db,aid)
            db.execute('UPDATE effects SET status=?,seal=? WHERE action_id=?',
                       (status,self._seal(aid,service,key,digest,status),aid))
            db.commit()
    def _readback(self, aid:str, provider:Provider, state:EffectState) -> bool:
        effect=provider.read_by_idempotency_key(state.idempotency_key)
        if effect is None: return False
        if not isinstance(effect,dict) or not hmac.compare_digest(
                hashlib.sha256(_canonical(effect)).hexdigest(),state.expected_hash):
            self._set(aid,'divergent')
            raise ExternalEffectUncertain('remote_provider_effect_differs')
        self._set(aid,'confirmed')
        return True
    def execute_once(self,aid:str,service:str,payload:dict[str,Any],provider:Provider)->EffectState:
        with self._guard():
            state=self._prepare(aid,service,payload)
            if state.status=='confirmed':return state
            if state.status in ('uncertain','divergent'):
                raise ExternalEffectUncertain('reconciliation_required_no_automatic_retry')
            try:
                found=self._readback(aid,provider,state)
            except ExternalEffectUncertain:raise
            except Exception as exc:
                self._set(aid,'uncertain')
                raise ExternalEffectUncertain('remote_preflight_readback_unavailable') from exc
            if found:return EffectState(aid,'confirmed',state.idempotency_key,state.expected_hash)
            # COMMIT the attempted intent before network dispatch. After crash,
            # no automatic resend, even if the network call never completed.
            self._set(aid,'uncertain')
            try:
                provider.submit(state.idempotency_key,payload)
                if self._readback(aid,provider,state):
                    return EffectState(aid,'confirmed',state.idempotency_key,state.expected_hash)
            except ExternalEffectUncertain:raise
            except Exception as exc:
                raise ExternalEffectUncertain('remote_submit_or_readback_unknown') from exc
            raise ExternalEffectUncertain('remote_submit_without_confirmed_readback')
    def reconcile_by_readback(self,aid:str,service:str,payload:dict[str,Any],provider:Provider)->EffectState:
        with self._guard():
            state=self._prepare(aid,service,payload)
            if state.status=='divergent':raise ExternalEffectUncertain('divergent_requires_manual_incident')
            try:
                confirmed=self._readback(aid,provider,state)
            except ExternalEffectUncertain:raise
            except Exception as exc:
                raise ExternalEffectUncertain('readback_unavailable_no_mutation') from exc
            if not confirmed:
                raise ExternalEffectUncertain('effect_absent_operator_review_required')
            return EffectState(aid,'confirmed',state.idempotency_key,state.expected_hash)
