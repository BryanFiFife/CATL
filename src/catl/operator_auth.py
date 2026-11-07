"""Optional, challenge-bound Ed25519 authorization for privilege-granting RPCs.

Not FIDO2/WebAuthn: a software signing key is NOT a presence/biometric claim.
The broker only holds the verified PUBLIC key, never the operator private key.
"""
from __future__ import annotations

import os
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Any

from .crypto import canonical

CHALLENGE_TTL_SECONDS = 30
MAX_OUTSTANDING_CHALLENGES = 32
MAX_SIGNED_COMMAND_BYTES = 16384


def signature_required(command: dict[str, Any]) -> bool:
    """Fail closed for every operation that can grant capability or clear safety state."""
    if not isinstance(command, dict):
        return True
    name = command.get('op')
    if name == 'set_feature':
        return command.get('enabled') is not False  # invalid values cannot bypass auth
    if name in ('set_tool', 'set_all_tools'):
        return command.get('enabled') is not False
    if name == 'decide':
        return command.get('approve') is not False
    if name == 'reconcile_incident':
        return True
    if name in ('status', 'pending', 'verify', 'incidents'):
        return False
    return True  # new operator methods cannot accidentally become unauthenticated


def _require_keyfile(path: Path, *, private: bool) -> bytes:
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise PermissionError('operator_key_symlink_refused')
    if os.name == 'posix':
        parent = path.parent.stat()
        if (parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)) or parent.st_uid not in (os.geteuid(), 0):
            raise PermissionError('operator_key_parent_untrusted')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise PermissionError('operator_key_not_regular_or_oversized')
        if os.name == 'posix':
            if info.st_uid not in (os.geteuid(), 0):
                raise PermissionError('operator_key_wrong_owner')
            if (info.st_mode & 0o077) if private else (info.st_mode & 0o022):
                raise PermissionError('operator_key_permissions_invalid')
        data = os.read(fd, 4097)
    finally:
        os.close(fd)
    if len(data) > 4096:
        raise PermissionError('operator_key_oversized')
    return data


def _validate_command(command: Any) -> dict[str, Any]:
    if not isinstance(command, dict) or not isinstance(command.get('op'), str):
        raise ValueError('operator_command_invalid')
    try:
        size = len(canonical(command))
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError('operator_command_invalid') from exc
    if size > MAX_SIGNED_COMMAND_BYTES or not signature_required(command):
        raise ValueError('operator_command_not_signable')
    return command


class OperatorAuthorizer:
    def __init__(self, public_file: Path):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        raw = _require_keyfile(public_file, private=False).strip()
        if len(raw) != 64:
            raise ValueError('operator_public_key_invalid')
        try:
            self.public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw.decode('ascii')))
        except (UnicodeError, ValueError) as exc:
            raise ValueError('operator_public_key_invalid') from exc
        self._pending: dict[str, tuple[int, bytes, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _data(command: dict[str, Any], uid: int, challenge: str) -> bytes:
        return canonical({'domain': 'CATL/OPERATOR-AUTH/v1', 'challenge': challenge,
                          'uid': uid, 'command': command})

    def issue(self, command: dict[str, Any], uid: int) -> dict[str, Any]:
        command = _validate_command(command)
        if type(uid) is not int or uid < 0:
            raise ValueError('operator_uid_invalid')
        with self._lock:
            now = time.monotonic()
            self._pending = {k:v for k,v in self._pending.items() if v[2] > now}
            if len(self._pending) >= MAX_OUTSTANDING_CHALLENGES:
                raise PermissionError('operator_challenge_capacity_reached')
            token = secrets.token_hex(24)  # 192-bit unpredictable single-use challenge
            data = self._data(command, uid, token)
            self._pending[token] = (uid, data, now+CHALLENGE_TTL_SECONDS)
        return {'challenge': token, 'message_hex': data.hex(),
                'expires_in_seconds': CHALLENGE_TTL_SECONDS,
                'scheme': 'Ed25519/CATL-OPERATOR-AUTH-v1'}

    def verify_and_consume(self, command: dict[str, Any], uid: int,
                           challenge: str, signature: str) -> dict[str, Any]:
        command = _validate_command(command)
        if not isinstance(challenge, str) or len(challenge) != 48 or not isinstance(signature, str) or len(signature) != 128:
            raise PermissionError('operator_signature_invalid')
        with self._lock:
            record = self._pending.pop(challenge, None)  # even bad signatures consume a challenge
        if record is None:
            raise PermissionError('operator_challenge_missing_or_replayed')
        issued_uid, issued_data, expiry = record
        if time.monotonic() >= expiry or issued_uid != uid or issued_data != self._data(command, uid, challenge):
            raise PermissionError('operator_challenge_expired_or_command_changed')
        try:
            signature_bytes = bytes.fromhex(signature)
            self.public.verify(signature_bytes, issued_data)
        except (ValueError, TypeError) as exc:
            raise PermissionError('operator_signature_invalid') from exc
        except Exception as exc:
            from cryptography.exceptions import InvalidSignature
            if isinstance(exc, InvalidSignature):
                raise PermissionError('operator_signature_invalid') from exc
            raise
        return command


class SoftwareOperatorSigner:
    """Evaluation signer. For high assurance replace with a separate hardware signer."""
    def __init__(self, private_file: Path):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = load_pem_private_key(_require_keyfile(private_file, private=True), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError('operator_signer_must_be_ed25519')
        self.private = key

    def sign_hex(self, message_hex: str) -> str:
        if not isinstance(message_hex, str) or len(message_hex) > 32768:
            raise ValueError('signing_message_invalid')
        return self.private.sign(bytes.fromhex(message_hex)).hex()


def generate_test_software_keypair(private_path: Path, public_path: Path) -> None:
    """Explicit provisioner: never silently creates, rotates, or overwrites keys."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (Encoding, PrivateFormat,
                                                               PublicFormat, NoEncryption)
    private = Ed25519PrivateKey.generate()
    values = ((Path(private_path), private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()), 0o600),
              (Path(public_path), private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex().encode('ascii')+b'\n', 0o644))
    if values[0][0] == values[1][0] or any(p.exists() or p.is_symlink() for p,_,_ in values):
        raise FileExistsError('operator_key_target_exists')
    created=[]
    try:
        for path, content, mode in values:
            fd=os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), mode)
            created.append(path)
            try:
                os.fchmod(fd,mode)
                with os.fdopen(fd,'wb') as stream:
                    stream.write(content);stream.flush();os.fsync(stream.fileno())
            except BaseException:
                # fdopen owns fd after entering the context manager; otherwise close safely.
                raise
    except BaseException:
        for path in created: path.unlink(missing_ok=True)
        raise
