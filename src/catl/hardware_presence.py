"""WebAuthn assertion verification primitive; NOT credential enrolment or a USB/FIDO client.

All challenges must originate from a one-use, command+UID-bound operator grant and
counters must be durably committed under a broker lock before authorisation.
No assertion, even a valid one, is accepted as a reusable bearer credential.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class PresenceRejected(PermissionError):
    pass


def _b64url(raw: str) -> bytes:
    if not isinstance(raw, str) or not 1 <= len(raw) <= 8192 or not re.fullmatch(r"[A-Za-z0-9_-]+", raw):
        raise PresenceRejected("invalid_base64url")
    try:
        value = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise PresenceRejected("invalid_base64url") from exc
    if base64.urlsafe_b64encode(value).rstrip(b"=").decode() != raw:
        raise PresenceRejected("noncanonical_base64url")
    return value


@dataclass(frozen=True)
class Credential:
    credential_id: str  # pinned credential's base64url ID
    public_key_pem: bytes
    rp_id: str
    allowed_origin: str  # fully qualified origin provisioned by operator
    sign_count: int
    require_user_verification: bool = True


def verify_assertion(credential: Credential, assertion: dict[str, Any], *, challenge: bytes) -> int:
    """Return a new signature counter only after authenticating the assertion.

    The caller MUST consume its one-time command-bound challenge atomically and
    persist the returned counter before invoking the action. This function
    does not assert that the *actual physical* device was used in this process.
    """
    if not isinstance(challenge, bytes) or len(challenge) < 24 or len(challenge) > 128:
        raise PresenceRejected("challenge_invalid")
    if not isinstance(assertion, dict) or set(assertion) != {
        "credential_id", "client_data_json", "authenticator_data", "signature"
    }:
        raise PresenceRejected("assertion_shape_invalid")
    if assertion["credential_id"] != credential.credential_id:
        raise PresenceRejected("credential_mismatch")
    if type(credential.sign_count) is not int or not 0 <= credential.sign_count <= 0xffffffff:
        raise PresenceRejected("stored_counter_invalid")
    client_raw = _b64url(assertion["client_data_json"])
    auth_raw = _b64url(assertion["authenticator_data"])
    signature = _b64url(assertion["signature"])
    if len(client_raw) > 4096 or len(auth_raw) != 37 or len(signature) > 160:
        raise PresenceRejected("assertion_size_or_extensions_unsupported")
    try:
        client = json.loads(client_raw, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)),
                            object_pairs_hook=lambda pairs: _unique_pairs(pairs))
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise PresenceRejected("client_data_invalid") from exc
    if not isinstance(client, dict) or client.get("type") != "webauthn.get":
        raise PresenceRejected("assertion_type_invalid")
    if client.get("crossOrigin", False) is not False or "topOrigin" in client:
        raise PresenceRejected("cross_origin_not_supported")
    if client.get("origin") != credential.allowed_origin:
        raise PresenceRejected("origin_mismatch")
    if not hmac.compare_digest(_b64url(client.get("challenge", "")), challenge):
        raise PresenceRejected("challenge_mismatch")
    if not hmac.compare_digest(auth_raw[:32], hashlib.sha256(credential.rp_id.encode("utf-8")).digest()):
        raise PresenceRejected("rp_id_mismatch")
    flags = auth_raw[32]
    if not flags & 0x01 or credential.require_user_verification and not flags & 0x04:
        raise PresenceRejected("required_presence_or_verification_missing")
    if flags & 0xE2:  # reserved bits or AT: cannot parse attested-credential data here
        raise PresenceRejected("unsupported_authenticator_flags")
    if (flags & 0x10) and not (flags & 0x08):
        raise PresenceRejected("invalid_backup_flags")
    new_count = int.from_bytes(auth_raw[33:37], "big")
    if (new_count or credential.sign_count) and new_count <= credential.sign_count:
        raise PresenceRejected("signature_counter_replay_or_clone")
    try:
        pub = serialization.load_pem_public_key(credential.public_key_pem)
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
            raise PresenceRejected("credential_key_must_be_es256")
        pub.verify(signature, auth_raw + hashlib.sha256(client_raw).digest(), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise PresenceRejected("assertion_signature_invalid") from exc
    return new_count


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, val in pairs:
        if key in out:
            raise ValueError("duplicate_client_data_key")
        out[key] = val
    return out
