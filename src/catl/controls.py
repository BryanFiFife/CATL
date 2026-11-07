"""Signed, fail-closed local operator controls.

The operator UI changes only *availability*. No control permits a policy bypass.
The supervisor must protect the HMAC key from the less-trusted agent identity.
"""
from __future__ import annotations

import json
from typing import Any
from .crypto import hmac_hex, strict_loads

TOGGLES = (
    "gateway_enabled", "approvals_enabled", "verification_enabled", "audit_enabled"
)
DEFAULT = {
    "schema": 1,
    "gateway_enabled": True,
    "approvals_enabled": True,
    "verification_enabled": True,
    "audit_enabled": True,
    "disabled_tools": [],
}


def validate(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict) or set(doc) != set(DEFAULT) or type(doc["schema"]) is not int or doc["schema"] != 1:
        raise ValueError("control_schema_invalid")
    for name in TOGGLES:
        if type(doc[name]) is not bool:
            raise ValueError("control_toggle_invalid")
    tools = doc["disabled_tools"]
    if (not isinstance(tools, list) or len(tools) > 256 or
            any(not isinstance(t, str) or not t or len(t) > 128 for t in tools) or
            sorted(set(tools)) != tools):
        raise ValueError("control_tools_invalid")
    return doc


def encode(doc: dict[str, Any], key: bytes) -> tuple[str, str]:
    validate(doc)
    body = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return body, hmac_hex(key, {"domain": "CATL/CONTROL/v1", "body": body})


def decode(body: str, mac: str, key: bytes) -> dict[str, Any]:
    import hmac
    candidate = hmac_hex(key, {"domain": "CATL/CONTROL/v1", "body": body})
    if not isinstance(mac, str) or not hmac.compare_digest(candidate, mac):
        raise PermissionError("control_signature_invalid")
    try:
        return validate(strict_loads(body))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise PermissionError("control_document_invalid") from exc
