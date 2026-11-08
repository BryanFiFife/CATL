"""Small modern/legacy MCP stdio *subset* adapter.

Only discovery, tool listing and tool calls are supported. The backend remains
legacy MCP 2025-11-25; HTTP, subscriptions and MRTR are intentionally excluded.
"""
from __future__ import annotations
from typing import Any
from . import __version__

MODERN = "2026-07-28"
LEGACY = "2025-11-25"
VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
CAPABILITY_KEY = "io.modelcontextprotocol/clientCapabilities"
CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo"
SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"
SERVER_INFO = {"name": "caledapt-agent-trust", "version": __version__}


def classify(msg: dict[str, Any]) -> str:
    """Reject malformed/missing modern envelopes and unknown versions safely."""
    params = msg.get("params", {})
    if not isinstance(params, dict):
        raise ValueError("invalid_params")
    if "_meta" not in params:
        if msg.get("method") == "server/discover":
            raise ValueError("modern_metadata_required")
        return "legacy"
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        raise ValueError("modern_metadata_invalid")
    if VERSION_KEY not in meta:
        return "legacy"  # Legacy protocols permit application-specific _meta
    if meta.get(VERSION_KEY) != MODERN:
        raise ValueError("unsupported_protocol_version")
    if not isinstance(meta.get(CAPABILITY_KEY), dict):
        raise ValueError("modern_client_capabilities_required")
    if CLIENT_INFO_KEY not in meta:
        raise ValueError("modern_client_info_required")
    ident = meta[CLIENT_INFO_KEY]
    if (not isinstance(ident, dict) or not isinstance(ident.get("name"), str) or
            not ident.get("name") or len(ident["name"]) > 128 or
            not isinstance(ident.get("version"), str) or not ident.get("version") or
            len(ident["version"]) > 64):
        raise ValueError("modern_client_info_invalid")
    return "modern"


def modernize(response: dict[str, Any]) -> dict[str, Any]:
    if "result" in response and isinstance(response["result"], dict):
        result = dict(response["result"])
        if result.get("resultType", "complete") != "complete":
            return {"jsonrpc": "2.0", "id": response["id"],
                    "error": {"code": -32603, "message": "unsupported_backend_result_type"}}
        previous_meta = result.get("_meta", {})
        if not isinstance(previous_meta, dict):
            return {"jsonrpc": "2.0", "id": response["id"],
                    "error": {"code": -32603, "message": "invalid_backend_result_metadata"}}
        result["resultType"] = "complete"
        # MCP 2026-07-28 requires cache metadata on EVERY successful Result,
        # including tools/call (not merely tools/list and discovery).
        # Never forward upstream cache hints: approvals, policy and operator
        # controls can change between calls, and tool results are private.
        result["ttlMs"] = 0
        result["cacheScope"] = "private"
        result["_meta"] = {**previous_meta, SERVER_INFO_KEY: SERVER_INFO}
        response = {**response, "result": result}
    return response


def discovery(request_id: Any) -> dict[str, Any]:
    return modernize({"jsonrpc": "2.0", "id": request_id, "result": {
        "supportedVersions": [MODERN],
        "capabilities": {"tools": {"listChanged": False}},
        "instructions": "CATL enforces a reviewed tool allowlist, human approval and local audit. Sensitive actions may require retry after operator consent.",
        "ttlMs": 0, "cacheScope": "private"}})
