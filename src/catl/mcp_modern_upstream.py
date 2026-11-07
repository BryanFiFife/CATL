"""Explicitly selected 2026-07-28 modern MCP upstream adapter for CATL's legacy Backend API.

This is a *tools-only*, fail-closed bridge. Not a full MCP SDK implementation;
MRTR, resources, prompts, subscriptions and HTTP auth stay unsupported.
"""
from __future__ import annotations
import copy
from typing import Any, Protocol

MODERN = "2026-07-28"
VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities"
CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo"

class ModernMCPRejected(ValueError):
    pass

class WireBackend(Protocol):
    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]: ...
    def notify(self, method: str, params: dict[str, Any] | None = None) -> None: ...
    def close(self) -> None: ...

class ModernToolsBackend:
    """Present legacy calls to CATL Gateway while talking only to modern upstream.

    Operator must select this wrapper consciously; no insecure heuristic
    fallback from modern to legacy is allowed after discovery fails.
    """
    def __init__(self, upstream: WireBackend, *, client_name: str = "caledapt-agent-trust",
                 client_version: str = "0.11.0rc1"):
        if not 1 <= len(client_name) <= 128 or not 1 <= len(client_version) <= 64:
            raise ModernMCPRejected("client_identity_invalid")
        self.upstream = upstream
        self.client_name = client_name
        self.client_version = client_version
        self.discovered = False

    def _meta(self) -> dict[str, Any]:
        return {VERSION_KEY: MODERN, CAPABILITIES_KEY: {},
                CLIENT_INFO_KEY: {"name": self.client_name, "version": self.client_version}}

    @staticmethod
    def _response(response: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(response, dict) or ("result" in response) == ("error" in response):
            raise ModernMCPRejected("ambiguous_upstream_reply")
        if "error" in response:
            value=response["error"]
            if not isinstance(value, dict) or type(value.get("code")) is not int:
                raise ModernMCPRejected("invalid_upstream_error")
            return {"error": {"code": -32050, "message": "upstream_error"}}
        result=response["result"]
        if not isinstance(result, dict):
            raise ModernMCPRejected("upstream_result_invalid")
        if (result.get("resultType", "complete") != "complete" or
                "inputRequests" in result or "requestState" in result):
            raise ModernMCPRejected("modern_multi_round_trip_not_supported")
        return {"result": copy.deepcopy(result)}

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if method == "initialize":
            if self.discovered:
                return {"result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}}}
            reply=self._response(self.upstream.request("server/discover", {"_meta": self._meta()}))
            if "error" in reply:
                raise ModernMCPRejected("modern_discovery_rejected")
            info=reply["result"]
            versions=info.get("supportedVersions")
            if (not isinstance(versions,list) or MODERN not in versions or
                    not isinstance(info.get("capabilities"),dict) or
                    not isinstance(info["capabilities"].get("tools"),dict)):
                raise ModernMCPRejected("modern_tools_capability_unavailable")
            self.discovered=True
            return {"result": {"protocolVersion":"2025-11-25", "capabilities":{"tools":{}}}}
        if not self.discovered:
            raise ModernMCPRejected("modern_discovery_required")
        if method not in ("tools/list", "tools/call"):
            raise ModernMCPRejected("modern_method_not_allowed")
        if params is None:
            params={}
        if not isinstance(params,dict) or "_meta" in params:
            raise ModernMCPRejected("untrusted_modern_metadata_refused")
        actual={**copy.deepcopy(params),"_meta":self._meta()}
        return self._response(self.upstream.request(method,actual))

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        if method != "notifications/initialized":
            raise ModernMCPRejected("modern_notification_not_allowed")
        # The modern era has no initialized notification. Gateway still expects
        # a legacy Backend interface; absorb this locally rather than sending it.

    def close(self) -> None:
        self.upstream.close()
