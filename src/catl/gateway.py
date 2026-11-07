"""Synchronous stdio MCP proxy with an independent, fail-closed tool boundary.

Consciously limited to one backend process and serial requests in this first release.
"""
from __future__ import annotations
import json
import ipaddress
import queue
import secrets
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any, Protocol
from .crypto import MAX_WIRE_BYTES, digest, parse_json
from .policy import Policy
from .store import State, binding_hash
from .isolation import isolation_for, child_environment, validate_workdir
from .protocol import classify, modernize, discovery
from .verifier import FileDigestVerifier
from .schema import validate_arguments, validate_structured_output

# The backend is untrusted even when a tool was present in a pinned catalogue.
# Never pass an oversized or malformed tool reply into a success path.
MAX_TOOL_REPLY_BYTES = 512 * 1024

# The model consumes backend text as untrusted data; do not let a malicious
# backend smuggle novel content types or active URI schemes through the proxy.
# New MCP types must be reviewed before adding them to this allowlist.
SUPPORTED_CONTENT_TYPES = frozenset({"text", "image", "audio", "resource", "resource_link"})


def _validate_display_uri(uri: Any) -> None:
    """Parse only; CATL never follows links or grants network authority."""
    if not isinstance(uri, str) or len(uri) > 2048 or any(ord(ch) < 32 for ch in uri):
        raise ValueError("backend_resource_link_invalid")
    parsed = urlsplit(uri)
    hostname = (parsed.hostname or "").lower()
    if (parsed.scheme != "https" or not hostname or
            parsed.username is not None or parsed.password is not None or
            hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal"))):
        raise ValueError("backend_resource_link_scheme_denied")
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        pass  # DNS names aren't resolved or automatically fetched by CATL.
    else:
        if not addr.is_global:
            raise ValueError("backend_resource_link_private_address_denied")


def _validate_content_item(item: Any) -> None:
    if not isinstance(item, dict) or item.get("type") not in SUPPORTED_CONTENT_TYPES:
        raise ValueError("backend_tool_content_type_unsupported")
    kind = item["type"]
    if kind == "text":
        if not isinstance(item.get("text"), str):
            raise ValueError("backend_tool_text_invalid")
    elif kind in ("image", "audio"):
        required_mime = "image/" if kind == "image" else "audio/"
        if (not isinstance(item.get("data"), str) or
                not isinstance(item.get("mimeType"), str) or
                not item["mimeType"].startswith(required_mime)):
            raise ValueError("backend_tool_media_invalid")
        # Do not decode media in the supervisor; a downstream decoder may have
        # its own vulnerabilities. The full JSON reply remains size-limited.
    elif kind == "resource_link":
        _validate_display_uri(item.get("uri"))
    else:
        resource = item.get("resource")
        if not isinstance(resource, dict) or not isinstance(resource.get("uri"), str):
            raise ValueError("backend_embedded_resource_invalid")
        _validate_display_uri(resource["uri"])
        if not (isinstance(resource.get("text"), str) ^ isinstance(resource.get("blob"), str)):
            raise ValueError("backend_embedded_resource_content_invalid")
        # Embedded resources are *data*, never an authorization signal.

def checked_tool_reply(reply: dict[str, Any], *, tool: dict[str, Any] | None = None) -> tuple[str, Any]:
    if not isinstance(reply, dict) or ("result" in reply) == ("error" in reply):
        raise ValueError("backend_response_ambiguous")
    try:
        raw = json.dumps(reply, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("backend_reply_not_json") from exc
    if len(raw) > MAX_TOOL_REPLY_BYTES:
        raise ValueError("backend_reply_oversized")
    if "error" in reply:
        # Backend error objects are untrusted. Never relay arbitrary backend
        # metadata, nested objects or attacker-invented error codes to clients.
        value = reply["error"]
        if not isinstance(value, dict) or type(value.get("code")) is not int or not isinstance(value.get("message"), str):
            raise ValueError("backend_rpc_error_invalid")
        return "rpc_error", {"code": -32050, "message": "upstream_tool_error"}
    result = reply["result"]
    if not isinstance(result, dict) or type(result.get("isError", False)) is not bool:
        raise ValueError("backend_tool_result_invalid")
    # MCP 2026 supports multi-round-trip results. CATL has no trusted MRTR
    # replay/approval contract, so treating input_required as a completed
    # action could both mislead clients and trigger an unsafe duplicate call.
    # The legacy backend may omit resultType but must never invent a variant.
    if result.get("resultType", "complete") != "complete":
        raise ValueError("backend_result_not_complete")
    if "inputRequests" in result or "requestState" in result:
        # A 'complete' result carrying unfinished multi-round-trip state
        # must never smuggle a continuation into the agent channel.
        raise ValueError("backend_mixed_completion_and_continuation")
    content = result.get("content")
    if not isinstance(content, list) or len(content) > 64:
        raise ValueError("backend_tool_content_invalid")
    for item in content:
        _validate_content_item(item)
    if tool is not None:
        validate_structured_output(tool, result)
    # CATL forwards only the reviewed MCP result contract. Unknown keys and
    # untrusted _meta must never acquire semantics in a downstream harness.
    sanitized: dict[str, Any] = {"content": []}
    if "resultType" in result:
        sanitized["resultType"] = "complete"
    if "isError" in result:
        sanitized["isError"] = result["isError"]
    if "structuredContent" in result:
        sanitized["structuredContent"] = result["structuredContent"]
    for item in content:
        kind = item["type"]
        if kind == "text":
            sanitized["content"].append({"type": kind, "text": item["text"]})
        elif kind in ("image", "audio"):
            sanitized["content"].append({"type": kind, "data": item["data"], "mimeType": item["mimeType"]})
        elif kind == "resource_link":
            safe = {"type": kind, "uri": item["uri"]}
            for field in ("name", "description", "mimeType"):
                if field in item and isinstance(item[field], str):
                    safe[field] = item[field]
            sanitized["content"].append(safe)
        else:
            resource = item["resource"]
            safe_resource = {key: resource[key] for key in ("uri", "text", "blob", "mimeType")
                             if key in resource and isinstance(resource[key], str)}
            sanitized["content"].append({"type": "resource", "resource": safe_resource})
    return "result", sanitized


class Backend(Protocol):
    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]: ...
    def notify(self, method: str, params: dict[str, Any] | None = None) -> None: ...
    def close(self) -> None: ...


class SubprocessBackend:
    """No shell. Gateway and child require external sandboxing for real isolation."""
    def __init__(self, command: list[str], timeout: float = 15, *, backend_user: str | None = None,
                 allow_unsandboxed: bool = False, pass_env: tuple[str, ...] = (),
                 workdir: Path | None = None):
        if not command:
            raise ValueError("missing_child_command")
        self.timeout = timeout
        isolation = isolation_for(backend_user, allow_unsandboxed)
        sandbox_home = None
        if isolation.sandbox_user:
            import pwd
            sandbox_home = pwd.getpwnam(isolation.sandbox_user).pw_dir
        environment = child_environment(pass_env=pass_env, sandbox_home=sandbox_home)
        kwargs: dict[str, Any] = {
            # Never stream untrusted backend terminal escapes into the trusted operator terminal.
            "stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL,
            "bufsize": 0, "env": environment, "cwd": validate_workdir(workdir),
            "close_fds": True,
            "start_new_session": (sys.platform != "win32"),
        }
        if isolation.user is not None:
            kwargs.update(user=isolation.user, group=isolation.group, extra_groups=list(isolation.extra_groups or ()))
        self.proc = subprocess.Popen(command, **kwargs)
        self.events: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=512)
        self.seq = 0
        self._overflow = threading.Event()
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        try:
            assert self.proc.stdout is not None
            malformed_count = 0
            while True:
                line = self.proc.stdout.readline(MAX_WIRE_BYTES + 2)
                if not line:
                    break
                try:
                    event = parse_json(line)
                except (ValueError, UnicodeError, json.JSONDecodeError):
                    malformed_count += 1
                    if malformed_count >= 32:
                        # Infinite invalid frames must not pin a CPU core.
                        self._overflow.set()
                        break
                    continue
                malformed_count = 0
                try:
                    self.events.put_nowait(event)
                except queue.Full:
                    # A malicious backend can emit unlimited unsolicited
                    # messages. Never strand the reader on a full queue.
                    self._overflow.set()
                    break
        finally:
            try:
                self.events.put_nowait(None)
            except queue.Full:
                # request() checks _overflow independently, so a sentinel
                # must never block a daemon thread during shutdown.
                self._overflow.set()

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    def _send(self, msg: dict[str, Any]) -> None:
        payload = json.dumps(msg, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(payload) > MAX_WIRE_BYTES:
            raise ValueError("outbound_message_too_large")
        if self.proc.poll() is not None:
            raise RuntimeError("child_exited")
        assert self.proc.stdin is not None
        outcome: list[BaseException] = []
        written = threading.Event()
        def write_payload():
            try:
                assert self.proc.stdin is not None
                self.proc.stdin.write(payload + b"\n")
                self.proc.stdin.flush()
            except BaseException as exc:
                outcome.append(exc)
            finally:
                written.set()
        thread = threading.Thread(target=write_payload, daemon=True)
        thread.start()
        if not written.wait(self.timeout):
            self.close()
            raise TimeoutError("backend_stdin_write_timeout")
        if outcome:
            raise RuntimeError("backend_stdin_write_failed") from outcome[0]

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.seq += 1
        request_id = f"catl-{self.seq}"
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, **({"params": params} if params is not None else {})})
        deadline = time.monotonic() + self.timeout
        while True:
            if self._overflow.is_set():
                self.close()
                raise RuntimeError("backend_event_queue_overflow")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.close()  # no later dispatch against a timed-out backend
                raise TimeoutError("backend_timeout")
            try:
                event = self.events.get(timeout=remaining)
            except queue.Empty as exc:
                self.close()  # stop late side effects; outcome still uncertain
                raise TimeoutError("backend_timeout") from exc
            if self._overflow.is_set():
                self.close()
                raise RuntimeError("backend_event_queue_overflow")
            if event is None:
                raise RuntimeError("backend_closed")
            # A backend request or notification cannot directly reach the agent.
            if event.get("jsonrpc") == "2.0" and event.get("id") == request_id and ("result" in event or "error" in event):
                return event

    def close(self) -> None:
        # Terminate the process BEFORE closing stdin: another thread may be
        # blocked in a pipe write and Python's buffered close could hang.
        if self.proc.poll() is None:
            # Terminate the ordinary child process group rather than only the
            # immediate process. Descendants that start a new session, and
            # Windows descendants, still need external OS containment.
            if sys.platform != "win32":
                import os, signal
                try:
                    os.killpg(self.proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            else:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if sys.platform != "win32":
                    try:
                        os.killpg(self.proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    self.proc.kill()
                self.proc.wait(timeout=2)
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            if self.proc.stdout:
                self.proc.stdout.close()
        except (OSError, ValueError):
            pass


def error(id_: Any, message: str, code: int = -32003, data: Any = None) -> dict[str, Any]:
    item = {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}
    if data is not None:
        item["error"]["data"] = data
    return item


class Gateway:
    def __init__(self, policy: Policy, state: State, backend: Backend):
        self.policy, self.state, self.backend = policy, state, backend
        self.available: dict[str, dict[str, Any]] = {}
        self.backend_ready = False
        self._legacy_initialized = False
        # Shared with the protected broker operator channel.  This lock
        # linearises permission-tightening commands against the FINAL dispatch
        # authorisation (controls, rate permit and signed dispatch intent).
        # It is never held during the untrusted backend's execution.
        self.dispatch_gate = threading.RLock()

    def _ensure_backend(self) -> None:
        if self.backend_ready:
            return
        response = self.backend.request("initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {}, "clientInfo": {"name": "caledapt-agent-trust", "version": "0.11.0rc1"}})
        if "error" in response or not isinstance(response.get("result"), dict):
            raise RuntimeError("backend_initialization_failed")
        self.backend.notify("notifications/initialized")
        self._legacy_initialized = True
        self.backend_ready = True

    def _refresh(self) -> list[dict[str, Any]]:
        """Check the backend's current tool definitions before every protected call."""
        self.available = {}
        controls = self.state.controls()  # signature-verified; missing/corrupt => no dispatch
        if not controls["gateway_enabled"] or not controls["audit_enabled"]:
            return []
        # A signed unresolved dispatch or ambiguous outcome MUST NOT be
        # retried simply because the client asked again or the broker restarted.
        quarantined = {item["tool"] for item in self.state.open_incidents()}
        self._ensure_backend()
        seen: set[str] = set()
        cursors: set[str] = set()
        cursor: str | None = None
        for _page in range(16):
            response = self.backend.request("tools/list", {"cursor": cursor} if cursor else {})
            if "error" in response:
                raise RuntimeError("backend_tools_list_failed")
            result = response.get("result")
            if (not isinstance(result, dict) or not isinstance(result.get("tools"), list)
                    or result.get("resultType", "complete") != "complete"):
                raise ValueError("backend_tools_list_invalid")
            for tool in result["tools"]:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                    raise ValueError("invalid_tool_definition")
                if tool["name"] in seen:
                    raise ValueError("duplicate_tool_name")
                seen.add(tool["name"])
                if len(seen) > 256:
                    raise ValueError("catalogue_too_large")
                if (self.policy.pinned(tool) and tool["name"] not in controls["disabled_tools"]
                        and tool["name"] not in quarantined):
                    self.available[tool["name"]] = tool
            cursor = result.get("nextCursor")
            if cursor is None or cursor == "":
                return [self.available[name] for name in sorted(self.available)]
            if not isinstance(cursor, str) or len(cursor) > 1024 or cursor in cursors:
                raise ValueError("catalogue_cursor_invalid_or_repeated")
            cursors.add(cursor)
        raise ValueError("catalogue_pages_exceeded")

    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return error(msg.get("id") if isinstance(msg, dict) else None, "invalid_request", -32600)
        method = msg["method"]
        try:
            era = classify(msg)
        except ValueError as exc:
            code = -32022 if str(exc) == "unsupported_protocol_version" else -32602
            return error(msg.get("id"), str(exc), code)
        if era == "modern" and method in ("initialize", "ping"):
            return error(msg.get("id"), "method_not_allowed_in_modern", -32601)
        if era == "legacy" and method == "server/discover":
            return error(msg.get("id"), "modern_metadata_required", -32602)
        is_req = "id" in msg
        if is_req and (msg["id"] is None or isinstance(msg["id"], bool) or not isinstance(msg["id"], (int, str))):
            return error(None, "invalid_request_id", -32600)
        if not is_req:
            # The broker owns the upstream handshake. Never forward untrusted
            # client notifications to the backend, including out-of-order
            # initialized messages while the gateway is disarmed.
            return None
        id_ = msg["id"]
        if era == "modern" and method == "server/discover":
            return discovery(id_)
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return error(id_, "invalid_params", -32602)
        if method == "ping":
            return {"jsonrpc": "2.0", "id": id_, "result": {}}
        if method == "initialize":
            # A legacy client's self-declared capabilities and identifiers are
            # untrusted input. Respond locally without activating a backend or
            # forwarding arbitrary client-supplied initialization metadata.
            if params.get("protocolVersion") not in (None, "2025-11-25"):
                return error(id_, "unsupported_protocol_version", -32022)
            return {"jsonrpc": "2.0", "id": id_, "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "caledapt-agent-trust", "version": "0.11.0rc1"}}}
        if method == "tools/list":
            try:
                result = {"jsonrpc": "2.0", "id": id_, "result": {"tools": self._refresh()}}
                return modernize(result) if era == "modern" else result
            except (RuntimeError, TimeoutError, ValueError, OSError) as exc:
                return error(id_, f"catalogue_unavailable:{type(exc).__name__}")
        if method == "tools/call":
            if era == "modern" and any(k in params for k in ("inputResponses", "requestState")):
                return error(id_, "multi_round_trip_not_supported", -32602)
            response = self._tool_call(id_, params)
            return modernize(response) if era == "modern" else response
        return error(id_, "method_not_allowed", -32601)

    def _record(self, tool: str, binding: str | None, decision: str, outcome: str,
                *, action_id: str | None = None) -> None:
        event = {"at": int(time.time()), "agent_id": self.policy.agent_id,
                 "tool": tool, "binding": binding, "policy_hash": self.policy.source_hash,
                 "decision": decision, "outcome": outcome}
        if action_id is not None:
            event["action_id"] = action_id
        self.state.append(event)

    def _tool_call(self, id_: Any, params: dict[str, Any]) -> dict[str, Any]:
        name, args = params.get("name"), params.get("arguments", {})
        if not isinstance(name, str) or not name or not isinstance(args, dict):
            return error(id_, "invalid_tool_call", -32602)
        # Reject oversized argument payloads even for programmatic callers.
        try:
            if len(json.dumps(args, allow_nan=False, ensure_ascii=False).encode("utf-8")) > 65536:
                return error(id_, "arguments_too_large", -32602)
        except (TypeError, ValueError):
            return error(id_, "arguments_invalid", -32602)
        binding = binding_hash(self.policy.agent_id, name, args, self.policy.tool_pins.get(name, ""), self.policy.source_hash)
        try:
            controls = self.state.controls()
            if not controls["gateway_enabled"] or not controls["audit_enabled"]:
                self._record(name, binding, "deny", "gateway_or_audit_disabled")
                return error(id_, "operator_disabled_gateway_or_audit")
            if name in controls["disabled_tools"]:
                self._record(name, binding, "deny", "operator_disabled_tool")
                return error(id_, "tool_disabled_by_operator")
            if any(item["tool"] == name for item in self.state.open_incidents()):
                self._record(name, binding, "deny", "unreconciled_effect_quarantine")
                return error(id_, "tool_quarantined_pending_reconciliation")
            if name not in {t["name"] for t in self._refresh()}:
                self._record(name, binding, "deny", "tool_unavailable_or_pin_mismatch")
                return error(id_, "tool_not_pinned_or_unavailable")
            try:
                validate_arguments(self.available[name], args)
            except (ValueError, TypeError, RecursionError):
                self._record(name, binding, "deny", "tool_arguments_invalid_against_schema")
                return error(id_, "tool_arguments_invalid_against_schema", -32602)
            effect = self.policy.evaluate(name, args)
            verifier = self.policy.postconditions.get(name)
            if effect == "approve" and not controls["approvals_enabled"]:
                self._record(name, binding, "deny", "approvals_disabled_by_operator")
                return error(id_, "approvals_disabled_by_operator")
            if verifier and not controls["verification_enabled"]:
                self._record(name, binding, "deny", "verification_disabled_by_operator")
                return error(id_, "verification_disabled_by_operator")
            if verifier and effect != "deny":
                try:
                    verifier.preflight(args)
                except (OSError, ValueError) as exc:
                    self._record(name, binding, "deny", "postcondition_preflight_invalid")
                    return error(id_, "postcondition_preflight_invalid", -32602)
            if effect == "deny":
                self._record(name, binding, "deny", "policy_denied")
                return error(id_, "policy_denied")
            if effect == "approve" and not self.state.consume(binding):
                approval_id = self.state.request(binding, {"agent": self.policy.agent_id, "tool": name, "arguments": args})
                self._record(name, binding, "approve", "awaiting_human")
                return error(id_, "human_approval_required", data={"approval_id": approval_id})
            # The operator channel acquires the SAME dispatch_gate while
            # committing a control change.  A completed Pause/Disable cannot
            # be overtaken by an action whose intent was not yet committed.
            # A previously recorded dispatch intent is already in flight and
            # may have effects even if the backend later times out.
            with self.dispatch_gate:
                latest = self.state.controls()
                if (not latest["gateway_enabled"] or not latest["audit_enabled"]
                        or name in latest["disabled_tools"]
                        or (effect == "approve" and not latest["approvals_enabled"])
                        or (verifier is not None and not latest["verification_enabled"])):
                    self._record(name, binding, "deny", "operator_control_changed_before_dispatch")
                    return error(id_, "operator_control_changed_before_dispatch")
                if not self.state.acquire_rate(self.policy.agent_id, name, self.policy.rate_limits.get(name, 60)):
                    self._record(name, binding, "deny", "rate_limit_exceeded")
                    return error(id_, "rate_limit_exceeded")
                # This signed event marks the instant the action becomes
                # in-flight.  The real-world effect may still be uncertain.
                action_id = secrets.token_hex(16)
                self._record(name, binding, effect, "dispatch_intent", action_id=action_id)
            try:
                reply = self.backend.request("tools/call", {"name": name, "arguments": args})
            except (RuntimeError, TimeoutError, ValueError, OSError) as exc:
                self._record(name, binding, effect, f"transport_failure:{type(exc).__name__}", action_id=action_id)
                return error(id_, "tool_transport_failure")
            try:
                reply_kind, payload = checked_tool_reply(reply, tool=self.available[name])
            except ValueError:
                # The side effect may already have happened. Do not present a
                # malformed reply as success; leave explicit uncertain evidence.
                self._record(name, binding, effect, "invalid_backend_result_side_effect_possible", action_id=action_id)
                return error(id_, "backend_result_unverified_side_effect_possible")
            if reply_kind == "rpc_error":
                outcome = "backend_rpc_error"
                result = {"jsonrpc": "2.0", "id": id_, "error": payload}
            else:
                outcome = "backend_reported_error" if payload.get("isError") is True else "backend_reported_result"
                result = {"jsonrpc": "2.0", "id": id_, "result": payload}
            verifier = self.policy.postconditions.get(name)
            if verifier and outcome == "backend_reported_result":
                try:
                    verified = verifier.verify(args)
                except (OSError, ValueError) as exc:
                    verified = {"verified": False, "reason": type(exc).__name__ + ":" + str(exc)}
                self.state.append({"at": int(time.time()), "agent_id": self.policy.agent_id,
                    "tool": name, "binding": binding, "decision": effect,
                    "policy_hash": self.policy.source_hash, "outcome": "postcondition_checked",
                    "action_id": action_id, "verification": verified})
                if not verified["verified"]:
                    self._record(name, binding, effect, "postcondition_failed_side_effect_possible", action_id=action_id)
                    return error(id_, "postcondition_failed_side_effect_possible")
            self._record(name, binding, effect, outcome, action_id=action_id)
            return result
        except (RuntimeError, TimeoutError, ValueError, OSError) as exc:
            # Do not attempt an impossible audit append on a corrupt or
            # rolled-back ledger and then let that secondary failure leak.
            # No protected tool is dispatched when the integrity check fails.
            try:
                self._record(name, binding, "deny", f"preflight_failure:{type(exc).__name__}")
            except (RuntimeError, TimeoutError, ValueError, OSError):
                pass
            return error(id_, "preflight_failed")


def serve(policy: Policy, state: State, command: list[str], *, input_stream=None, output_stream=None,
          backend_user: str | None = None, allow_unsandboxed: bool = False,
          pass_env: tuple[str, ...] = (), workdir: Path | None = None) -> None:
    input_stream = input_stream or sys.stdin.buffer
    output_stream = output_stream or sys.stdout.buffer
    backend = SubprocessBackend(command, backend_user=backend_user, allow_unsandboxed=allow_unsandboxed,
                                pass_env=pass_env, workdir=workdir)
    gateway = Gateway(policy, state, backend)
    try:
        while True:
            line = input_stream.readline(MAX_WIRE_BYTES + 2)
            if not line:
                return
            try:
                msg = parse_json(line)
                response = gateway.handle(msg)
            except (ValueError, UnicodeError, json.JSONDecodeError, RecursionError):
                response = error(None, "malformed_or_oversized_request", -32700)
            if response is not None:
                out = json.dumps(response, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
                output_stream.write(out + b"\n")
                output_stream.flush()
    finally:
        backend.close()
