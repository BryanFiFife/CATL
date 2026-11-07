"""Linux-only, identity-pinned local broker with distinct agent/operator sockets.

The broker owns policy, database, HMAC key, and backend process. Its agent socket
exposes ONLY the MCP JSON-RPC gateway. The operator socket exposes an explicit,
small control API. Both channels validate kernel-reported peer UID.

This does NOT constitute a sandbox for arbitrary code on the same host. Deploy
with separate OS identities and enforce filesystem/network restrictions outside
CATL. No TCP listener, browser-origin approval, or remote updater is provided.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import struct
import sys
import threading
from pathlib import Path
from typing import Any

from .crypto import MAX_WIRE_BYTES, parse_json
from .gateway import Gateway
from .policy import Policy
from .store import State

MAX_CLIENTS = 16


def _peer_uid(conn: socket.socket) -> int:
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise PermissionError("broker_peer_auth_linux_only")
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def _prepare_socket(path: Path, uid: int, gid: int, *, group_access: bool = False) -> socket.socket:
    path = Path(path)
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise PermissionError("socket_parent_invalid")
    info = parent.stat()
    if info.st_mode & (stat.S_IWOTH | stat.S_IWGRP):
        raise PermissionError("socket_parent_writable_by_others")
    if info.st_uid != os.geteuid():
        raise PermissionError("socket_parent_not_owned_by_service")
    if not (0 <= uid <= 2**31 - 1 and 0 <= gid <= 2**31 - 1):
        raise ValueError("socket_identity_invalid")
    if group_access:
        if uid != os.geteuid():
            raise PermissionError("group_access_socket_must_remain_service_owned")
        if gid not in {*os.getgroups(), os.getegid()}:
            raise PermissionError("service_not_member_of_socket_group")
    elif os.geteuid() != 0 and uid != os.geteuid():
        raise PermissionError("socket_uid_change_requires_privileged_setup")
    if path.exists() or path.is_symlink():
        raise FileExistsError("socket_path_already_exists_refusing_unlink")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(path))
        os.chown(path, -1 if group_access else uid, gid)
        os.chmod(path, 0o660 if group_access else 0o600)
        # Exact peer UID is checked for every connection; group alone is not authority.
        sock.listen(MAX_CLIENTS)
        sock.settimeout(0.2)
        return sock
    except BaseException:
        sock.close()
        if path.is_socket():
            path.unlink()
        raise


def _read_frame(stream) -> dict[str, Any] | None:
    raw = stream.readline(MAX_WIRE_BYTES + 2)
    if not raw:
        return None
    return parse_json(raw)


def _write_frame(stream, message: dict[str, Any]) -> None:
    payload = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(payload) > MAX_WIRE_BYTES:
        raise ValueError("broker_response_too_large")
    stream.write(payload + b"\n")
    stream.flush()


class BrokerServer:
    def __init__(self, gateway: Gateway, state: State, policy: Policy, *, agent_socket: Path,
                 operator_socket: Path, agent_uid: int, operator_uid: int,
                 allow_test_same_uid: bool = False, agent_gid: int | None = None,
                 operator_gid: int | None = None):
        if sys.platform != "linux":
            raise PermissionError("broker_requires_linux_so_peercred")
        current_uid = os.geteuid()
        if not allow_test_same_uid and len({agent_uid, operator_uid, current_uid}) != 3:
            raise PermissionError("broker_agent_and_operator_must_have_distinct_uids")
        if agent_uid == operator_uid:
            raise PermissionError("agent_cannot_be_operator")
        if Path(agent_socket).resolve() == Path(operator_socket).resolve():
            raise ValueError("broker_channels_must_be_distinct")
        if state.anchor is None and not allow_test_same_uid:
            raise PermissionError("anchored_broker_state_required")
        self.gateway = gateway
        self.state = state
        self.policy = policy
        self.agent_socket = Path(agent_socket)
        self.operator_socket = Path(operator_socket)
        self.agent_uid = agent_uid
        self.operator_uid = operator_uid
        if (agent_gid is None) != (operator_gid is None):
            raise ValueError("both_channel_groups_are_required")
        if os.geteuid() != 0 and agent_gid is None and not allow_test_same_uid:
            raise PermissionError("rootless_broker_requires_group_access_sockets")
        if agent_gid is not None and (agent_gid == operator_gid or agent_gid < 1 or operator_gid < 1):
            raise PermissionError("agent_and_operator_socket_groups_must_differ")
        self.agent_gid, self.operator_gid = agent_gid, operator_gid
        self.stop = threading.Event()
        self._gate_lock = threading.RLock()  # backend is serial, never multiplex unguarded
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []

    def _op(self, msg: dict[str, Any], uid: int) -> dict[str, Any]:
        name = msg.get("op")
        actor = f"uid:{uid}"
        if not isinstance(name, str) or len(json.dumps(msg, ensure_ascii=False)) > 65536:
            raise ValueError("invalid_operator_request")
        if name == "status":
            return {"controls": self.state.controls(), "tools": sorted(self.policy.tool_pins),
                    "audit": self.state.verify(), "protocol": "CATL/OPERATOR/v1"}
        if name == "pending":
            return {"requests": self.state.list_pending()}
        if name == "verify":
            return self.state.verify()
        if name == "set_feature":
            return {"controls": self.state.set_feature(msg.get("feature"), msg.get("enabled"), actor)}
        if name == "set_tool":
            return {"controls": self.state.set_tool(msg.get("tool"), msg.get("enabled"), actor,
                      set(self.policy.tool_pins))}
        if name == "set_all_tools":
            return {"controls": self.state.set_all_tools(msg.get("enabled"), actor,
                      set(self.policy.tool_pins))}
        if name == "decide":
            identifier, approve = msg.get("id"), msg.get("approve")
            if not isinstance(identifier, str) or len(identifier) > 128 or type(approve) is not bool:
                raise ValueError("decision_invalid")
            return {"accepted": self.state.decide(identifier, actor, approve)}
        raise ValueError("operator_operation_denied")

    def _client(self, conn: socket.socket, role: str) -> None:
        try:
            conn.settimeout(10)
            uid = _peer_uid(conn)
            expected_uid = self.agent_uid if role == "agent" else self.operator_uid
            if uid != expected_uid:
                return
            if role == "agent":
                conn.settimeout(45)  # bound idle client/flood resource use
            with conn.makefile("rwb", buffering=0) as stream:
                if role == "operator":
                    try:
                        msg = _read_frame(stream)
                        if msg is None:
                            return
                        result = self._op(msg, uid)
                        _write_frame(stream, {"ok": True, "result": result})
                    except (OSError, ValueError, PermissionError, TypeError, RecursionError) as exc:
                        _write_frame(stream, {"ok": False, "error": type(exc).__name__ + ":" + str(exc)[:120]})
                    return
                while not self.stop.is_set():
                    try:
                        msg = _read_frame(stream)
                        if msg is None:
                            return
                        with self._gate_lock:
                            result = self.gateway.handle(msg)
                        if result is not None:
                            _write_frame(stream, result)
                    except (OSError, ValueError, PermissionError, TypeError, RecursionError) as exc:
                        try:
                            _write_frame(stream, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32603, "message": "broker_request_rejected"}})
                        except OSError:
                            return
        except (OSError, PermissionError):
            return
        finally:
            conn.close()

    def _accept_loop(self, sock: socket.socket, role: str) -> None:
        while not self.stop.is_set():
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            # Avoid creating unbounded threads on a local connection flood.
            self._threads = [t for t in self._threads if t.is_alive()]
            if len(self._threads) >= MAX_CLIENTS:
                conn.close()
                continue
            t = threading.Thread(target=self._client, args=(conn, role), daemon=True)
            self._threads.append(t)
            t.start()

    def serve(self) -> None:
        agent_sock: socket.socket | None = None
        operator_sock: socket.socket | None = None
        try:
            self.state.assert_anchor()
            agent_sock = _prepare_socket(self.agent_socket,
                   os.geteuid() if self.agent_gid is not None else self.agent_uid,
                   self.agent_gid if self.agent_gid is not None else os.getegid(),
                   group_access=self.agent_gid is not None)
            operator_sock = _prepare_socket(self.operator_socket,
                   os.geteuid() if self.operator_gid is not None else self.operator_uid,
                   self.operator_gid if self.operator_gid is not None else os.getegid(),
                   group_access=self.operator_gid is not None)
            self._sockets = [agent_sock, operator_sock]
            threads = [threading.Thread(target=self._accept_loop, args=(agent_sock, "agent"), daemon=True),
                       threading.Thread(target=self._accept_loop, args=(operator_sock, "operator"), daemon=True)]
            for t in threads:
                t.start()
            self._threads.extend(threads)
            while not self.stop.wait(0.2):
                pass
        finally:
            self.stop.set()
            for sock in self._sockets:
                sock.close()
            for path in (self.agent_socket, self.operator_socket):
                # The path is an operator-controlled install surface; never unlink non-sockets.
                if path.is_socket():
                    path.unlink()

    def shutdown(self) -> None:
        self.stop.set()
        for sock in self._sockets:
            sock.close()


def _exchange(sock_path: Path, payload: dict[str, Any], timeout: float = 10) -> dict[str, Any]:
    if sys.platform != "linux":
        raise PermissionError("broker_client_linux_only")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(sock_path))
        with sock.makefile("rwb", buffering=0) as stream:
            _write_frame(stream, payload)
            result = _read_frame(stream)
            if result is None:
                raise PermissionError("broker_peer_or_response_rejected")
            return result


class OperatorClient:
    """Thin trusted GUI client; never opens the database or HMAC key."""
    def __init__(self, socket_path: Path):
        self.socket_path = Path(socket_path)

    def _rpc(self, command: dict[str, Any]) -> dict[str, Any]:
        reply = _exchange(self.socket_path, command)
        if reply.get("ok") is not True:
            raise PermissionError("broker_" + str(reply.get("error", "rejected")))
        return reply["result"]

    def status(self) -> dict[str, Any]:
        return self._rpc({"op": "status"})

    def controls(self) -> dict[str, Any]:
        return self.status()["controls"]

    def list_pending(self) -> list[dict[str, Any]]:
        return self._rpc({"op": "pending"})["requests"]

    def verify(self) -> dict[str, Any]:
        return self._rpc({"op": "verify"})

    def set_feature(self, name: str, enabled: bool, _actor: str) -> dict[str, Any]:
        return self._rpc({"op": "set_feature", "feature": name, "enabled": enabled})["controls"]

    def set_tool(self, tool: str, enabled: bool, _actor: str, _tools: set[str]) -> dict[str, Any]:
        return self._rpc({"op": "set_tool", "tool": tool, "enabled": enabled})["controls"]

    def set_all_tools(self, enabled: bool, _actor: str, _tools: set[str]) -> dict[str, Any]:
        return self._rpc({"op": "set_all_tools", "enabled": enabled})["controls"]

    def decide(self, identifier: str, _actor: str, approve: bool) -> bool:
        return self._rpc({"op": "decide", "id": identifier, "approve": approve})["accepted"]


def shim(socket_path: Path, input_stream=None, output_stream=None) -> None:
    """Keyless stdio bridge, one bounded AF_UNIX connection per MCP message.

    Never opens protected policy, supervisor key, or database. Connections do
    not remain idle indefinitely, reducing local socket-exhaustion exposure.
    """
    in_stream = input_stream or sys.stdin.buffer
    out_stream = output_stream or sys.stdout.buffer
    while True:
        line = in_stream.readline(MAX_WIRE_BYTES + 2)
        if not line:
            return
        msg = parse_json(line)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(45)
            sock.connect(str(socket_path))
            with sock.makefile("rwb", buffering=0) as channel:
                _write_frame(channel, msg)
                if "id" in msg:
                    response = _read_frame(channel)
                    if response is None:
                        raise RuntimeError("broker_disconnected")
                    _write_frame(out_stream, response)
