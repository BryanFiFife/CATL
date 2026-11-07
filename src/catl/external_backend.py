"""Explicitly supervised, distinct-UID MCP backend over Linux Unix sockets.

Trusted boundaries:
- Broker (no root privileges) authenticates backend using kernel SO_PEERCRED.
- Backend service only admits a peer with the configured broker UID.
- Each method is a bounded, single-request newline-delimited JSON-RPC exchange.
- Backend service must be independently launched under a restricted identity.

NOT a sandbox, not an external TCP listener, and not a production service manager.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import sys
import threading
from pathlib import Path
from typing import Any

from .broker import _peer_uid, _prepare_socket, _read_frame, _write_frame
from .crypto import MAX_WIRE_BYTES
from .gateway import Backend

ALLOWED_REQUEST_METHODS = frozenset({"initialize", "tools/list", "tools/call"})
ALLOWED_NOTIFICATION_METHODS = frozenset({"notifications/initialized"})


def _check_socket_path(path: Path) -> None:
    if sys.platform != "linux":
        raise PermissionError("external_backend_linux_only")
    if len(os.fsencode(path)) > 96:
        raise ValueError("unix_socket_path_too_long")
    if path.is_symlink() or not path.is_socket():
        raise PermissionError("backend_socket_missing_or_symlink")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise PermissionError("backend_socket_parent_invalid")
    st = parent.stat()
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError("backend_socket_parent_writable_by_others")
    if st.st_uid == os.geteuid():
        raise PermissionError("backend_socket_parent_must_be_separate_identity")


class SocketBackend:
    """Rootless broker client for an independently supervised tool service."""
    def __init__(self, path: Path, *, backend_uid: int, timeout: float = 15.0):
        if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
            raise PermissionError("external_backend_requires_linux_peercred")
        if type(backend_uid) is not int or backend_uid < 1 or backend_uid == os.geteuid():
            raise PermissionError("backend_uid_must_be_distinct_and_unprivileged")
        if not (0 < timeout <= 120):
            raise ValueError("invalid_backend_timeout")
        self.path = Path(path)
        self.backend_uid = backend_uid
        self.timeout = timeout
        self.seq = 0
        self._lock = threading.Lock()

    def _exchange(self, message: dict[str, Any], *, expect_response: bool) -> dict[str, Any] | None:
        _check_socket_path(self.path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout)
            conn.connect(str(self.path))
            if _peer_uid(conn) != self.backend_uid:
                raise PermissionError("backend_peer_uid_mismatch")
            with conn.makefile("rwb", buffering=0) as stream:
                _write_frame(stream, message)
                if not expect_response:
                    return None
                reply = _read_frame(stream)
                if not isinstance(reply, dict) or reply.get("jsonrpc") != "2.0" or reply.get("id") != message["id"]:
                    raise PermissionError("backend_response_invalid_or_wrong_id")
                if ("result" in reply) == ("error" in reply):
                    raise PermissionError("backend_response_ambiguous")
                return reply

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if method not in ALLOWED_REQUEST_METHODS:
            raise PermissionError("backend_method_not_allowed")
        with self._lock:
            self.seq += 1
            msg = {"jsonrpc": "2.0", "id": f"catl-external-{self.seq}", "method": method}
            if params is not None:
                msg["params"] = params
            response = self._exchange(msg, expect_response=True)
            assert response is not None
            return response

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        if method not in ALLOWED_NOTIFICATION_METHODS:
            raise PermissionError("backend_notification_not_allowed")
        with self._lock:
            msg = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                msg["params"] = params
            self._exchange(msg, expect_response=False)

    def close(self) -> None:
        return


def validate_service_environment(path: Path, *, broker_uid: int, broker_gid: int) -> None:
    """Validate immutable startup preconditions BEFORE spawning a tool subprocess."""
    if sys.platform != "linux" or os.geteuid() == 0:
        raise PermissionError("backend_service_requires_unprivileged_linux_identity")
    if type(broker_uid) is not int or broker_uid < 1 or broker_uid == os.geteuid():
        raise PermissionError("backend_service_broker_uid_invalid")
    if type(broker_gid) is not int or broker_gid < 1 or broker_gid not in {*os.getgroups(), os.getegid()}:
        raise PermissionError("backend_service_must_belong_to_broker_ipc_group")
    path = Path(path)
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise PermissionError("backend_service_socket_directory_invalid")
    st = parent.stat()
    if st.st_uid != os.geteuid() or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError("backend_service_socket_directory_not_protected")
    if path.exists() or path.is_symlink():
        raise FileExistsError("backend_service_socket_path_already_exists")


class BackendService:
    """Runs as distinct, unprivileged TOOL UID, with no broker secrets available."""
    def __init__(self, backend: Backend, path: Path, *, broker_uid: int, broker_gid: int):
        validate_service_environment(path, broker_uid=broker_uid, broker_gid=broker_gid)
        self.backend = backend
        self.path = Path(path)
        self.broker_uid = broker_uid
        self.broker_gid = broker_gid
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.sock: socket.socket | None = None

    def _client(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(30)
            if _peer_uid(conn) != self.broker_uid:
                return
            with conn.makefile("rwb", buffering=0) as stream:
                msg = _read_frame(stream)
                if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
                    return
                method = msg.get("method")
                if not isinstance(method, str):
                    return
                if "id" not in msg:
                    if method in ALLOWED_NOTIFICATION_METHODS:
                        with self.lock:
                            self.backend.notify(method, msg.get("params"))
                    return
                req_id = msg["id"]
                if method not in ALLOWED_REQUEST_METHODS:
                    _write_frame(stream, {"jsonrpc": "2.0", "id": req_id, "error": {
                        "code": -32601, "message": "backend_method_denied"}})
                    return
                with self.lock:
                    try:
                        response = self.backend.request(method, msg.get("params"))
                        if not isinstance(response, dict) or ("result" in response) == ("error" in response):
                            raise ValueError("underlying_backend_invalid_reply")
                        reply = {"jsonrpc": "2.0", "id": req_id}
                        if "error" in response:
                            reply["error"] = response["error"]
                        else:
                            reply["result"] = response["result"]
                    except (OSError, ValueError, RuntimeError, TimeoutError, PermissionError, TypeError):
                        reply = {"jsonrpc": "2.0", "id": req_id, "error": {
                            "code": -32603, "message": "backend_execution_rejected"}}
                    _write_frame(stream, reply)
        except (OSError, ValueError, PermissionError, TypeError):
            return
        finally:
            conn.close()

    def serve(self) -> None:
        # Group-access socket: service cannot change UID and must be a member
        # of the broker's shared IPC group. SO_PEERCRED still checks exact UID.
        sock = _prepare_socket(self.path, os.geteuid(), self.broker_gid, group_access=True)
        self.sock = sock
        try:
            while not self.stop.is_set():
                try:
                    conn, _addr = sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self._client(conn)  # deliberately serial, bounded connection timeout
        finally:
            self.stop.set()
            sock.close()
            if self.path.is_socket() and self.path.stat().st_uid == os.geteuid():
                self.path.unlink()

    def shutdown(self) -> None:
        self.stop.set()
        if self.sock is not None:
            self.sock.close()
