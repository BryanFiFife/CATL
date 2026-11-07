"""SQLite approval state and keyed, linked execution receipts.

HMAC detects offline tampering when the key is protected; no external anchoring is claimed.
"""
from __future__ import annotations
import hmac
import json
import os
import stat
import secrets
import sqlite3
import time
from pathlib import Path
from contextlib import closing, contextmanager
from typing import Any
from .crypto import digest, hmac_hex
from .controls import DEFAULT, TOGGLES, encode, decode
from .anchor import AnchorGuard

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
 id TEXT PRIMARY KEY, binding TEXT NOT NULL, status TEXT NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 detail TEXT NOT NULL, approved_by TEXT, used_at INTEGER,
 request_mac TEXT, decision_mac TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_binding ON approvals(binding, status);
CREATE TABLE IF NOT EXISTS receipts (
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 body TEXT NOT NULL, previous TEXT NOT NULL, mac TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operator_controls (
 id INTEGER PRIMARY KEY CHECK(id = 1), body TEXT NOT NULL, mac TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_rate (
 agent_id TEXT NOT NULL, tool TEXT NOT NULL, window INTEGER NOT NULL,
 count INTEGER NOT NULL, PRIMARY KEY(agent_id, tool)
);
"""


def binding_hash(agent: str, tool: str, args: dict[str, Any], pin: str, policy_hash: str) -> str:
    return digest({"agent": agent, "tool": tool, "arguments": args, "pin": pin, "policy_hash": policy_hash})


class State:
    def __init__(self, db_path: Path, key: bytes, *, anchor_path: Path | None = None):
        self.path = db_path
        self.key = key
        self.anchor = AnchorGuard(anchor_path, key) if anchor_path is not None else None
        if db_path.parent.is_symlink():
            raise PermissionError("state_directory_symlink_refused")
        db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            parent_info = db_path.parent.stat()
            if parent_info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise PermissionError("state_directory_permissions_too_open")
            if parent_info.st_uid != os.geteuid():
                raise PermissionError("state_directory_not_owned_by_supervisor")
        created = not db_path.exists()
        if created:
            fd = os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(fd)
        if os.name == "posix":
            db_info = db_path.stat()
            if db_info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise PermissionError("database_permissions_too_open")
            if db_info.st_uid != os.geteuid():
                raise PermissionError("database_not_owned_by_supervisor")
        if db_path.is_symlink():
            raise PermissionError("refusing_symlink_db")
        with closing(self._conn()) as db:
            db.executescript(SCHEMA)
            # Upgrade earlier databases without granting existing pending approvals.
            columns = {row[1] for row in db.execute("PRAGMA table_info(approvals)")}
            for column in ("request_mac", "decision_mac"):
                if column not in columns:
                    db.execute(f"ALTER TABLE approvals ADD COLUMN {column} TEXT")
            present = db.execute("SELECT 1 FROM operator_controls WHERE id=1").fetchone()
            if not present:
                # A v0.2 migration or a deleted control row fails closed.
                baseline = dict(DEFAULT)
                # A new or reconstructed database must never silently re-arm.
                # Operator confirmation is required even on the first launch.
                baseline["gateway_enabled"] = False
                body, mac = encode(baseline, self.key)
                db.execute("INSERT INTO operator_controls(id,body,mac) VALUES(1,?,?)", (body, mac))

    def _conn(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def _verified_head(self, db: sqlite3.Connection) -> tuple[int, str]:
        """Reverify the ENTIRE receipt chain before trusting an anchored head."""
        # Stream rather than materialise the entire ledger in RAM. A long-running
        # agent may have millions of receipts; full-memory fetch was a local DoS.
        previous = "GENESIS"
        count = 0
        for count, (seq, body, prev, mac) in enumerate(
                db.execute("SELECT seq,body,previous,mac FROM receipts ORDER BY seq"), 1):
            expected = hmac_hex(self.key, {"body": body, "previous": previous})
            if seq != count or prev != previous or not hmac.compare_digest(expected, mac):
                raise PermissionError("receipt_chain_integrity_invalid")
            previous = mac
        return count, previous

    @staticmethod
    def _last_control_digest(db: sqlite3.Connection) -> str | None:
        """A row-level replay of a previously signed control document must fail."""
        for (body,) in db.execute("SELECT body FROM receipts ORDER BY seq DESC"):
            event = json.loads(body)
            if event.get("decision") == "operator_control_change":
                return event.get("after")
        return None

    @staticmethod
    def _approval_history(db: sqlite3.Connection, identifier: str, wanted: set[str]) -> bool:
        """Receipt-history fence against rewinding one SQLite approval row."""
        for (body,) in db.execute("SELECT body FROM receipts ORDER BY seq DESC"):
            event = json.loads(body)
            if event.get("request_id") == identifier and event.get("decision") in wanted:
                return True
        return False

    def assert_anchor(self) -> None:
        if self.anchor is None:
            # Demo/legacy mode still authenticates the ledger even though it
            # cannot detect valid truncated tails without an independent head.
            with closing(self._conn()) as db:
                self._verified_head(db)
            return
        with self.anchor.locked():
            with closing(self._conn()) as db:
                head = self._verified_head(db)
                self.anchor.assert_head(*head)

    @contextmanager
    def _receipt_change(self):
        """Commit receipt and advance external checkpoint; crash gaps fail closed.

        Never auto-heal an anchor mismatch: a trusted operator must investigate.
        This is a single-writer transaction protocol for local POSIX brokers.
        """
        if self.anchor is not None:
            with self.anchor.locked():
                with closing(self._conn()) as db:
                    db.execute("BEGIN IMMEDIATE")
                    self.anchor.assert_head(*self._verified_head(db))
                    try:
                        yield db
                    except BaseException:
                        db.rollback()
                        raise
                    db.commit()
                    self.anchor.advance(*self._verified_head(db))
        else:
            with closing(self._conn()) as db:
                db.execute("BEGIN IMMEDIATE")
                self._verified_head(db)  # never treat unsigned mutable rows as authority
                try:
                    yield db
                except BaseException:
                    db.rollback()
                    raise
                db.commit()

    def request(self, binding: str, detail: dict[str, Any], ttl: int = 300) -> str:
        if not (1 <= ttl <= 3600):
            raise ValueError("ttl_invalid")
        detail_json = json.dumps(detail, sort_keys=True, ensure_ascii=False, allow_nan=False)
        if len(detail_json.encode("utf-8")) > 16384:
            raise ValueError("approval_details_too_large")
        identifier = secrets.token_urlsafe(18)
        now = int(time.time())
        with self._receipt_change() as db:
            prior = db.execute("SELECT id FROM approvals WHERE binding=? AND status='pending' AND expires_at>? ORDER BY created_at LIMIT 1", (binding, now)).fetchone()
            if prior:
                return prior[0]
            count = db.execute("SELECT count(*) FROM approvals WHERE status='pending' AND expires_at>?", (now,)).fetchone()[0]
            if count >= 100:
                raise ValueError("approval_queue_full")
            request_mac = hmac_hex(self.key, {"domain": "CATL/APPROVAL-REQUEST/v1", "id": identifier,
                "binding": binding, "created_at": now, "expires_at": now + ttl, "detail": detail_json})
            db.execute("INSERT INTO approvals(id,binding,status,created_at,expires_at,detail,request_mac) VALUES(?,?,?,?,?,?,?)",
                       (identifier, binding, "pending", now, now + ttl, detail_json, request_mac))
            self._append_tx(db, {"at": now, "decision": "approval_requested", "request_id": identifier,
                "binding": binding, "detail_digest": digest(detail)})
        return identifier

    def list_pending(self) -> list[dict[str, Any]]:
        self.assert_anchor()
        with closing(self._conn()) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT id,binding,created_at,expires_at,detail,request_mac FROM approvals WHERE status='pending' AND expires_at>? ORDER BY created_at", (int(time.time()),)).fetchall()
            result = []
            for row in rows:
                expected = hmac_hex(self.key, {"domain": "CATL/APPROVAL-REQUEST/v1", "id": row["id"],
                    "binding": row["binding"], "created_at": row["created_at"],
                    "expires_at": row["expires_at"], "detail": row["detail"]})
                if not row["request_mac"] or not hmac.compare_digest(row["request_mac"], expected):
                    raise PermissionError("pending_approval_integrity_invalid")
                result.append({k: row[k] for k in ("id", "binding", "created_at", "expires_at")} |
                              {"detail": json.loads(row["detail"])})
            return result

    def decide(self, identifier: str, user: str, approve: bool) -> bool:
        if not user.strip() or len(user) > 128:
            raise ValueError("invalid_approver")
        with self._receipt_change() as db:
            row = db.execute("SELECT binding,created_at,expires_at,detail,request_mac FROM approvals WHERE id=? AND status='pending' AND expires_at>?",
                             (identifier, int(time.time()))).fetchone()
            if row is None:
                return False
            if self._approval_history(db, identifier, {"approval_decided", "approval_consumed"}):
                raise PermissionError("approval_decision_replay_detected")
            binding, created_at, expires_at, detail, request_mac = row
            expected = hmac_hex(self.key, {"domain": "CATL/APPROVAL-REQUEST/v1", "id": identifier,
                "binding": binding, "created_at": created_at, "expires_at": expires_at, "detail": detail})
            if not request_mac or not hmac.compare_digest(request_mac, expected):
                raise PermissionError("approval_request_tampered")
            status = "approved" if approve else "rejected"
            decision_mac = hmac_hex(self.key, {"domain": "CATL/APPROVAL-DECISION/v1", "id": identifier,
                "binding": binding, "created_at": created_at, "expires_at": expires_at,
                "detail": detail, "approved_by": user, "status": status})
            result = db.execute("UPDATE approvals SET status=?, approved_by=?, decision_mac=? WHERE id=? AND status='pending'",
                                (status, user, decision_mac, identifier))
            if result.rowcount == 1:
                self._append_tx(db, {"at": int(time.time()), "decision": "approval_decided",
                    "request_id": identifier, "binding": binding, "outcome": status, "operator": user})
            return result.rowcount == 1

    def consume(self, binding: str) -> bool:
        with self._receipt_change() as db:
            row = db.execute("SELECT id,binding,created_at,expires_at,detail,approved_by,request_mac,decision_mac FROM approvals WHERE binding=? AND status='approved' AND expires_at>? ORDER BY created_at, id LIMIT 1", (binding, int(time.time()))).fetchone()
            if row is None:
                return False
            identifier, row_binding, created_at, expires_at, detail, approver, request_mac, decision_mac = row
            if self._approval_history(db, identifier, {"approval_consumed"}):
                raise PermissionError("approval_consumption_replay_detected")
            request_expected = hmac_hex(self.key, {"domain": "CATL/APPROVAL-REQUEST/v1", "id": identifier,
                "binding": row_binding, "created_at": created_at, "expires_at": expires_at, "detail": detail})
            decision_expected = hmac_hex(self.key, {"domain": "CATL/APPROVAL-DECISION/v1", "id": identifier,
                "binding": row_binding, "created_at": created_at, "expires_at": expires_at,
                "detail": detail, "approved_by": approver, "status": "approved"})
            if not (request_mac and decision_mac and hmac.compare_digest(request_mac, request_expected)
                    and hmac.compare_digest(decision_mac, decision_expected)):
                raise PermissionError("approval_integrity_invalid")
            result = db.execute("UPDATE approvals SET status='used',used_at=? WHERE id=? AND status='approved'", (int(time.time()), identifier))
            if result.rowcount == 1:
                self._append_tx(db, {"at": int(time.time()), "decision": "approval_consumed",
                    "request_id": identifier, "binding": binding})
            return result.rowcount == 1


    def acquire_rate(self, agent: str, tool: str, maximum_per_minute: int) -> bool:
        """Authenticated fixed-window throttle, derived from the anchored ledger.

        The legacy `tool_rate` SQLite table is intentionally ignored: unlike
        signed receipts, a mutable unkeyed counter can be rewound offline.
        Every granted slot is a signed, anchored receipt, including when a
        caller later fails to execute, to prevent quota-replay after crashes.
        """
        if type(maximum_per_minute) is not int or not 1 <= maximum_per_minute <= 600:
            raise ValueError("rate_limit_invalid")
        if not isinstance(agent, str) or not agent or not isinstance(tool, str) or not tool:
            raise ValueError("rate_identity_invalid")
        window = int(time.time()) // 60
        with self._receipt_change() as db:
            used = 0
            for (body,) in db.execute("SELECT body FROM receipts ORDER BY seq DESC"):
                event = json.loads(body)
                if (event.get("decision") == "rate_permit" and
                        event.get("agent_id") == agent and event.get("tool") == tool and
                        event.get("window") == window):
                    used += 1
                    if used >= maximum_per_minute:
                        return False
            self._append_tx(db, {"at": int(time.time()), "decision": "rate_permit",
                                 "agent_id": agent, "tool": tool, "window": window})
            return True


    def controls(self) -> dict[str, Any]:
        """Read and authenticate current operator controls on *each* protected call."""
        self.assert_anchor()
        with closing(self._conn()) as db:
            row = db.execute("SELECT body,mac FROM operator_controls WHERE id=1").fetchone()
            if row is None:
                raise PermissionError("controls_missing")
            document = decode(row[0], row[1], self.key)
            after = self._last_control_digest(db)
            if after is not None and after != digest(document):
                raise PermissionError("signed_control_rollback_detected")
            return document

    def _update_control(self, actor: str, mutate) -> dict[str, Any]:
        if not isinstance(actor, str) or not actor.strip() or len(actor) > 128:
            raise ValueError("invalid_operator_identity")
        with self._receipt_change() as db:
            row = db.execute("SELECT body,mac FROM operator_controls WHERE id=1").fetchone()
            if row is None:
                raise PermissionError("controls_missing")
            current = decode(row[0], row[1], self.key)
            after = self._last_control_digest(db)
            if after is not None and after != digest(current):
                raise PermissionError("signed_control_rollback_detected")
            revised = mutate({**current, "disabled_tools": list(current["disabled_tools"])})
            body, mac = encode(revised, self.key)
            db.execute("UPDATE operator_controls SET body=?,mac=? WHERE id=1", (body, mac))
            self._append_tx(db, {"at": int(time.time()), "agent_id": "OPERATOR",
                "decision": "operator_control_change", "actor": actor,
                "before": digest(current), "after": digest(revised)})
        return revised

    def set_feature(self, name: str, enabled: bool, actor: str) -> dict[str, Any]:
        if name not in TOGGLES or type(enabled) is not bool:
            raise ValueError("feature_invalid")
        def change(doc: dict[str, Any]) -> dict[str, Any]:
            doc[name] = enabled
            return doc
        return self._update_control(actor, change)

    def set_tool(self, tool: str, enabled: bool, actor: str, permitted_tools: set[str]) -> dict[str, Any]:
        if tool not in permitted_tools or type(enabled) is not bool:
            raise ValueError("tool_control_invalid")
        def change(doc: dict[str, Any]) -> dict[str, Any]:
            disabled = set(doc["disabled_tools"])
            if enabled:
                disabled.discard(tool)
            else:
                disabled.add(tool)
            doc["disabled_tools"] = sorted(disabled)
            return doc
        return self._update_control(actor, change)

    def set_all_tools(self, enabled: bool, actor: str, permitted_tools: set[str]) -> dict[str, Any]:
        if type(enabled) is not bool or len(permitted_tools) > 128 or any(not isinstance(x,str) for x in permitted_tools):
            raise ValueError("tool_control_invalid")
        def change(doc: dict[str, Any]) -> dict[str, Any]:
            disabled = set(doc["disabled_tools"])
            if enabled:
                disabled.difference_update(permitted_tools)
            else:
                disabled.update(permitted_tools)
            doc["disabled_tools"] = sorted(disabled)
            return doc
        return self._update_control(actor, change)

    def _append_tx(self, db: sqlite3.Connection, data: dict[str, Any]) -> str:
        body = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        row = db.execute("SELECT mac FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()
        previous = row[0] if row else "GENESIS"
        mac = hmac_hex(self.key, {"body": body, "previous": previous})
        db.execute("INSERT INTO receipts(body,previous,mac) VALUES(?,?,?)", (body, previous, mac))
        return mac

    def append(self, data: dict[str, Any]) -> str:
        with self._receipt_change() as db:
            mac = self._append_tx(db, data)
        return mac

    def verify(self) -> dict[str, Any]:
        try:
            with closing(self._conn()) as db:
                count, head = self._verified_head(db)
            if self.anchor is not None:
                self.assert_anchor()
            return {"valid": True, "count": count, "head_mac": head,
                    "externally_anchored": self.anchor is not None}
        except (ValueError, PermissionError, OSError) as exc:
            return {"valid": False, "reason": str(exc)}
