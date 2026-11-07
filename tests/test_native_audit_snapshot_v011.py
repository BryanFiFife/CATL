"""Native CATL State.verify consistency and single-scan security regressions.

These tests are intended to run in the complete CATL source checkout with
`PYTHONPATH=src python -m unittest tests/test_native_audit_snapshot_v011.py`.
Do not call the isolated reference tests a native full-suite pass.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from catl.anchor import AnchorGuard
from catl.store import State


@unittest.skipUnless(os.name == "posix", "POSIX anchor locking required")
class TestNativeVerifiedSnapshot(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="catl-snapshot-")
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        state_dir = base / "state"
        anchor_dir = base / "anchor"
        anchor_dir.mkdir(mode=0o700)
        self.key = b"V" * 32
        self.db_file = state_dir / "audit.sqlite3"
        self.anchor_file = anchor_dir / "head.json"
        original = State(self.db_file, self.key)
        initial = original.verify()
        self.assertTrue(initial["valid"])
        AnchorGuard(self.anchor_file, self.key).bootstrap(initial["count"], initial["head_mac"])
        self.state = State(self.db_file, self.key, anchor_path=self.anchor_file)

    def test_verify_scans_entire_chain_once(self):
        self.state.append({"decision": "test", "seq": 1})
        self.state.append({"decision": "test", "seq": 2})
        original = self.state._verified_head
        with patch.object(self.state, "_verified_head", wraps=original) as counted:
            result = self.state.verify()
        self.assertTrue(result["valid"], result)
        self.assertEqual(counted.call_count, 1, "verify must not rescan the receipt chain")
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["head_mac"], AnchorGuard(self.anchor_file, self.key).read()["receipt_head_mac"])

    def test_verify_holds_anchor_lock_across_receipt_scan(self):
        self.state.append({"decision": "baseline"})
        entered = threading.Event()
        release = threading.Event()
        append_finished = threading.Event()
        append_started = threading.Event()
        errors: list[str] = []
        results: list[dict] = []
        original = self.state._verified_head

        def blocking_scan(db):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("fixture_timeout")
            return original(db)

        def reader():
            try:
                results.append(self.state.verify())
            except BaseException as exc:
                errors.append(str(exc))

        def writer():
            try:
                append_started.set()
                self.state.append({"decision": "concurrent_write"})
            except BaseException as exc:
                errors.append(str(exc))
            finally:
                append_finished.set()

        with patch.object(self.state, "_verified_head", side_effect=blocking_scan):
            reader_thread = threading.Thread(target=reader)
            writer_thread = threading.Thread(target=writer)
            reader_thread.start()
            try:
                self.assertTrue(entered.wait(3), "verify scan did not start")
                writer_thread.start()
                self.assertTrue(append_started.wait(3), "writer did not attempt append")
                self.assertFalse(append_finished.wait(0.1), "writer passed the anchor lock during verification")
            finally:
                release.set()
                reader_thread.join(5)
                if writer_thread.ident is not None:
                    writer_thread.join(5)
        self.assertFalse(reader_thread.is_alive())
        self.assertFalse(writer_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["valid"], results[0])
        self.assertEqual(results[0]["count"], 1)
        self.assertEqual(self.state.verify()["count"], 2)

    def test_anchor_mismatch_invalidates_verification(self):
        self.state.append({"decision": "baseline"})
        self.anchor_file.unlink()
        self.assertFalse(self.state.verify()["valid"])

    def test_sqlite_failure_returns_invalid_not_uncaught_exception(self):
        with patch.object(self.state, "_conn", side_effect=sqlite3.DatabaseError("injected_io_error")):
            result = self.state.verify()
        self.assertFalse(result["valid"])
        self.assertIn("injected_io_error", result["reason"])

    def test_no_anchor_is_explicitly_reported(self):
        unanchored = State(self.db_file, self.key)
        result = unanchored.verify()
        self.assertTrue(result["valid"])
        self.assertFalse(result["externally_anchored"])


if __name__ == "__main__":
    unittest.main()
