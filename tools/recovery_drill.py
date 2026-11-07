"""Isolated destructive recovery simulation: never touches a real CATL state.

Creates a fresh state in a tempfile directory, checkpoints it, uses SQLite's
backup API to capture a consistent earlier database image, then restores that
image after moving the independent anchor forward. A successful drill MUST
fail closed on the mismatched anchor, without resetting it automatically.
"""
from __future__ import annotations
import json
import secrets
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from catl.anchor import AnchorGuard
from catl.store import State


def drill() -> dict:
    with tempfile.TemporaryDirectory(prefix='catl-recovery-drill-') as tmp:
        root=Path(tmp)
        state_dir=root/'state';state_dir.mkdir(mode=0o700)
        anchor_dir=root/'anchor';anchor_dir.mkdir(mode=0o700)
        key=secrets.token_bytes(32)
        db_file=state_dir/'audit.sqlite3'
        anchor_file=anchor_dir/'head.json'
        bootstrap=State(db_file,key)
        initial=bootstrap.verify()
        AnchorGuard(anchor_file,key).bootstrap(initial['count'],initial['head_mac'])
        guarded=State(db_file,key,anchor_path=anchor_file)
        selfcheck=guarded.verify()
        if not selfcheck['valid']:
            raise RuntimeError('fresh_guarded_state_invalid')
        old_snapshot=root/'before.sqlite3'
        with closing(sqlite3.connect(db_file)) as source, closing(sqlite3.connect(old_snapshot)) as destination:
            source.backup(destination)
        guarded.set_feature('gateway_enabled',True,'recovery-drill')
        updated=guarded.verify()
        if not updated['valid'] or updated['count'] <= selfcheck['count']:
            raise RuntimeError('anchor_not_advanced')
        # Restore ONLY the database, exactly as a partial rollback attacker or
        # operator mistake might. Keep the independent checkpoint unchanged.
        with closing(sqlite3.connect(old_snapshot)) as source, closing(sqlite3.connect(db_file)) as destination:
            source.backup(destination)
        blocked=False
        try:
            guarded.assert_anchor()
        except PermissionError as exc:
            blocked=str(exc)=='audit_rollback_or_unanchored_commit'
        if not blocked:
            raise RuntimeError('CRITICAL: stale_database_was_accepted')
        return {'passed':True, 'scenario':'rollback_database_without_rewinding_independent_anchor',
                'initial_count':selfcheck['count'],'advanced_count':updated['count'],
                'restored_database_rejected':blocked,
                'host_claim':'none; synthetic isolated rehearsal only'}

if __name__=='__main__':
    print(json.dumps(drill(),indent=2,sort_keys=True))
