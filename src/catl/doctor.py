"""Explicit, non-remediating CATL Linux deployment preflight.

This inspects operator-provided paths only. It never creates missing state,
keys, checkpoints, users or sockets, and never starts an executable. Reading an
existing state through State may perform a compatible schema migration; run on
a backup or newly provisioned release candidate before using production state.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any

from .crypto import get_or_create_key
from .policy import Policy
from .store import State


def run_checks(*, config: Path, state_dir: Path, anchor_path: Path,
               agent_uid: int | None = None, operator_uid: int | None = None,
               backend_uid: int | None = None, strict: bool = False) -> dict[str, Any]:
    """Return machine-readable checks without printing secrets.

    `strict` treats warnings as an unsuccessful preflight. This check does not
    prove that a systemd service, Linux MAC policy or backend is sandboxed.
    """
    results: list[dict[str, str]] = []

    def add(name: str, status: str, detail: str) -> None:
        results.append({"check": name, "status": status, "detail": detail})

    if sys.platform != 'linux':
        add('operating_system', 'fail', 'protected broker requires Linux SO_PEERCRED')
    else:
        add('operating_system', 'pass', 'Linux kernel peer credentials available')

    from importlib.metadata import PackageNotFoundError, version
    try:
        installed = version('jsonschema')
        add('schema_dependency', 'pass' if installed == '4.26.0' else 'fail',
            f'jsonschema={installed}; expected pinned 4.26.0')
    except PackageNotFoundError:
        add('schema_dependency', 'fail', 'pinned jsonschema 4.26.0 is not installed')

    uid = os.geteuid() if hasattr(os, 'geteuid') else None
    if uid == 0:
        add('broker_identity', 'fail', 'normal operation must not run broker as root')
    else:
        add('broker_identity', 'pass', 'broker runs without root')

    identities = (uid, agent_uid, operator_uid, backend_uid)
    if any(type(x) is not int or x < 1 for x in identities):
        add('identity_separation', 'fail', 'specify distinct positive broker, agent, operator and backend UIDs')
    elif len(set(identities)) != 4:
        add('identity_separation', 'fail', 'broker, agent, operator and backend UIDs must all be distinct')
    else:
        add('identity_separation', 'pass', 'four identities are distinct; OS user membership still needs review')

    try:
        policy = Policy.from_file(config)
        add('policy_integrity', 'pass', f'loaded {len(policy.tool_pins)} pinned tool definitions')
        # We cannot infer from the tool name whether execution has external
        # effects. A trusted reviewer must classify permitted tools that lack
        # an independent postcondition as genuinely read-only.
        permitted = {r.tool for r in policy.rules if r.effect != 'deny'}
        unverified = sorted(permitted - set(policy.postconditions))
        if unverified:
            add('tool_effect_assurance', 'warn',
                f'{len(unverified)} permitted tool(s) lack independent postconditions; '
                'review as read-only or add a verifier')
        else:
            add('tool_effect_assurance', 'pass', 'all permitted tool rules have postconditions')
    except (OSError, ValueError, PermissionError, TypeError) as exc:
        add('policy_integrity', 'fail', f'{type(exc).__name__}: policy rejected')

    state_dir = Path(state_dir)
    anchor_path = Path(anchor_path)
    paths = [("database", state_dir / 'audit.sqlite3'),
             ("signing_key", state_dir / 'audit.key'),
             ("checkpoint", anchor_path)]
    path_errors = False
    if anchor_path.resolve(strict=False).is_relative_to(state_dir.resolve(strict=False)):
        add('checkpoint_separation', 'fail', 'checkpoint must not share the broker state directory')
        path_errors = True
    else:
        add('checkpoint_separation', 'pass', 'checkpoint is outside the broker state directory')
    for label, path in paths:
        try:
            if path.is_symlink():
                raise PermissionError('symlink')
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise PermissionError('non_regular_file')
            if info.st_mode & 0o077 or info.st_uid != uid:
                raise PermissionError('insecure_owner_or_mode')
            add(label, 'pass', 'exists, restricted mode, broker-owned')
        except (OSError, PermissionError) as exc:
            add(label, 'fail', f'{type(exc).__name__}: missing or untrusted')
            path_errors = True
    if not path_errors:
        try:
            # Missing key is rejected above: no new key can be created.
            key = get_or_create_key(state_dir / 'audit.key')
            state = State(state_dir / 'audit.sqlite3', key, anchor_path=anchor_path)
            state.assert_anchor()
            controls = state.controls()
            add('audit_chain', 'pass', 'receipt chain and independent checkpoint authenticated')
            add('gateway_state', 'pass' if not controls['gateway_enabled'] else 'warn',
                'disarmed for commissioning' if not controls['gateway_enabled']
                else 'currently armed; confirm operator and backend identities before use')
        except (OSError, ValueError, PermissionError, TypeError) as exc:
            add('audit_chain', 'fail', f'{type(exc).__name__}: failed verification')
    else:
        add('audit_chain', 'fail', 'cannot inspect incomplete or unsafe state')

    # No host introspection can establish these controls without service/LSM
    # inspection or an independent tester. Keep this limitation prominent.
    add('host_sandbox', 'warn', 'systemd restrictions, MAC/LSM and network egress not attested')
    add('human_identity', 'warn', 'operator UID is not phishing-resistant human authentication')
    failures = sum(item['status'] == 'fail' for item in results)
    warnings = sum(item['status'] == 'warn' for item in results)
    return {'ok': not failures and (not strict or not warnings),
            'failures': failures, 'warnings': warnings, 'checks': results,
            'scope': 'Linux protected-broker preflight only; not penetration-test certification'}
