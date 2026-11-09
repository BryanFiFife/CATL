"""Strict, read-only checks of live systemd service resource and isolation settings.

These properties are read from `systemctl show` by host_audit; this module
performs only deterministic validation. It does not attest kernel enforcement,
LSM, firewall, installed unit contents or a separate running process.
"""
from __future__ import annotations

from typing import Mapping

# These match the reviewed evaluation units, not a universal deployment policy.
MEMORY_CEILINGS = {
    'catl-broker': 768 * 1024 * 1024,
    'catl-tools': 1536 * 1024 * 1024,
}
MAX_TASKS = 64

# No path or namespace imports are present in the reviewed CATL units.
# A drop-in can use these settings to expose additional host data, remount a
# writable tree, or join a different network namespace while the original
# sandbox settings still appear enabled. Refuse any unreviewed value.
NO_UNREVIEWED_MOUNTS_OR_NAMESPACES = {
    'BindPaths': 'unreviewed writable bind mount',
    'BindReadOnlyPaths': 'unreviewed host path exposure',
    'NetworkNamespacePath': 'unreviewed externally selected network namespace',
    'JoinsNamespaceOf': 'unreviewed namespace sharing with another unit',
    'RootDirectory': 'unreviewed alternate filesystem root',
    'RootImage': 'unreviewed alternate filesystem image',
    'TemporaryFileSystem': 'unreviewed mount-overlay configuration',
}


STRICT_PROPERTIES = {
    'ProtectKernelLogs': 'yes',
    'ProtectClock': 'yes',
    'ProtectHostname': 'yes',
    'ProtectProc': 'invisible',
    'RestrictNamespaces': 'yes',
    'RestrictRealtime': 'yes',
    'KeyringMode': 'private',
    'KillMode': 'control-group',
    'OOMPolicy': 'stop',
}


def _nonnegative_int(value: object) -> int | None:
    """Accept only canonical decimal systemd numeric property values.

    Reject `infinity`, `max`, empty, signed numbers and surprises rather than
    making a best-effort guess about service containment.
    """
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal():
        return None
    try:
        return int(value)
    except ValueError:
        return None


def assess_runtime_gates(properties: Mapping[str, str], expected_user: str) -> list[dict[str, str]]:
    """Return granular checks. A missing/unknown property is a failure."""
    findings: list[dict[str, str]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        findings.append({'control': name, 'status': 'pass' if passed else 'fail',
                         'detail': detail})

    ceiling = MEMORY_CEILINGS.get(expected_user)
    if ceiling is None:
        check('known_service_role', False, 'unknown role has no reviewed systemd profile')
        return findings

    memory = _nonnegative_int(properties.get('MemoryMax'))
    swap = _nonnegative_int(properties.get('MemorySwapMax'))
    tasks = _nonnegative_int(properties.get('TasksMax'))
    core = _nonnegative_int(properties.get('LimitCORE'))
    check('cgroup_memory_max', memory is not None and 0 < memory <= ceiling,
          'MemoryMax must be a finite decimal byte limit within the reviewed role ceiling')
    check('cgroup_swap_disabled', swap == 0,
          'MemorySwapMax must be an explicit zero-byte limit')
    check('cgroup_task_max', tasks is not None and 0 < tasks <= MAX_TASKS,
          'TasksMax must be finite and no greater than 64')
    check('core_dumps_disabled', core == 0,
          'LimitCORE must be zero')
    check('no_egress_allow_exceptions', properties.get('IPAddressAllow', '').strip() == '',
          'IPAddressAllow must have no entries alongside IPAddressDeny=any')
    for name, expected in STRICT_PROPERTIES.items():
        check('runtime_' + name, properties.get(name) == expected,
              name + ' must be ' + expected + ' in effective service properties')
    for name, rationale in NO_UNREVIEWED_MOUNTS_OR_NAMESPACES.items():
        actual = properties.get(name, '')
        check('no_unreviewed_' + name, isinstance(actual, str) and actual.strip() == '',
              name + ' must be empty in reviewed profile: ' + rationale)
    return findings
