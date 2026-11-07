"""Read-only, host-specific Linux systemd sandbox preflight.

A passing result means the named units expose the REQUIRED systemd settings;
it is not proof of AppArmor, SELinux, kernel integrity, OS identity or absence
of host compromise. Missing service manager/unknown property always fails.
"""
from __future__ import annotations
import os
import subprocess
import sys
import re
import stat
from pathlib import Path
from typing import Any

REQUIRED = {
    'NoNewPrivileges': {'yes'},
    'ProtectSystem': {'strict'},
    'ProtectHome': {'yes', 'read-only', 'tmpfs'},
    'PrivateTmp': {'yes', 'disconnected'},
    'PrivateDevices': {'yes'},
    'PrivateNetwork': {'yes'},
    'ProtectKernelTunables': {'yes'},
    'ProtectKernelModules': {'yes'},
    'ProtectControlGroups': {'yes'},
    'LockPersonality': {'yes'},
    'RestrictSUIDSGID': {'yes'},
    'SystemCallArchitectures': {'native'},
}
# IP egress is denied for CATL's supervisor and its demonstration tool server.
# Production external-effect tools require independently reviewed egress policy.


def assess_unit(unit: str, properties: dict[str, str], expected_user: str) -> dict[str, Any]:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,120}\.service',unit):
        raise ValueError('unsafe_unit_name')
    findings: list[dict[str, str]] = []
    def check(name: str, passed: bool, reason: str) -> None:
        findings.append({'control': name, 'status': 'pass' if passed else 'fail', 'detail': reason})

    user = properties.get('User', '')
    check('unprivileged_user', bool(user) and user == expected_user and user != 'root',
          'unit must run under its dedicated non-root account')
    check('primary_group', properties.get('Group') == expected_user,
          'unit primary group must match the dedicated service identity')
    if expected_user == 'catl-broker':
        expected_groups={'catl-agent-ipc','catl-operator-ipc','catl-backend-ipc'}
    elif expected_user == 'catl-tools':
        expected_groups={'catl-backend-ipc'}
    else:
        expected_groups=set()
    groups=set(properties.get('SupplementaryGroups','').split())
    check('supplementary_groups', groups == expected_groups,
          'IPC group memberships must match reviewed role separation')
    check('service_loaded', properties.get('LoadState') == 'loaded', 'named unit must be loaded by systemd')
    check('active_service', properties.get('ActiveState') == 'active', 'unit must be active for live host audit')
    for name, accepted in REQUIRED.items():
        check(name, properties.get(name) in accepted, 'must be one of '+ ','.join(sorted(accepted)))
    families = set(properties.get('RestrictAddressFamilies', '').split())
    check('AF_UNIX_only', families == {'AF_UNIX'}, 'only AF_UNIX must be allowed')
    check('IP_egress_disabled', properties.get('IPAddressDeny', '').strip() == 'any',
          'all IP egress denied for the constrained deployment profile')
    check('capabilities_bounded', properties.get('CapabilityBoundingSet', '') in ('', '0'),
          'capability bounding set must be empty')
    check('ambient_capabilities_empty', properties.get('AmbientCapabilities', '') in ('', '0'),
          'ambient capabilities must be empty')
    # For this specific constrained CATL systemd profile, accept ONLY the
    # service-owned state and IPC paths.  A broad path or an unrelated path
    # must never count as a restricted writable location. Future deployment
    # profiles need their own reviewed allowlist, not a permissive default.
    allowed_writable = {
        'catl-broker': {
            '/var/lib/catl/state', '/var/lib/catl-anchor',
            '/run/catl-agent', '/run/catl-operator',
        },
        'catl-tools': {
            '/var/lib/catl-tools/work', '/run/catl-tools',
        },
    }
    paths = properties.get('ReadWritePaths', '').split()
    expected_paths = allowed_writable.get(expected_user, set())
    restricted_paths = bool(expected_paths) and set(paths) == expected_paths and len(paths) == len(expected_paths)
    check('restrict_write_locations', restricted_paths,
          'writable roots must match the exact reviewed role-specific service profile')
    # Systemd reports umasks in several equivalent octal notations.
    check('restricted_umask', properties.get('UMask', '') in ('0077', '077', '0o077'),
          '0077 umask required')
    return {'unit': unit, 'user': user, 'passed': all(x['status'] == 'pass' for x in findings),
            'checks': findings, 'scope': 'systemd unit-properties preflight only'}


def parse_show(raw: str) -> dict[str, str]:
    if not isinstance(raw, str) or len(raw) > 256_000:
        raise ValueError('systemd_output_invalid')
    out: dict[str, str] = {}
    for line in raw.splitlines():
        if not line or '=' not in line:
            continue
        name, value = line.split('=', 1)
        if name in out:
            raise ValueError('duplicate_systemd_property')
        out[name] = value
    return out


def run(broker_unit: str = 'catl-broker.service', backend_unit: str = 'catl-backend.service',
        broker_user: str = 'catl-broker', backend_user: str = 'catl-tools') -> dict[str, Any]:
    units = ((broker_unit, broker_user), (backend_unit, backend_user))
    try:
        if sys.platform != 'linux' or os.name != 'posix':
            raise PermissionError('systemd_host_audit_linux_only')
        # Validate unit names before invoking any external command.
        for unit, user in units:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,120}\.service',unit) or not user:
                raise ValueError('invalid_unit_or_user')
        # Do not execute a user-PATH-supplied fake systemctl as an auditor.
        binary=Path('/usr/bin/systemctl')
        info=binary.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise PermissionError('systemctl_binary_untrusted')
        reports = []
        for unit, user in units:
            response = subprocess.run(['/usr/bin/systemctl','show','--no-pager','--',unit],
                                      capture_output=True, text=True, timeout=8, check=False)
            if response.returncode != 0:
                raise RuntimeError('systemctl_show_failed:'+unit)
            reports.append(assess_unit(unit, parse_show(response.stdout), user))
        check_distinct = reports[0]['user'] != reports[1]['user']
        return {'passed': all(x['passed'] for x in reports) and check_distinct,
                'distinct_service_users': check_distinct, 'units': reports,
                'limitations': 'Does not attest kernel, LSM, socket parent ACLs, user sessions or tool permissions'}
    except (OSError, ValueError, RuntimeError, TimeoutError, PermissionError) as exc:
        return {'passed': False, 'error': type(exc).__name__ + ': ' + str(exc)[:100],
                'limitations': 'No host sandbox attestation has been completed'}
