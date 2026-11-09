"""Deterministic adversarial mutations of the source-exact systemd host preflight.

This uses synthetic systemctl property maps; it does not claim live kernel
or service-manager isolation acceptance.
"""
from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from catl.host_audit import REQUIRED, assess_unit
from catl.systemd_runtime_gates import MEMORY_CEILINGS, STRICT_PROPERTIES, NO_UNREVIEWED_MOUNTS_OR_NAMESPACES


def broker_properties() -> dict[str, str]:
    return {
        **{key: sorted(accepted)[0] for key, accepted in REQUIRED.items()},
        'User': 'catl-broker',
        'Group': 'catl-broker',
        'SupplementaryGroups': 'catl-agent-ipc catl-operator-ipc catl-backend-ipc',
        'LoadState': 'loaded',
        'ActiveState': 'active',
        'RestrictAddressFamilies': 'AF_UNIX',
        'IPAddressDeny': 'any',
        'CapabilityBoundingSet': '',
        'AmbientCapabilities': '',
        'ReadWritePaths': '/var/lib/catl/state /var/lib/catl-anchor /run/catl-agent /run/catl-operator',
        'UMask': '0077',
        'MemoryMax': str(MEMORY_CEILINGS['catl-broker']),
        'MemorySwapMax': '0',
        'TasksMax': '64',
        'LimitCORE': '0',
        'IPAddressAllow': '',
        **STRICT_PROPERTIES,
    }


class DeterministicHostileServiceMutations(unittest.TestCase):
    def test_ten_thousand_fail_closed_mutations(self):
        rng = random.Random(20261109)
        base = broker_properties()
        self.assertTrue(assess_unit('catl-broker.service', base, 'catl-broker')['passed'])
        keys = [
            'MemoryMax', 'MemorySwapMax', 'TasksMax', 'LimitCORE',
            'IPAddressAllow', 'ProtectProc', 'RestrictNamespaces',
            'PrivateNetwork', 'NoNewPrivileges', 'User', 'Group',
            'SupplementaryGroups', 'RestrictAddressFamilies',
            'ReadWritePaths', 'ProtectSystem', 'CapabilityBoundingSet',
            'KeyringMode',
            *NO_UNREVIEWED_MOUNTS_OR_NAMESPACES,
        ]
        candidates = (
            'infinity', '999999999999999', '-1', ' ', '42MB',
            '0.0.0.0/0', 'no', 'root', '/run', 'AF_INET', ' /tmp ', 'weak',
        )
        for index in range(10000):
            properties = dict(base)
            key = keys[rng.randrange(len(keys))]
            value = candidates[(index + rng.randrange(len(candidates))) % len(candidates)]
            if key in ('MemoryMax', 'TasksMax', 'MemorySwapMax', 'LimitCORE') and value == '0':
                value = 'infinity'
            if key in ('IPAddressAllow', 'ReadWritePaths') and not value.strip():
                value = '/tmp'
            if key in ('User', 'Group', 'SupplementaryGroups') and value == base[key]:
                value = 'root'
            if key in NO_UNREVIEWED_MOUNTS_OR_NAMESPACES and not value.strip():
                value = '/tmp/forbidden'
            properties[key] = value
            result = assess_unit('catl-broker.service', properties, 'catl-broker')
            self.assertFalse(result['passed'], f'accepted trial {index}: {key}={value!r}')


if __name__ == '__main__':
    unittest.main()
