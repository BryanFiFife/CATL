"""Fail-closed live systemd resource and egress profile regressions."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from catl.systemd_runtime_gates import (MEMORY_CEILINGS, STRICT_PROPERTIES,
                                        NO_UNREVIEWED_MOUNTS_OR_NAMESPACES,
                                        assess_runtime_gates)


def profile(user='catl-broker'):
    return {
        'MemoryMax': str(MEMORY_CEILINGS[user]),
        'MemorySwapMax': '0',
        'TasksMax': '64',
        'LimitCORE': '0',
        'IPAddressAllow': '',
        **STRICT_PROPERTIES,
    }


class SystemdRuntimeGates(unittest.TestCase):
    def rejected(self, properties, user='catl-broker'):
        result = assess_runtime_gates(properties, user)
        self.assertFalse(all(x['status'] == 'pass' for x in result))
        return [x['control'] for x in result if x['status'] == 'fail']

    def test_reviewed_broker_passes(self):
        self.assertTrue(all(x['status'] == 'pass' for x in assess_runtime_gates(profile(), 'catl-broker')))

    def test_reviewed_backend_passes(self):
        self.assertTrue(all(x['status'] == 'pass' for x in assess_runtime_gates(profile('catl-tools'), 'catl-tools')))

    def test_unknown_role_fails_closed(self):
        self.assertIn('known_service_role', self.rejected({}, 'catl-agent'))

    def test_missing_every_required_property_fails(self):
        for key in profile():
            with self.subTest(key=key):
                bad = profile()
                bad.pop(key)
                if key == 'IPAddressAllow':
                    # Missing means no exceptions; that is the safe empty value.
                    self.assertTrue(all(x['status'] == 'pass' for x in assess_runtime_gates(bad, 'catl-broker')))
                else:
                    self.rejected(bad)

    def test_unbounded_and_oversized_memory_rejected(self):
        for value in ('max', 'infinity', '', '-1', '0', str(MEMORY_CEILINGS['catl-broker'] + 1), '1e9', ' 100 ', '１２３'):
            with self.subTest(value=value):
                bad = profile()
                bad['MemoryMax'] = value
                self.assertIn('cgroup_memory_max', self.rejected(bad))

    def test_backend_ceiling_is_distinct(self):
        bad = profile('catl-tools')
        bad['MemoryMax'] = str(MEMORY_CEILINGS['catl-tools'] + 1)
        self.assertIn('cgroup_memory_max', self.rejected(bad, 'catl-tools'))

    def test_swap_must_be_zero(self):
        for value in ('1', 'max', 'infinity', '-1', ''):
            with self.subTest(value=value):
                bad = profile()
                bad['MemorySwapMax'] = value
                self.assertIn('cgroup_swap_disabled', self.rejected(bad))

    def test_task_limit_is_finite(self):
        for value in ('65', '0', 'max', 'infinity', '-1', ''):
            with self.subTest(value=value):
                bad = profile()
                bad['TasksMax'] = value
                self.assertIn('cgroup_task_max', self.rejected(bad))

    def test_core_dumps_denied(self):
        for value in ('1', 'infinity', '', '-1'):
            with self.subTest(value=value):
                bad = profile()
                bad['LimitCORE'] = value
                self.assertIn('core_dumps_disabled', self.rejected(bad))

    def test_no_explicit_ip_egress_allowlist(self):
        for value in ('127.0.0.1/32', '10.0.0.0/8', 'any', '0.0.0.0/0'):
            with self.subTest(value=value):
                bad = profile()
                bad['IPAddressAllow'] = value
                self.assertIn('no_egress_allow_exceptions', self.rejected(bad))

    def test_every_strict_property_is_required(self):
        for key in STRICT_PROPERTIES:
            with self.subTest(key=key):
                bad = profile()
                bad[key] = 'no' if STRICT_PROPERTIES[key] == 'yes' else ''
                self.assertIn('runtime_' + key, self.rejected(bad))

    def test_unreviewed_host_mounts_and_namespace_sharing_denied(self):
        overrides = {
            'BindPaths': '/tmp:/etc/catl',
            'BindReadOnlyPaths': '/root:/mnt/root',
            'NetworkNamespacePath': '/run/netns/external',
            'JoinsNamespaceOf': 'untrusted.service',
            'RootDirectory': '/tmp/other-root',
            'RootImage': '/tmp/other-root.img',
            'TemporaryFileSystem': '/etc',
        }
        self.assertEqual(set(overrides), set(NO_UNREVIEWED_MOUNTS_OR_NAMESPACES))
        for key, value in overrides.items():
            with self.subTest(property=key):
                bad = profile()
                bad[key] = value
                self.assertIn('no_unreviewed_' + key, self.rejected(bad))

    def test_unreviewed_properties_are_allowed_only_when_empty(self):
        good = profile()
        for name in NO_UNREVIEWED_MOUNTS_OR_NAMESPACES:
            good[name] = ''
        self.assertTrue(all(x['status'] == 'pass'
                            for x in assess_runtime_gates(good, 'catl-broker')))
        for key in NO_UNREVIEWED_MOUNTS_OR_NAMESPACES:
            bad = dict(good)
            bad[key] = object()
            self.assertIn('no_unreviewed_' + key, self.rejected(bad))

    def test_malformed_numeric_input_fails_closed(self):
        for key in ('MemoryMax', 'MemorySwapMax', 'TasksMax', 'LimitCORE'):
            with self.subTest(key=key):
                bad = profile()
                bad[key] = object()
                self.rejected(bad)


if __name__ == '__main__':
    unittest.main()
