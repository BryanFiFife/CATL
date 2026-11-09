"""Unit evidence is machine-checkable, but not confused with a live pentest."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import stat
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from catl.host_audit import assess_unit, parse_show, run, REQUIRED
from catl.systemd_runtime_gates import MEMORY_CEILINGS, STRICT_PROPERTIES, NO_UNREVIEWED_MOUNTS_OR_NAMESPACES


def acceptable():
    return {**{k:sorted(v)[0] for k,v in REQUIRED.items()},
       'User':'catl-broker', 'Group':'catl-broker',
       'SupplementaryGroups':'catl-agent-ipc catl-operator-ipc catl-backend-ipc', 'LoadState':'loaded', 'ActiveState':'active',
       'RestrictAddressFamilies':'AF_UNIX', 'IPAddressDeny':'any',
       'CapabilityBoundingSet':'', 'AmbientCapabilities':'',
       'ReadWritePaths':'/var/lib/catl/state /var/lib/catl-anchor /run/catl-agent /run/catl-operator', 'UMask':'0077',
       'MemoryMax':str(MEMORY_CEILINGS['catl-broker']), 'MemorySwapMax':'0',
       'TasksMax':'64', 'LimitCORE':'0', 'IPAddressAllow':'', **STRICT_PROPERTIES}

class UnitAudit(unittest.TestCase):
    def test_restricted_profile_passes(self):
        self.assertTrue(assess_unit('catl-broker.service',acceptable(),'catl-broker')['passed'])

    def test_loss_of_each_required_property_fails(self):
        original=acceptable()
        for item in list(REQUIRED)+['RestrictAddressFamilies','IPAddressDeny','CapabilityBoundingSet',
                    'ReadWritePaths','User','Group','SupplementaryGroups','LoadState','ActiveState','UMask']:
            with self.subTest(item=item):
                props=dict(original)
                props[item]='no' if item!='User' else 'root'
                self.assertFalse(assess_unit('catl-broker.service',props,'catl-broker')['passed'])

    def test_only_reviewed_write_roots_pass(self):
        props = acceptable()
        permitted = props['ReadWritePaths']
        for changed in ('/var/lib/other', '/var/lib', '/var/lib/catl/state /run',
                        permitted + ' /var/lib/other',
                        '/var/lib/catl/state /var/lib/catl-anchor /run/catl-operator'):
            with self.subTest(value=changed):
                props['ReadWritePaths'] = changed
                self.assertFalse(assess_unit('catl-broker.service',props,'catl-broker')['passed'])
        props['ReadWritePaths'] = permitted
        self.assertTrue(assess_unit('catl-broker.service',props,'catl-broker')['passed'])

    def test_backend_write_roots_are_separate(self):
        props = acceptable()
        props.update(User='catl-tools',Group='catl-tools',
                     SupplementaryGroups='catl-backend-ipc',
                     ReadWritePaths='/var/lib/catl-tools/work /run/catl-tools')
        self.assertTrue(assess_unit('catl-backend.service',props,'catl-tools')['passed'])
        props['ReadWritePaths'] += ' /run/catl-agent'
        self.assertFalse(assess_unit('catl-backend.service',props,'catl-tools')['passed'])

    def test_live_cgroup_and_egress_weakening_fails_audit(self):
        original = acceptable()
        for name,value in (('MemoryMax','infinity'), ('MemorySwapMax','1048576'),
                           ('TasksMax','infinity'), ('LimitCORE','infinity'),
                           ('IPAddressAllow','192.0.2.0/24'),
                           ('ProtectProc','default'), ('KeyringMode','shared')):
            with self.subTest(name=name):
                props = dict(original)
                props[name] = value
                self.assertFalse(assess_unit('catl-broker.service',props,'catl-broker')['passed'])

    def test_unreviewed_mount_namespace_profile_cannot_pass_integrated_host_audit(self):
        base = acceptable()
        for key, value in (
            ('BindPaths', '/tmp:/var/lib/catl/state'),
            ('BindReadOnlyPaths', '/root:/mnt/host-secrets'),
            ('NetworkNamespacePath', '/run/netns/unsafe'),
            ('JoinsNamespaceOf', 'public-net.service'),
            ('RootDirectory', '/tmp/alternate-root'),
            ('RootImage', '/tmp/alternate.img'),
            ('TemporaryFileSystem', '/etc'),
        ):
            with self.subTest(field=key):
                altered = dict(base)
                altered[key] = value
                report = assess_unit('catl-broker.service', altered, 'catl-broker')
                self.assertFalse(report['passed'])
                failed = {part['control'] for part in report['checks']
                          if part['status'] == 'fail'}
                self.assertIn('no_unreviewed_' + key, failed)
        self.assertEqual(len(NO_UNREVIEWED_MOUNTS_OR_NAMESPACES), 7)

    @unittest.skipUnless(sys.platform == 'linux', 'live systemd API is Linux-only')
    def test_systemctl_show_ingress_rejects_unreviewed_mounts(self):
        from catl.host_audit import run
        backend = acceptable()
        backend.update(User='catl-tools', Group='catl-tools',
                       SupplementaryGroups='catl-backend-ipc',
                       ReadWritePaths='/var/lib/catl-tools/work /run/catl-tools',
                       MemoryMax=str(MEMORY_CEILINGS['catl-tools']))
        def output(props):
            return '\\n'.join(k + '=' + str(v) for k, v in props.items()) + '\\n'
        trusted = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        with patch('catl.host_audit.Path.stat', return_value=trusted):
            for field,value in (
                ('BindPaths', '/tmp:/etc/catl'),
                ('NetworkNamespacePath', '/run/netns/untrusted'),
                ('JoinsNamespaceOf', 'untrusted.service'),
            ):
                with self.subTest(field=field):
                    broker = acceptable()
                    broker[field] = value
                    responses = [
                        SimpleNamespace(returncode=0, stdout=output(broker)),
                        SimpleNamespace(returncode=0, stdout=output(backend)),
                    ]
                    with patch('catl.host_audit.subprocess.run', side_effect=responses):
                        result = run()
                    self.assertFalse(result['passed'])
                    self.assertFalse(result['units'][0]['passed'])
                    self.assertTrue(result['units'][1]['passed'])
            good_responses = [
                SimpleNamespace(returncode=0, stdout=output(acceptable())),
                SimpleNamespace(returncode=0, stdout=output(backend)),
            ]
            with patch('catl.host_audit.subprocess.run', side_effect=good_responses):
                self.assertTrue(run()['passed'])

    def test_no_systemd_is_explicit_failure(self):
        with patch('catl.host_audit.subprocess.run',side_effect=FileNotFoundError('missing systemd')):
            self.assertFalse(run()['passed'])

    def test_duplicate_properties_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate_systemd_property'):
            parse_show('User=a\nUser=b\n')

    def test_units_contain_required_safety_controls(self):
        for filename in ('catl-broker.service.example','catl-backend.service.example'):
            with self.subTest(filename=filename):
                content=(ROOT/'packaging/systemd'/filename).read_text()
                for key,values in REQUIRED.items():
                    self.assertIn(key+'=',content)
                self.assertIn('IPAddressDeny=any',content)
                self.assertIn('RestrictAddressFamilies=AF_UNIX',content)
