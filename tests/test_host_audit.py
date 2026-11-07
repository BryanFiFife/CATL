"""Unit evidence is machine-checkable, but not confused with a live pentest."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from catl.host_audit import assess_unit, parse_show, run, REQUIRED


def acceptable():
    return {**{k:sorted(v)[0] for k,v in REQUIRED.items()},
       'User':'catl-broker', 'Group':'catl-broker',
       'SupplementaryGroups':'catl-agent-ipc catl-operator-ipc catl-backend-ipc', 'LoadState':'loaded', 'ActiveState':'active',
       'RestrictAddressFamilies':'AF_UNIX', 'IPAddressDeny':'any',
       'CapabilityBoundingSet':'', 'AmbientCapabilities':'',
       'ReadWritePaths':'/var/lib/catl/state /var/lib/catl-anchor /run/catl-agent /run/catl-operator', 'UMask':'0077'}

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
