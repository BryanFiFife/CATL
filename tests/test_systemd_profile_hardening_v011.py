"""Offline checks of CATL evaluation systemd profiles.

No services are installed or started. This is template syntax and regression
coverage, not a claim that a real host enforces the requested sandbox.
"""
from __future__ import annotations
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PROFILES=ROOT/'packaging'/'systemd'

REQUIRED={
    'StartLimitIntervalSec':'60',
    'StartLimitBurst':'3',
    'Restart':'on-failure',
    'RestartSec':'3',
    'TimeoutStopSec':'10',
    'KillMode':'control-group',
    'OOMPolicy':'stop',
    'UMask':'0077',
    'NoNewPrivileges':'true',
    'PrivateNetwork':'yes',
    'ProtectSystem':'strict',
    'ProtectHome':'true',
    'ProtectKernelModules':'yes',
    'ProtectKernelTunables':'yes',
    'ProtectKernelLogs':'yes',
    'ProtectControlGroups':'yes',
    'ProtectClock':'yes',
    'ProtectHostname':'yes',
    'ProtectProc':'invisible',
    'RestrictNamespaces':'true',
    'RestrictSUIDSGID':'yes',
    'PrivateDevices':'yes',
    'PrivateTmp':'true',
    'RestrictAddressFamilies':'AF_UNIX',
    'IPAddressDeny':'any',
    'CapabilityBoundingSet':'',
    'AmbientCapabilities':'',
    'KeyringMode':'private',
    'LockPersonality':'true',
    'RestrictRealtime':'true',
    'SystemCallArchitectures':'native',
    'SystemCallFilter':'~@mount @swap @reboot @raw-io',
    'SystemCallErrorNumber':'EPERM',
    'LimitCORE':'0',
    'MemorySwapMax':'0',
    'TasksMax':'64',
}


def parse_unit(name):
    text=(PROFILES/f'catl-{name}.service.example').read_text(encoding='utf-8')
    values={}
    for line in text.splitlines():
        stripped=line.strip()
        if not stripped or stripped.startswith(('#','[')):
            continue
        if '=' not in stripped:
            raise ValueError('invalid_setting')
        k,v=stripped.split('=',1)
        if k in values:
            raise ValueError('duplicate_setting:'+k)
        values[k]=v
    return values


class SystemdProfileHardening(unittest.TestCase):
    def test_all_required_security_knobs_present(self):
        for name in ('broker','backend'):
            with self.subTest(name=name):
                values=parse_unit(name)
                for key,expected in REQUIRED.items():
                    self.assertEqual(values.get(key), expected, f'{name}: {key}')

    def test_bounded_memory_and_recovery(self):
        maximum={'broker':768,'backend':1536}
        for name,value in maximum.items():
            with self.subTest(name=name):
                vals=parse_unit(name)
                self.assertEqual(vals.get('MemoryMax'),f'{value}M')
                self.assertLessEqual(value,2048)
                self.assertEqual(vals.get('StartLimitBurst'),'3')

    def test_no_private_users_namespace_which_can_break_peer_uid(self):
        for name in ('broker','backend'):
            vals=parse_unit(name)
            self.assertNotIn(vals.get('PrivateUsers','').lower(),('true','yes','1'))

    def test_socket_and_write_paths_are_reviewed(self):
        target={
            'broker':{'/var/lib/catl/state','/var/lib/catl-anchor','/run/catl-agent','/run/catl-operator'},
            'backend':{'/var/lib/catl-tools/work','/run/catl-tools'},
        }
        for name,writes in target.items():
            with self.subTest(name=name):
                vals=parse_unit(name)
                self.assertEqual(set(vals['ReadWritePaths'].split()),writes)
                self.assertNotIn('AF_INET',vals['RestrictAddressFamilies'])
                self.assertNotIn('AF_INET6',vals['RestrictAddressFamilies'])

    def test_no_automatic_privileged_execution_or_host_user(self):
        for name in ('broker','backend'):
            vals=parse_unit(name)
            self.assertEqual(vals['User'],'catl-broker' if name=='broker' else 'catl-tools')
            self.assertTrue(vals['ExecStart'].startswith('/usr/local/bin/catl '))
            self.assertNotIn('/bin/sh ',vals['ExecStart'])
            self.assertNotIn('/bin/bash ',vals['ExecStart'])

    @unittest.skipUnless(sys.platform=='linux' and shutil.which('systemd-analyze'), 'systemd-analyze unavailable')
    def test_systemd_analyze_verify_sanitised_offline(self):
        with tempfile.TemporaryDirectory(prefix='catl-static-units-') as d:
            for name in ('broker','backend'):
                source=(PROFILES/f'catl-{name}.service.example').read_text(encoding='utf-8')
                source=source.replace('/usr/local/bin/catl','/usr/bin/true')
                for token,value in [('BROKER_UID','1001'),('BACKEND_IPC_GID','1002'),
                                    ('AGENT_UID','1003'),('OPERATOR_UID','1004'),
                                    ('AGENT_GID','1005'),('OPERATOR_GID','1006'),('TOOLS_UID','1007')]:
                    source=source.replace(token,value)
                source=source.replace('User=catl-broker','User=root').replace('Group=catl-broker','Group=root')
                source=source.replace('User=catl-tools','User=root').replace('Group=catl-tools','Group=root')
                source=source.replace('SupplementaryGroups=catl-agent-ipc catl-operator-ipc catl-backend-ipc','SupplementaryGroups=root')
                source=source.replace('SupplementaryGroups=catl-backend-ipc','SupplementaryGroups=root')
                source=source.replace('WorkingDirectory=/var/lib/catl-tools/work','WorkingDirectory=/tmp')
                (Path(d)/f'catl-{name}.service').write_text(source)
            files=[str(Path(d)/f'catl-{name}.service') for name in ('broker','backend')]
            out=subprocess.run(['systemd-analyze','verify',*files],capture_output=True,text=True,timeout=15)
            self.assertEqual(out.returncode,0,out.stdout+'\n'+out.stderr)

if __name__ == '__main__':unittest.main()
