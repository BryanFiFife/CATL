#!/usr/bin/env python3
"""Conservative, read-only CATL/Hermes MCP configuration audit.

Passing means only the *reviewed MCP entry* is present. Hermes' effective tool
registry, executable integrity, Unix peer credentials and OS sandbox MUST be
verified separately; this tool cannot certify end-to-end isolation.
"""
from __future__ import annotations
import argparse
import json
import os
import stat
from pathlib import Path
import sys
from strict_yaml import load_config
from profile_guard import expected_platform_toolsets, validate_restricted_profile

REVIEWED_KEYS = {
    'command', 'args', 'enabled', 'lazy', 'timeout', 'connect_timeout',
    'tools', 'sampling', 'events', 'supports_parallel_tool_calls',
}
REVIEWED_TOOLS = {'include': ['echo_safe', 'write_demo'], 'resources': False, 'prompts': False}
DEFAULT_PROTECTED_CLI = '/opt/catl-venv/bin/catl'
DEFAULT_PROTECTED_SOCKET = '/run/catl-agent/agent.sock'


def demo_args_valid(command: str, argv: list[str]) -> bool:
    if len(argv) != 9:
        return False
    if (argv[0], argv[1], argv[3], argv[5], argv[6]) != (
            'run', '--config', '--state-dir', '--allow-unsandboxed', '--'):
        return False
    policy = Path(argv[2]); state = Path(argv[4]); python = Path(argv[7]); script = Path(argv[8])
    if not all(x.is_absolute() for x in (policy, state, python, script)):
        return False
    if policy.name != 'policy.json' or policy.parent.name != 'examples':
        return False
    source = policy.parent.parent
    if script != source / 'examples' / 'mock_server.py':
        return False
    expected_python = Path(command).parent / ('python.exe' if Path(command).suffix.lower() == '.exe' else 'python')
    return python == expected_python and state != source


def audit(data: object, name: str, mode: str, *,
          expected_catl: str | None = None,
          expected_socket: str = DEFAULT_PROTECTED_SOCKET) -> dict:
    errors, warnings = [], []
    if not isinstance(data, dict):
        return {'passed': False, 'errors': ['Hermes config must be a mapping'], 'warnings': []}
    servers = data.get('mcp_servers', {})
    if not isinstance(servers, dict) or not isinstance(servers.get(name), dict):
        return {'passed': False, 'errors': [f'Missing CATL MCP server {name!r}'], 'warnings': []}
    item = servers[name]
    command = item.get('command')
    argv = item.get('args')
    if not isinstance(command, str) or not Path(command).is_absolute():
        errors.append('CATL command must be an absolute path')
        command = ''
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        errors.append('CATL args must be an array of strings')
        argv = []
    if item.get('enabled') is not True:
        errors.append('CATL MCP server is not explicitly enabled')
    unknown = sorted(set(item) - REVIEWED_KEYS)
    if unknown:
        errors.append('Unreviewed CATL MCP configuration keys: ' + ', '.join(unknown))
    if item.get('tools') != REVIEWED_TOOLS:
        errors.append('CATL tools allowlist/resources/prompts differ from reviewed policy')
    if item.get('sampling') != {'enabled': False}:
        errors.append('MCP model sampling must be explicitly disabled')
    if item.get('events') is not False:
        errors.append('MCP events must be explicitly disabled')
    if item.get('supports_parallel_tool_calls') is not False:
        errors.append('Parallel CATL tool calls must be explicitly disabled')
    if item.get('lazy') is not False:
        errors.append('Lazy/stale tool discovery not allowed')
    if type(item.get('timeout')) is not int or not 0 < item['timeout'] <= 60:
        errors.append('CATL tool timeout must be an explicit bounded integer <= 60s')
    if type(item.get('connect_timeout')) is not int or not 0 < item['connect_timeout'] <= 30:
        errors.append('CATL connection timeout must be an explicit bounded integer <= 30s')
    if expected_catl is not None and command != expected_catl:
        errors.append('CATL executable path differs from independently pinned path')
    if command and Path(command).name.lower() not in ('catl', 'catl.exe'):
        errors.append('CATL executable name unexpected; cannot trust arbitrary executable')
    content = json.dumps(item)
    if ('operator.sock' in content or 'private.pem' in content or
            'signing-key' in content or '--allow-uid-only-operator' in content):
        errors.append('Operator channel, signer or unsafe privilege override in agent config')
    if mode == 'protected':
        # Top-level toolsets is obsolete and would not suppress hermes-cli.
        # Current Hermes reads platform_toolsets.cli; unknown future/plugin
        # channels must also be independently controlled at the OS boundary.
        errors.extend(validate_restricted_profile(data, name))
        target = DEFAULT_PROTECTED_CLI
        if expected_catl is not None and expected_catl != DEFAULT_PROTECTED_CLI:
            errors.append('Protected CATL executable pin cannot be overridden by --expected-catl')
        if expected_socket != DEFAULT_PROTECTED_SOCKET:
            errors.append('Protected CATL agent socket pin cannot be overridden')
        if command != target:
            errors.append(f'Protected CATL executable differs from pinned path {target}')
        if argv != ['shim', '--agent-socket', expected_socket]:
            errors.append('Protected CATL MUST use exact pinned agent socket/arguments')
        if sys.platform != 'linux':
            errors.append('Protected CATL requires Linux')
        if not Path(expected_socket).is_absolute():
            errors.append('Expected protected agent socket is not absolute')
    elif mode == 'demo':
        if not demo_args_valid(command, argv):
            errors.append('Demo CATL arguments differ from reviewed mock-only implementation')
        warnings.append('DEMO ONLY: same-UID CATL does not isolate agent from operator')
    else:
        errors.append('Unknown mode')
    other = sorted(k for k in servers if k != name)
    enabled_other = [k for k in other if isinstance(servers[k], dict) and servers[k].get('enabled') is not False]
    if enabled_other:
        message = 'Other enabled/unclassified MCP servers may bypass CATL: ' + ', '.join(enabled_other)
        if mode == 'protected': errors.append(message)
        else: warnings.append(message)
    if mode == 'protected':
        warnings.append('Static toolset config can be overridden by CLI/session/plugin behaviour; inspect effective runtime tool registry and OS isolation')
    warnings.append('MCP config only; native Hermes tools, plugins, credentials and OS confinement NOT verified')
    return {'passed': not errors, 'scope': 'MCP entry only; NOT E2E isolation', 'mode': mode,
            'CATL_server': name, 'errors': errors, 'warnings': warnings}




def check_linux_protected_executable(path: Path) -> list[str]:
    """Read-only structural inspection of a reviewed root-owned CATL CLI path."""
    errors = []
    if sys.platform != 'linux':
        return ['Protected binary inspection requires Linux']
    if not path.is_absolute():
        return ['Protected binary path is not absolute']
    cursor = path
    while True:
        try:
            info = cursor.lstat()
        except OSError as exc:
            errors.append(f'Executable path component missing/unreadable: {cursor}: {exc}')
            break
        if stat.S_ISLNK(info.st_mode):
            errors.append(f'Executable path component is a symlink: {cursor}')
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            errors.append(f'Executable path component not root-owned and non-writable: {cursor}')
        if cursor == path and (not stat.S_ISREG(info.st_mode) or not (info.st_mode & 0o111)):
            errors.append(f'CATL executable must be a regular executable file: {cursor}')
        if cursor != path and not stat.S_ISDIR(info.st_mode):
            errors.append(f'Executable parent not a directory: {cursor}')
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    return errors

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, default=Path.home() / '.hermes/config.yaml')
    p.add_argument('--mode', choices=['demo', 'protected'], required=True)
    p.add_argument('--server-name')
    p.add_argument('--expected-catl', help='Independently pinned CATL executable path')
    p.add_argument('--expected-agent-socket', default=DEFAULT_PROTECTED_SOCKET)
    args = p.parse_args(argv)
    try:
        if args.config.is_symlink() or not args.config.is_file():
            raise PermissionError('No trusted Hermes config file')
        raw = args.config.read_bytes()
        data = load_config(raw)
        report = audit(data, args.server_name or ('catl_eval' if args.mode == 'demo' else 'catl'),
                       args.mode, expected_catl=args.expected_catl,
                       expected_socket=args.expected_agent_socket)
        if args.mode == 'protected':
            binary_errors = check_linux_protected_executable(Path(DEFAULT_PROTECTED_CLI))
            report['errors'].extend(binary_errors)
            report['passed'] = report['passed'] and not binary_errors
            report['protected_executable_filesystem_checked'] = not binary_errors
        print(json.dumps(report, indent=2))
        return 0 if report['passed'] else 1
    except Exception as exc:
        print(json.dumps({'passed': False, 'error': str(exc)}), file=sys.stderr)
        return 1


if __name__ == '__main__': raise SystemExit(main())
