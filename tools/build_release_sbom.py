#!/usr/bin/env python3
"""Deterministic CycloneDX inventory of pinned CATL audit requirements.

This is NOT a complete resolved environment SBOM, a vulnerability scan, a
licence clearance, or a declaration of platform-specific transitive closure.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)")


class InventoryError(ValueError):
    pass


def _pins(lines: list[str], *, allow_comments: bool) -> dict[str, str]:
    found: dict[str, str] = {}
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or (allow_comments and line.startswith('#')):
            continue
        match = PIN.fullmatch(line)
        if not match:
            raise InventoryError(f'not_an_exact_pin_at_line_{lineno}')
        name = re.sub(r'[-_.]+', '-', match.group(1)).lower()
        version = match.group(2)
        if name in found:
            raise InventoryError('duplicate_package:' + name)
        found[name] = version
    if not found:
        raise InventoryError('empty_inventory')
    return found


def build(root: Path) -> dict:
    root = Path(root)
    config = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))
    project = config['project']
    name = str(project['name'])
    version = str(project['version'])
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name):
        raise InventoryError('invalid_project_name')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.!+_-]*', version):
        raise InventoryError('invalid_project_version')
    declared = _pins(list(project['dependencies']), allow_comments=False)
    inventory = _pins((root / 'requirements-security-audit.txt').read_text(encoding='utf-8').splitlines(), allow_comments=True)
    for package, pinned_version in declared.items():
        if inventory.get(package) != pinned_version:
            raise InventoryError('direct_dependency_missing_or_mismatch:' + package)
    app_name = re.sub(r'[-_.]+', '-', name).lower()
    app_ref = f'pkg:pypi/{app_name}@{version}'
    components = [
        {'type': 'library', 'bom-ref': f'pkg:pypi/{package}@{pinned_version}',
         'name': package, 'version': pinned_version,
         'purl': f'pkg:pypi/{package}@{pinned_version}'}
        for package, pinned_version in sorted(inventory.items())
    ]
    seed = app_ref + '\n' + '\n'.join(c['bom-ref'] for c in components)
    return {
        'bomFormat': 'CycloneDX', 'specVersion': '1.6',
        'serialNumber': 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, seed)),
        'version': 1,
        'metadata': {
            'component': {'type': 'application', 'bom-ref': app_ref,
                          'name': name, 'version': version},
            'properties': [
                {'name': 'catl:scope', 'value': 'PINNED_AUDIT_INVENTORY_ONLY'},
                {'name': 'catl:source', 'value': 'pyproject.toml + requirements-security-audit.txt'},
                {'name': 'catl:limitation', 'value': 'Not an installed environment inventory, complete dependency lock, vulnerability scan or licence audit'},
            ],
        },
        'components': components,
        'dependencies': [
            {'ref': app_ref, 'dependsOn': [
                f'pkg:pypi/{package}@{declared[package]}' for package in sorted(declared)
            ]},
        ],
    }


def render(root: Path) -> bytes:
    return (json.dumps(build(root), sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', action='store_true', help='fail if output does not exactly match pinned source')
    args = parser.parse_args()
    target = args.output or args.repo / 'docs' / 'SBOM-evaluation.json'
    try:
        content = render(args.repo)
        if args.check:
            if not target.is_file() or target.read_bytes() != content:
                raise InventoryError('stale_or_missing_sbom')
            print(f'PASS pinned-inventory SBOM current: {target}')
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            print(f'WROTE pinned-inventory SBOM: {target}')
    except (InventoryError, OSError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f'REJECTED: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
