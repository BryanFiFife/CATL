"""Conservative static denylist for accidental dangerous runtime constructs.

NOT a substitute for malware analysis, code review or an independent pentest.
"""
from __future__ import annotations
import ast
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN_IMPORTS={'requests','httpx','urllib.request','pickle','marshal','ctypes'}
FORBIDDEN_CALLS={'eval','exec','os.system','os.popen','pickle.loads','marshal.loads'}
# These carefully scoped components are NOT the networkless broker supervisor:
# - platform_proofs: read-only Windows native token inspection needs ctypes.
# - witness_protocol: independently configured outbound mTLS witness needs
#   exactly these urllib.request transport primitives (no generic urlopen).
ALLOWED_MODULE_IMPORTS = {'platform_proofs.py': {'ctypes'}}
ALLOWED_FROM_IMPORTS = {
    'platform_proofs.py': {'ctypes': {'wintypes'}},
    'witness_protocol.py': {
        'urllib.request': {'Request', 'build_opener', 'HTTPSHandler',
                           'HTTPRedirectHandler', 'ProxyHandler'}
    }
}


def check_runtime() -> list[str]:
    findings=[]
    for p in sorted((ROOT/'src'/'catl').glob('*.py')):
        tree=ast.parse(p.read_text(encoding='utf-8'),filename=str(p))
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                for alias in node.names:
                    if (alias.name in FORBIDDEN_IMPORTS and
                            alias.name not in ALLOWED_MODULE_IMPORTS.get(p.name, set())):
                        findings.append(f'{p.name}:{node.lineno}: import {alias.name}')
            if isinstance(node,ast.ImportFrom) and node.module in FORBIDDEN_IMPORTS:
                allowed = ALLOWED_FROM_IMPORTS.get(p.name, {}).get(node.module)
                imported = {alias.name for alias in node.names}
                if allowed is None or imported != allowed:
                    findings.append(f'{p.name}:{node.lineno}: from {node.module}')
            if isinstance(node,ast.Call):
                fn=node.func
                name=fn.id if isinstance(fn,ast.Name) else (
                    fn.value.id+'.'+fn.attr if isinstance(fn,ast.Attribute) and isinstance(fn.value,ast.Name) else None)
                if name in FORBIDDEN_CALLS:
                    findings.append(f'{p.name}:{node.lineno}: {name}()')
                if name in {'subprocess.Popen','subprocess.run','subprocess.call','subprocess.check_output'}:
                    for kw in node.keywords:
                        if kw.arg == 'shell' and not (isinstance(kw.value,ast.Constant) and kw.value.value is False):
                            findings.append(f'{p.name}:{node.lineno}: subprocess shell setting')
            if isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name):
                if node.value.id=='socket' and node.attr in ('AF_INET','AF_INET6'):
                    findings.append(f'{p.name}:{node.lineno}: network socket family {node.attr}')
    return findings

if __name__=='__main__':
    issues=check_runtime()
    if issues:
        print('\n'.join(issues),file=sys.stderr)
        raise SystemExit(2)
    print('PASS static sanity scan: no forbidden runtime constructs or TCP socket families')
