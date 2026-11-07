#!/usr/bin/env python3
"""Fail-closed, read-only verification of Hermes' resolved CLI tool inventory.

Must run as the isolated Hermes agent OS user against a trusted Python runtime.
This is *not* a sandbox and cannot prove a separate running Hermes process uses
this tool inventory. Its role is detecting fail-open config/plugin drift before
Hermes is launched through a separately enforced OS sandbox.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import time
from pathlib import Path
import signal
import stat
import subprocess
import sys
from typing import Any

import hermes_audit
import strict_yaml
import profile_guard
from hermes_audit import audit
from strict_yaml import load_config

MARKER = "CATL_RUNTIME_REPORT_V1="
MAX_OUTPUT = 131072
EXPECTED_NAMES = frozenset(("mcp_catl_echo_safe", "mcp_catl_write_demo"))
EXPECTED_TOOLSETS = frozenset(("catl",))

# This program executes inside the same trusted Python environment as Hermes,
# to resolve native, MCP, plugin and context toolsets as Hermes actually does.
# It never issues an LLM prompt or invokes a tool.
SNAPSHOT_CODE = r'''
import hashlib, json, logging, os, pathlib, sys
marker = "CATL_RUNTIME_REPORT_V1="
try:
    home = pathlib.Path(os.environ["HERMES_HOME"]).resolve(strict=True)
    path = home / "config.yaml"
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    from hermes_cli.config import load_config_readonly
    from hermes_cli.tools_config import _get_platform_tools
    from model_tools import get_tool_definitions
    from hermes_cli.mcp_startup import ensure_mcp_discovery_before_agent_build
    config = load_config_readonly()
    ensure_mcp_discovery_before_agent_build(logger=logging.getLogger("catl-runtime"),timeout=12)
    resolved = sorted(_get_platform_tools(config, "cli"))
    # Raw schemas are mandatory: tool-search bridges can otherwise conceal
    # active tools behind a single aggregated search entry.
    definitions = get_tool_definitions(enabled_toolsets=resolved,
                                       quiet_mode=True,
                                       skip_tool_search_assembly=True)
    names = [d["function"]["name"] for d in definitions]
    after = hashlib.sha256(path.read_bytes()).hexdigest()
    result = {"version": 1, "config_sha256_before": before,
              "config_sha256_after": after, "resolved_toolsets": resolved,
              "tool_names": names, "uid": os.geteuid() if hasattr(os,"geteuid") else None,
              "home": str(home)}
except BaseException as exc:
    result = {"version": 1, "error": type(exc).__name__ + ":" + str(exc)[:180]}
print(marker + json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
'''


def _safe_file(path: Path, *, root_owner: bool = False) -> list[str]:
    """Inspect without resolving symlinks; validate every path component."""
    errors = []
    if not path.is_absolute():
        return ["path_not_absolute"]
    cur = path
    while True:
        try:
            s = cur.lstat()
        except OSError:
            errors.append("missing_or_unreadable:" + str(cur))
            break
        if stat.S_ISLNK(s.st_mode):
            if root_owner and cur == path and s.st_uid == 0:
                # Root-owned interpreter venv entry points are commonly symlinks.
                # The agent must be unable to replace link or target, so inspect
                # its target and every ancestor under the same trust policy.
                try:
                    target = cur.resolve(strict=True)
                    if target == cur:
                        errors.append("circular_executable_link")
                    else:
                        errors.extend("target:" + e for e in _safe_file(target, root_owner=True))
                except (OSError,RuntimeError):
                    errors.append("invalid_executable_symlink")
            else:
                errors.append("symlink:" + str(cur))
        if not stat.S_ISLNK(s.st_mode) and stat.S_IMODE(s.st_mode) & 0o022:
            errors.append("group_or_world_writable:" + str(cur))
        if root_owner and s.st_uid != 0:
            errors.append("not_root_owned:" + str(cur))
        if cur != path and not stat.S_ISDIR(s.st_mode):
            errors.append("non_directory_parent:" + str(cur))
        if cur == path and not stat.S_ISREG(s.st_mode) and not (root_owner and stat.S_ISLNK(s.st_mode)):
            errors.append("not_regular_file:" + str(cur))
        if cur == cur.parent:
            break
        cur = cur.parent
    return errors


def _trusted_venv_tree(python: Path, *, max_entries: int = 100000) -> list[str]:
    """Reject an agent-modifiable Hermes interpreter environment.

    Checking only the root-owned Python launcher is insufficient: a writable
    site-packages module or .pth can forge the in-process inventory report.
    Read only, no symlink traversal during directory enumeration. Symlink
    targets are checked separately, including their ancestor permissions.
    """
    if sys.platform != 'linux':
        return ['trusted_venv_requires_linux']
    if python.parent.name != 'bin':
        return ['trusted_venv_requires_bin_python']
    venv = python.parent.parent
    cfg = venv / 'pyvenv.cfg'
    errors = ['venv_config:' + x for x in _safe_file(cfg, root_owner=True)]
    if errors:
        return errors
    seen_links = set()

    def check_one(path: Path, *, depth: int = 0) -> None:
        if depth > 8:
            errors.append('venv_symlink_depth_exceeded:' + str(path))
            return
        try:
            st = path.lstat()
        except OSError:
            errors.append('venv_missing:' + str(path))
            return
        if st.st_uid != 0:
            errors.append('venv_not_root_owned:' + str(path))
        if not stat.S_ISLNK(st.st_mode) and stat.S_IMODE(st.st_mode) & 0o022:
            errors.append('venv_untrusted_writable:' + str(path))
        if stat.S_ISLNK(st.st_mode):
            if path in seen_links:
                return
            seen_links.add(path)
            try:
                target = path.resolve(strict=True)
            except (OSError, RuntimeError):
                errors.append('venv_broken_symlink:' + str(path))
                return
            if target == path:
                errors.append('venv_circular_symlink:' + str(path))
                return
            # Every ancestor of the ultimate target must also be trusted;
            # a root-owned link into /tmp is not safe.
            cursor = target
            while True:
                check_one(cursor, depth=depth + 1) if cursor == target else check_parent(cursor)
                if cursor == cursor.parent:
                    break
                cursor = cursor.parent

    def check_parent(path: Path) -> None:
        try:
            st = path.lstat()
        except OSError:
            errors.append('venv_target_parent_missing:' + str(path))
            return
        if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022 or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            errors.append('venv_untrusted_target_parent:' + str(path))

    stack = [venv]
    counter = 0
    while stack:
        directory = stack.pop()
        check_one(directory)
        try:
            with os.scandir(directory) as scanned:
                entries = list(scanned)
        except OSError:
            errors.append('venv_unreadable_directory:' + str(directory))
            continue
        for entry in entries:
            counter += 1
            if counter > max_entries:
                errors.append('venv_tree_too_large_to_attest')
                return errors
            path = Path(entry.path)
            check_one(path)
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
            except OSError:
                errors.append('venv_entry_unreadable:' + str(path))
    return errors


def _trusted_verifier_code() -> list[str]:
    """Fail closed if the inspection program itself could be agent-modified.

    This self-check is an additional deployment diagnostic, not an attestation:
    the operator/OS must independently install and protect this code. An agent
    that can replace the verifier can remove its self-check entirely.
    """
    files = (Path(__file__).absolute(), Path(hermes_audit.__file__).absolute(),
             Path(strict_yaml.__file__).absolute(), Path(profile_guard.__file__).absolute())
    folder = files[0].parent
    errors=[]
    if any(path.parent != folder for path in files):
        errors.append('verifier_local_import_outside_trusted_directory')
    for path in files:
        errors.extend('verifier:' + error for error in _safe_file(path, root_owner=True))
    # Imported Python bytecode may be loaded in lieu of root-owned .py files.
    # A writable cache directory is not acceptable in a protected install.
    cache = folder / '__pycache__'
    if cache.exists() or cache.is_symlink():
        try:
            st = cache.lstat()
            if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
                    or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022):
                errors.append('verifier_untrusted_bytecode_cache')
            else:
                for item in cache.iterdir():
                    info=item.lstat()
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                            or stat.S_IMODE(info.st_mode) & 0o022):
                        errors.append('verifier_untrusted_cached_module:' + str(item))
        except OSError:
            errors.append('verifier_unreadable_bytecode_cache')
    return errors


def inspect_snapshot(snapshot: Any, *, config_sha256: str, home: Path,
                     expect: str = "armed", expected_uid: int | None = None) -> dict:
    errors = []
    if not isinstance(snapshot, dict) or type(snapshot.get('version')) is not int or snapshot['version'] != 1:
        return {'passed': False, 'errors': ['bad_or_missing_runtime_snapshot']}
    if 'error' in snapshot:
        errors.append('runtime_probe_failed:' + str(snapshot['error'])[:200])
    if snapshot.get('config_sha256_before') != config_sha256 or snapshot.get('config_sha256_after') != config_sha256:
        errors.append('config_changed_or_not_matching_operator_pin')
    if snapshot.get('home') != str(home):
        errors.append('wrong_hermes_profile_home')
    if type(snapshot.get('uid')) is not int or (expected_uid is not None and snapshot.get('uid') != expected_uid):
        errors.append('runtime_not_executed_as_expected_agent_uid')
    toolsets = snapshot.get('resolved_toolsets')
    if not isinstance(toolsets, list) or any(not isinstance(v,str) for v in toolsets) or len(toolsets) != len(set(toolsets)):
        errors.append('invalid_runtime_toolsets')
    elif set(toolsets) != EXPECTED_TOOLSETS:
        errors.append('additional_or_missing_runtime_toolsets:' + ','.join(sorted(set(toolsets) ^ EXPECTED_TOOLSETS)))
    names = snapshot.get('tool_names')
    if not isinstance(names, list) or len(names) > 100 or any(not isinstance(v,str) or not v or len(v)>128 for v in names) or len(names) != len(set(names)):
        errors.append('invalid_or_duplicate_runtime_tool_schemas')
    elif set(names) != (EXPECTED_NAMES if expect == 'armed' else set()):
        errors.append('unexpected_runtime_tool_names:' + ','.join(sorted(set(names) ^ (EXPECTED_NAMES if expect == 'armed' else set()))))
    if expect not in ('armed','paused'):
        errors.append('invalid_expected_mode')
    return {'passed': not errors, 'errors': errors, 'expect': expect,
            'observed_toolsets': toolsets if isinstance(toolsets,list) else None,
            'observed_tools': names if isinstance(names,list) else None,
            'scope': 'Resolved Hermes CLI snapshot only; NOT proof of unmediated OS containment'}


def _run_bounded(argv: list[str], *, env: dict[str,str], timeout: int) -> tuple[int,bytes]:
    """Read a finite amount; kill entire subprocess group on hang or flood."""
    if sys.platform != 'linux':
        raise OSError('protected_runtime_probe_linux_only')
    proc=subprocess.Popen(argv, stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT,env=env,start_new_session=True,bufsize=0)
    buffer=bytearray()
    deadline=time.monotonic()+timeout
    sel=selectors.DefaultSelector()
    assert proc.stdout is not None
    sel.register(proc.stdout,selectors.EVENT_READ)
    try:
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:
                raise TimeoutError('runtime_probe_timeout')
            ready=sel.select(min(remaining,0.5))
            if not ready:
                if proc.poll() is not None:
                    # A child inherited stdout; do not wait forever for EOF.
                    continue
                continue
            chunk=os.read(proc.stdout.fileno(),min(8192,MAX_OUTPUT+1-len(buffer)))
            if not chunk:
                break
            buffer.extend(chunk)
            if len(buffer)>MAX_OUTPUT:
                raise ValueError('runtime_probe_output_oversized')
        remaining=deadline-time.monotonic()
        if remaining<=0:
            raise TimeoutError('runtime_probe_timeout')
        code=proc.wait(timeout=remaining)
        return code,bytes(buffer)
    finally:
        sel.close()
        # The direct child may have exited while a descendant inherited the
        # pipe. Kill its whole dedicated process group even after parent exit.
        # This is not a substitute for a kernel cgroup on protected hosts.
        try: os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        try:proc.wait(timeout=2)
        except subprocess.TimeoutExpired: pass
        proc.stdout.close()


def _read_snapshot(output: bytes) -> dict:
    if len(output)>MAX_OUTPUT:
        raise ValueError('runtime_probe_output_oversized')
    decoded=output.decode('utf-8','strict')
    matched=[s[len(MARKER):] for s in decoded.splitlines() if s.startswith(MARKER)]
    if len(matched)!=1:
        raise ValueError('no_unique_runtime_snapshot')
    if len(matched[0])>65536:
        raise ValueError('runtime_snapshot_oversized')
    def unique_pairs(items):
        d={}
        for k,v in items:
            if k in d: raise ValueError('runtime_snapshot_duplicate_key')
            d[k]=v
        return d
    obj=json.loads(matched[0],object_pairs_hook=unique_pairs)
    if not isinstance(obj,dict):
        raise ValueError('runtime_snapshot_not_object')
    return obj


def verify_hermes(*, python: Path, home: Path, expect: str='armed',
                  timeout: int=30, expected_uid: int | None=None,
                  require_trusted_python: bool=True) -> dict:
    errors=[]
    home=home.absolute()
    python=python.absolute()
    config=home/'config.yaml'
    if sys.platform != 'linux':
        errors.append('protected_probe_requires_linux')
    if os.geteuid()==0:
        errors.append('must_not_run_as_root')
    if expected_uid is not None and os.geteuid()!=expected_uid:
        errors.append('current_os_identity_not_agent_uid')
    if not isinstance(timeout,int) or not 1<=timeout<=60:
        errors.append('invalid_timeout')
    if require_trusted_python:
        errors.extend(_trusted_verifier_code())
    errors.extend('config:'+e for e in _safe_file(config))
    errors.extend('python:'+e for e in _safe_file(python,root_owner=require_trusted_python))
    if require_trusted_python and not any(x.startswith('python:') for x in errors):
        errors.extend('python_env:'+e for e in _trusted_venv_tree(python))
    if errors:
        return {'passed': False,'errors': errors,'scope':'preflight_failure'}
    original=config.read_bytes()
    digest=hashlib.sha256(original).hexdigest()
    config_data=load_config(original)
    config_audit=audit(config_data,'catl','protected')
    if not config_audit['passed']:
        return {'passed': False,'errors':['protected_config_invalid:'+x for x in config_audit['errors']]}
    # Minimise environmental contamination. HERMES_HOME identifies the isolated
    # profile; the agent user should have no privileged credentials at all.
    clean={'HERMES_HOME':str(home),'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',
           'PYTHONDONTWRITEBYTECODE':'1'}
    rc,out=_run_bounded([str(python),'-I','-c',SNAPSHOT_CODE],env=clean,timeout=timeout)
    if rc!=0:
        return {'passed':False,'errors':['runtime_probe_nonzero_exit'],'returncode':rc}
    snapshot=_read_snapshot(out)
    report=inspect_snapshot(snapshot,config_sha256=digest,home=home,expect=expect,expected_uid=expected_uid)
    report['config_sha256']=digest
    report['runtime_python']=str(python)
    return report


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hermes-python',type=Path,required=True)
    p.add_argument('--hermes-home',type=Path,required=True)
    p.add_argument('--expect',choices=['armed','paused'],default='armed')
    p.add_argument('--timeout',type=int,default=30)
    p.add_argument('--agent-uid',type=int,required=True)
    p.add_argument('--allow-untrusted-python',action='store_true',
                   help='DIAGNOSTIC ONLY: allow agent-owned interpreter; result is NOT high-assurance')
    a=p.parse_args(argv)
    try:
        r=verify_hermes(python=a.hermes_python,home=a.hermes_home,expect=a.expect,
                        timeout=a.timeout,expected_uid=a.agent_uid,
                        require_trusted_python=not a.allow_untrusted_python)
        if a.allow_untrusted_python:
            # Never signal readiness to an orchestrator when the interpreter
            # and its imports are agent-modifiable. Diagnostic only.
            r['low_assurance']=True
            r['diagnostic_result_only']=r.get('passed',False)
            r['passed']=False
            r.setdefault('errors',[]).append('untrusted_interpreter_cannot_certify_protected_profile')
        print(json.dumps(r,indent=2,sort_keys=True))
        return 0 if r['passed'] else 1
    except (OSError,ValueError,RuntimeError,TimeoutError) as e:
        print(json.dumps({'passed':False,'errors':[type(e).__name__+':'+str(e)[:240]]}))
        return 1

if __name__=='__main__': raise SystemExit(main())
