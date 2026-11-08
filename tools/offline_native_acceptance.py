"""Offline native CATL regression acceptance (no GitHub Actions or live Hermes).

Run only from a trusted, fully cloned CATL repository. This tool reads the
source tree, verifies SHA-256 manifest and index, then executes unit regressions
in a bounded subprocess. It does not install packages, pull, push or invoke CI.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import time
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_FILES = 10000
MAX_NATIVE_LOG_BYTES = 32 * 1024 * 1024


def _git_process(repo: Path, *args: str) -> bytes:
    """Never inherit Git hooks/fsmonitor, executable diff drivers or user PATH.

    Keep this dependency-free: the native runner itself must validate sources
    *before* importing or executing any untrusted checkout Python module.
    """
    env = {
        'PATH': os.defpath, 'LC_ALL': 'C',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
        'GIT_CONFIG_SYSTEM': os.devnull, 'GIT_OPTIONAL_LOCKS': '0',
    }
    if os.name == 'nt':
        env['SystemRoot'] = os.environ.get('SystemRoot', '')
        env['WINDIR'] = os.environ.get('WINDIR', '')
    argv = ['git', '--no-replace-objects',
            '-c', 'core.fsmonitor=false', '-c', 'diff.external=',
            '-c', 'core.hooksPath=' + os.devnull, *args]
    return subprocess.run(argv, cwd=repo, env=env, check=True,
                          capture_output=True, timeout=15).stdout


def _git(repo: Path, *args: str) -> str:
    return _git_process(repo, *args).decode('utf-8', 'strict').strip()


def _git_files(repo: Path) -> set[str]:
    raw = _git_process(repo, 'ls-files', '-z')
    return {part.decode('utf-8', 'strict') for part in raw.split(b'\0') if part}


def _safe_source_path(repo: Path, name: str) -> Path:
    if (not isinstance(name, str) or not name or "\\" in name or "\x00" in name
            or name.startswith("/") or "//" in name):
        raise ValueError("unsafe_manifest_path")
    pure = PurePosixPath(name)
    if any(x in (".", "..") for x in name.split("/")) or str(pure) != name:
        raise ValueError("unsafe_manifest_path")
    p = repo.joinpath(*pure.parts)
    info = p.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
        raise ValueError("non_regular_or_oversized_source")
    # Every directory in the path must be an actual directory (no symlink pivots).
    cur = repo
    for part in pure.parts[:-1]:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError("source_directory_symlink")
    return p


def _file_hash(p: Path) -> str:
    d = hashlib.sha256()
    with p.open("rb") as stream:
        while buf := stream.read(1024 * 1024):
            d.update(buf)
    return d.hexdigest()


def verify_exact_git_source(repo: Path, commit: str) -> dict:
    """Validate a sealed checkout before executing ANY repository Python.

    The index/porcelain status can conceal `skip-worktree` modifications; a
    manifest and checksum file can also be changed in tandem. Git's immutable
    HEAD tree provides the authority, never those editable files or the index.
    Refuse all additional worktree entries (including .gitignored bytecode,
    import hooks and local modules) that could change code under test.
    """
    if not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', commit):
        raise ValueError('native_source_commit_invalid')
    algorithm = _git(repo, 'rev-parse', '--show-object-format')
    if algorithm not in ('sha1', 'sha256') or len(commit) != (40 if algorithm == 'sha1' else 64):
        raise ValueError('native_source_git_object_format_invalid')
    if _git(repo, 'rev-parse', 'HEAD') != commit:
        raise ValueError('native_source_head_changed')
    tree = _git_process(repo, 'ls-tree', '-r', '-z', '--full-tree', commit)
    expected: dict[str, tuple[str, bytes]] = {}
    for entry in tree.split(b'\0'):
        if not entry:
            continue
        try:
            metadata, encoded_name = entry.split(b'\t', 1)
            mode, kind, oid = metadata.split(b' ')
            name = encoded_name.decode('utf-8', 'strict')
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError('native_source_git_tree_invalid') from exc
        if (kind != b'blob' or mode not in (b'100644', b'100755')
                or not name or name.startswith('/') or '\\' in name
                or any(part in ('', '.', '..') for part in name.split('/'))
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in name)
                or len(oid) != len(commit) or not re.fullmatch(rb'[0-9a-f]+', oid)):
            raise ValueError('native_source_git_entry_untrusted:' + name[:150])
        if name in expected:
            raise ValueError('native_source_duplicate_git_entry')
        expected[name] = (oid.decode('ascii'), mode)
    if not expected or len(expected) > MAX_FILES:
        raise ValueError('native_source_file_set_invalid')
    permitted_dirs = {'.'}
    for name in expected:
        components = name.split('/')
        for i in range(1, len(components)):
            permitted_dirs.add('/'.join(components[:i]))
    observed = set()
    stack: list[tuple[Path, str]] = [(repo, '.')]
    nodes = 0
    verified_bytes = 0
    while stack:
        directory, label = stack.pop()
        with os.scandir(directory) as entries:
            for item in entries:
                # A Git checkout may represent .git as a directory or a
                # worktree pointer file. Neither is executable source.
                if label == '.' and item.name == '.git':
                    continue
                name = item.name if label == '.' else label + '/' + item.name
                nodes += 1
                if nodes > MAX_FILES * 4:
                    raise ValueError('native_source_worktree_node_limit')
                info = item.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if name not in permitted_dirs:
                        raise ValueError('native_source_untracked_directory:' + name[:150])
                    stack.append((Path(item.path), name))
                    continue
                if not stat.S_ISREG(info.st_mode) or name not in expected:
                    raise ValueError('native_source_untracked_or_nonregular:' + name[:150])
                if info.st_nlink != 1 or info.st_size < 0 or info.st_size > MAX_SOURCE_BYTES:
                    raise ValueError('native_source_untrusted_file:' + name[:150])
                oid, mode = expected[name]
                if bool(info.st_mode & 0o111) != (mode == b'100755'):
                    raise ValueError('native_source_file_mode_changed:' + name[:150])
                fd = os.open(item.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                try:
                    before = os.fstat(fd)
                    if (not stat.S_ISREG(before.st_mode) or before.st_ino != info.st_ino
                            or before.st_dev != info.st_dev or before.st_nlink != 1
                            or before.st_size != info.st_size):
                        raise ValueError('native_source_file_race:' + name[:150])
                    with os.fdopen(fd, 'rb', closefd=False) as stream:
                        payload = stream.read(MAX_SOURCE_BYTES + 1)
                    after = os.fstat(fd)
                    if (len(payload) != before.st_size or after.st_mtime_ns != before.st_mtime_ns
                            or after.st_ctime_ns != before.st_ctime_ns or after.st_size != before.st_size):
                        raise ValueError('native_source_changed_during_verification:' + name[:150])
                finally:
                    os.close(fd)
                actual = hashlib.new(algorithm, b'blob ' + str(len(payload)).encode('ascii') + b'\0' + payload).hexdigest()
                if actual != oid:
                    raise ValueError('native_source_not_equal_committed_blob:' + name[:150])
                observed.add(name)
                verified_bytes += len(payload)
                if verified_bytes > 64 * 1024 * 1024:
                    raise ValueError('native_source_total_byte_limit')
    if observed != set(expected):
        raise ValueError('native_source_tracked_file_missing')
    if _git(repo, 'rev-parse', 'HEAD') != commit:
        raise ValueError('native_source_head_changed_during_scan')
    return {'exact_git_commit_verified': True, 'git_object_format': algorithm,
            'committed_files_verified': len(expected), 'committed_bytes_verified': verified_bytes,
            'untracked_source_entries': 0}


def _validated_local_xvfb_env() -> dict[str, str]:
    """Opt-in local Unix X11 display for GUI acceptance; never remote DISPLAY."""
    display = os.environ.get('DISPLAY', '')
    xauthority = os.environ.get('XAUTHORITY', '')
    if not re.fullmatch(r':[0-9]{1,4}(?:\.[0-9]{1,2})?', display):
        raise ValueError('native_xvfb_must_be_local_unix_display')
    path = Path(xauthority)
    if not path.is_absolute() or not path.exists() or path.is_symlink():
        raise ValueError('native_xauthority_path_untrusted')
    info = path.stat()
    parent = path.parent.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_mode & 0o077
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o022 or path.parent.is_symlink()):
        raise ValueError('native_xauthority_permissions_untrusted')
    return {'DISPLAY': display, 'XAUTHORITY': str(path)}

def verify_files(repo: Path) -> dict:
    manifest_path = repo / "RELEASE_MANIFEST.json"
    sums_path = repo / "SHA256SUMS.txt"
    for p in (manifest_path, sums_path):
        _safe_source_path(repo, p.name)
    def no_duplicate_keys(pairs):
        result = {}
        for key,value in pairs:
            if key in result:
                raise ValueError("manifest_duplicate_key")
            result[key] = value
        return result
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"),
                          object_pairs_hook=no_duplicate_keys)
    if not isinstance(manifest, dict):
        raise ValueError("manifest_schema_invalid")
    hashes = manifest.get("files")
    if manifest.get("algorithm") != "sha256" or not isinstance(hashes, dict) or not 1 <= len(hashes) <= MAX_FILES:
        raise ValueError("manifest_schema_invalid")
    expected = {}
    for name,hexdigest in hashes.items():
        if not isinstance(hexdigest, str) or not re.fullmatch(r"[0-9a-f]{64}",hexdigest):
            raise ValueError("manifest_digest_invalid")
        actual = _file_hash(_safe_source_path(repo, name))
        if actual != hexdigest:
            raise ValueError("manifest_hash_mismatch:" + name)
        expected[name] = actual
    observed = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (.+)",line)
        if not m or m[2] in observed:
            raise ValueError("checksum_index_malformed_or_duplicate")
        observed[m[2]] = m[1]
    if observed != expected:
        raise ValueError("checksum_index_mismatch")
    tracked = _git_files(repo)
    tracked.difference_update({"RELEASE_MANIFEST.json", "SHA256SUMS.txt"})
    if tracked != set(expected):
        raise ValueError("git_tracked_files_and_manifest_disagree")
    return {"verified_files":len(expected),"manifest_sha256":_file_hash(manifest_path),
            "checksum_index_sha256":_file_hash(sums_path)}



def _trusted_report_directory(path: Path) -> tuple[Path, int]:
    """Create/open a private report directory without traversing untrusted links.

    This runner is Linux/POSIX evaluation software, not a privileged installer.
    Every ancestor must be protected against replacement by other users;
    root-owned sticky /tmp-style directories are the only writable exception.
    """
    if os.name != 'posix':
        raise PermissionError('native_report_directory_posix_required')
    target = Path(os.path.abspath(os.fspath(path)))  # DO NOT resolve symlinks
    root = Path('/')
    for node in reversed([target, *target.parents]):
        try:
            info = node.lstat()
        except FileNotFoundError:
            node.mkdir(mode=0o700)
            info = node.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise PermissionError('native_report_ancestor_not_real_directory:' + str(node))
        if info.st_uid not in (0, os.geteuid()):
            raise PermissionError('native_report_ancestor_wrong_owner:' + str(node))
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            if not (node != target and info.st_uid == 0
                    and info.st_mode & stat.S_ISVTX and info.st_mode & stat.S_IWOTH):
                raise PermissionError('native_report_ancestor_writable:' + str(node))
    info = target.lstat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PermissionError('native_report_directory_not_private')
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    dir_fd = os.open(target, flags)
    actual = os.fstat(dir_fd)
    if (not stat.S_ISDIR(actual.st_mode) or actual.st_dev != info.st_dev
            or actual.st_ino != info.st_ino or actual.st_uid != os.geteuid()
            or actual.st_mode & 0o077):
        os.close(dir_fd)
        raise PermissionError('native_report_directory_race_or_not_private')
    for name in ('native-unittest.log', 'acceptance.json'):
        try:
            os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        os.close(dir_fd)
        raise FileExistsError('native_report_output_already_exists:' + name)
    return target, dir_fd


def _create_private_report(dir_fd: int, name: str) -> int:
    """Never overwrite existing evidence or follow an attacker-made symlink."""
    if name not in ('native-unittest.log', 'acceptance.json'):
        raise ValueError('native_report_filename_unexpected')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=dir_fd)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_mode & 0o077):
        os.close(fd)
        raise PermissionError('native_report_file_not_private')
    return fd



def _execute_native_suite(cmd: list[str], *, cwd: Path, env: dict[str, str],
                          stream, timeout: int) -> tuple[int, str | None]:
    """Stream bounded test stdout; refuse lingering pipe-owning descendants.

    A post-run size check is insufficient: an untrusted test could consume the
    entire disk before the runner notices. This uses a POSIX pipe so the parent
    can stop the process group as soon as the byte budget is exhausted.
    """
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            start_new_session=True, bufsize=0)
    deadline = time.monotonic() + timeout
    output_bytes = 0
    issue: str | None = None
    saw_eof = False
    try:
        assert proc.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    issue = 'native_suite_timeout'
                    break
                ready = selector.select(timeout=remaining)
                if not ready:
                    issue = 'native_suite_timeout'
                    break
                data = os.read(proc.stdout.fileno(), 65536)
                if not data:
                    saw_eof = True
                    break
                available = MAX_NATIVE_LOG_BYTES - output_bytes
                if len(data) > available:
                    if available:
                        stream.write(data[:available])
                        output_bytes += available
                    issue = 'native_suite_log_size_limit'
                    break
                stream.write(data)
                output_bytes += len(data)
        if saw_eof:
            try:
                proc.wait(timeout=max(0, deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                issue = 'native_suite_timeout'
    finally:
        # Always supervise the entire immediately-owned process group, not
        # only the unittest process. No background child should survive a
        # timed-out or failed acceptance process by holding the output pipe.
        if issue is not None or proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if proc.stdout is not None:
            proc.stdout.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if issue == 'native_suite_timeout':
        return 124, issue
    if issue == 'native_suite_log_size_limit':
        return 125, issue
    return proc.returncode, None


def run(repo: Path, out: Path, *, timeout: int=900, expected_commit: str | None=None,
        minimum_tests: int=1, maximum_skips: int=10000,
        allow_local_xvfb: bool=False) -> dict:
    if (type(minimum_tests) is not int or not 1 <= minimum_tests <= 10000
            or type(maximum_skips) is not int or not 0 <= maximum_skips <= 10000):
        raise ValueError('native_test_count_limits_invalid')
    repo=repo.resolve(strict=True)
    raw_out = Path(os.path.abspath(os.fspath(out)))
    out_resolved = raw_out.resolve(strict=False)
    # Avoid writing run artifacts back into the repository being verified.
    if out_resolved==repo or repo in out_resolved.parents:
        raise ValueError("output_must_be_outside_repo")
    out, report_fd = _trusted_report_directory(raw_out)
    status={"tool":"catl_offline_native_acceptance_v1","repo":str(repo),
            "result":"FAIL","suite":"unittest test_*.py","test_count":0,
            "minimum_tests":minimum_tests,"maximum_skips":maximum_skips,
            "skipped":0,"full_host_e2e":"NOT_RUN","live_hermes":"NOT_RUN",
            "independent_pentest":"NOT_RUN","github_actions":"NOT_INVOKED"}
    try:
        if not (repo/"src"/"catl").is_dir() or not (repo/"tests").is_dir():
            raise ValueError("catl_repo_layout_missing")
        root = _git(repo,"rev-parse","--show-toplevel")
        if Path(root).resolve() != repo:
            raise ValueError("git_root_mismatch")
        status["commit"]=_git(repo,"rev-parse","HEAD")
        if expected_commit is not None and status["commit"] != expected_commit:
            raise ValueError("unexpected_checkout_commit")
        # Git status/diff may execute repository-defined .gitattributes clean
        # filters. Inspect file bytes/modes directly against immutable HEAD,
        # not via Git's worktree diff machinery.
        try:
            status.update(verify_exact_git_source(repo, status['commit']))
        except ValueError as exc:
            if str(exc).startswith('native_source_not_equal_committed_blob:'):
                raise ValueError('tracked_source_dirty (' + str(exc) + ')') from exc
            raise
        status.update(verify_files(repo))
        # Do not inherit credentials or cloud identifiers from the operator shell.
        allowed=("PATH","LANG","LC_ALL","SYSTEMROOT","WINDIR","HOME","TMP","TEMP","TMPDIR")
        env={key:os.environ[key] for key in allowed if key in os.environ}
        env["PYTHONPATH"]=str(repo/"src")
        env["PYTHONNOUSERSITE"]="1"
        env["PYTHONDONTWRITEBYTECODE"]="1"
        if allow_local_xvfb:
            env.update(_validated_local_xvfb_env())
        cmd=[sys.executable,"-m","unittest","discover","-s","tests","-p","test_*.py","-v"]
        status["command"]=cmd
        log=out/"native-unittest.log"
        with os.fdopen(_create_private_report(report_fd, "native-unittest.log"), "wb") as stream:
            status["exit_code"], suite_issue = _execute_native_suite(
                cmd, cwd=repo, env=env, stream=stream, timeout=timeout)
            stream.flush()
            os.fsync(stream.fileno())
        if suite_issue:
            status["suite_failure_reason"] = suite_issue
        status["log_sha256"]=_file_hash(log)
        if log.stat().st_size > MAX_NATIVE_LOG_BYTES:
            raise RuntimeError('native_suite_log_size_limit')
        output=log.read_text(encoding="utf-8",errors="replace")
        # Test modules can print counterfeit "Ran N tests" banners. The
        # unittest runner's final banner must be used, never the first match.
        summaries=re.findall(r"(?m)^Ran (\d+) tests? in [0-9.]+s\s*$",output)
        status["test_count"]=int(summaries[-1]) if summaries else 0
        status["skipped"]=len(re.findall(r"\.\.\. skipped ",output))
        if (suite_issue == "native_suite_log_size_limit"):
            raise RuntimeError("native_suite_log_size_limit")
        if (status["exit_code"] != 0 or status["test_count"] < minimum_tests
                or status["skipped"] > maximum_skips
                or status["test_count"] <= status["skipped"]
                or "\nOK" not in output):
            raise RuntimeError("native_unit_suite_incomplete_or_failed")
        # A successful test run does NOT authorise changed or injected source.
        # Reject tests that leave executable artefacts, bytecode or edited
        # tracked files behind in the supposedly reviewed checkout.
        verify_exact_git_source(repo, status['commit'])
        status["post_test_source_integrity"]="PASS_EXACT_GIT_TREE"
        status["result"]="PASS_UNIT_SUITE_ONLY"
    except (ValueError,OSError,subprocess.SubprocessError,RuntimeError,UnicodeError,json.JSONDecodeError) as exc:
        status["failure"] = str(exc)
    finally:
        try:
            with os.fdopen(_create_private_report(report_fd, "acceptance.json"), 'w', encoding='utf-8') as report:
                report.write(json.dumps(status,indent=2,sort_keys=True)+"\n")
                report.flush()
                os.fsync(report.fileno())
        finally:
            os.close(report_fd)
    return status


def main(argv: list[str] | None=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo",type=Path,default=Path.cwd())
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--timeout",type=int,default=900)
    parser.add_argument("--expected-commit",type=str)
    parser.add_argument("--minimum-tests",type=int,default=1)
    parser.add_argument("--maximum-skips",type=int,default=10000)
    parser.add_argument("--allow-local-xvfb",action="store_true")
    args=parser.parse_args(argv)
    if not 10 <= args.timeout <= 7200:
        parser.error("timeout must be 10..7200 seconds")
    if args.expected_commit and not re.fullmatch(r"[0-9a-f]{40}",args.expected_commit):
        parser.error("expected commit must be 40 lowercase hex digits")
    if not 1 <= args.minimum_tests <= 10000 or not 0 <= args.maximum_skips <= 10000:
        parser.error("minimum-tests and maximum-skips outside allowed bounds")
    result=run(args.repo,args.out,timeout=args.timeout,expected_commit=args.expected_commit,
               minimum_tests=args.minimum_tests,maximum_skips=args.maximum_skips,
               allow_local_xvfb=args.allow_local_xvfb)
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result["result"]=="PASS_UNIT_SUITE_ONLY" else 1


if __name__=="__main__":
    raise SystemExit(main())
