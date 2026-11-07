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
import signal
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_FILES = 10000


def _git(repo: Path, *args: str) -> str:
    process = subprocess.run(["git", *args], cwd=repo, check=True,
                             capture_output=True, timeout=15)
    return process.stdout.decode("utf-8", "strict").strip()


def _git_files(repo: Path) -> set[str]:
    proc = subprocess.run(["git", "ls-files", "-z"], cwd=repo, check=True,
                          capture_output=True, timeout=15)
    return {part.decode("utf-8", "strict") for part in proc.stdout.split(b"\0") if part}


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


def run(repo: Path, out: Path, *, timeout: int=900, expected_commit: str | None=None) -> dict:
    repo=repo.resolve(strict=True)
    out=out.resolve(strict=False)
    # Avoid writing run artifacts back into the repository being verified.
    if out==repo or repo in out.parents:
        raise ValueError("output_must_be_outside_repo")
    out.mkdir(parents=True,exist_ok=True)
    status={"tool":"catl_offline_native_acceptance_v1","repo":str(repo),
            "result":"FAIL","suite":"unittest test_*.py","test_count":0,
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
        if _git(repo,"status","--porcelain","--untracked-files=no"):
            raise ValueError("tracked_source_dirty")
        status.update(verify_files(repo))
        # Do not inherit credentials or cloud identifiers from the operator shell.
        allowed=("PATH","LANG","LC_ALL","SYSTEMROOT","WINDIR","HOME","TMP","TEMP","TMPDIR")
        env={key:os.environ[key] for key in allowed if key in os.environ}
        env["PYTHONPATH"]=str(repo/"src")
        cmd=[sys.executable,"-m","unittest","discover","-s","tests","-p","test_*.py","-v"]
        status["command"]=cmd
        log=out/"native-unittest.log"
        with log.open("wb") as stream:
            proc = subprocess.Popen(cmd,cwd=repo,env=env,stdin=subprocess.DEVNULL,
                                    stdout=stream,stderr=subprocess.STDOUT,
                                    start_new_session=(os.name == "posix"))
            try:
                status["exit_code"] = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Kill the entire immediate test process group, not just
                # unittest; a hung subprocess must not survive the timeout.
                if os.name == "posix":
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    proc.kill()
                proc.wait(timeout=10)
                status["exit_code"] = 124
                status["failure"] = "native_suite_timeout"
        output=log.read_text(encoding="utf-8",errors="replace")
        match=re.search(r"Ran (\d+) tests? in",output)
        status["test_count"]=int(match[1]) if match else 0
        status["skipped"]=len(re.findall(r"\.\.\. skipped ",output))
        status["log_sha256"]=_file_hash(log)
        if status["exit_code"] != 0 or status["test_count"] < 1 or "\nOK" not in output:
            raise RuntimeError("native_unit_suite_incomplete_or_failed")
        status["result"]="PASS_UNIT_SUITE_ONLY"
    except (ValueError,OSError,subprocess.SubprocessError,RuntimeError,UnicodeError,json.JSONDecodeError) as exc:
        status["failure"] = str(exc)
    finally:
        (out/"acceptance.json").write_text(json.dumps(status,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return status


def main(argv: list[str] | None=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo",type=Path,default=Path.cwd())
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--timeout",type=int,default=900)
    parser.add_argument("--expected-commit",type=str)
    args=parser.parse_args(argv)
    if not 10 <= args.timeout <= 7200:
        parser.error("timeout must be 10..7200 seconds")
    if args.expected_commit and not re.fullmatch(r"[0-9a-f]{40}",args.expected_commit):
        parser.error("expected commit must be 40 lowercase hex digits")
    result=run(args.repo,args.out,timeout=args.timeout,expected_commit=args.expected_commit)
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result["result"]=="PASS_UNIT_SUITE_ONLY" else 1


if __name__=="__main__":
    raise SystemExit(main())
