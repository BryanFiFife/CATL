#!/usr/bin/env python3
"""Preview or safely append CATL MCP configuration to an existing Hermes YAML config.

Default is PREVIEW ONLY. Actual application requires --apply --accept-reformat.
Hermes configuration and all pre-existing MCP servers are preserved semantically;
original file is backed up byte-for-byte before any write.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from datetime import datetime, timezone
from strict_yaml import load_config
from profile_guard import expected_platform_toolsets, validate_restricted_profile, NATIVE_DISABLED_TOOLSETS


def entry(mode: str, catl: Path, source: Path | None, state: Path | None, socket: Path) -> dict:
    if not catl.is_absolute():
        raise ValueError("CATL command must use an absolute path")
    if mode == "demo":
        if source is None or state is None:
            raise ValueError("Demo requires --source-dir and --state-dir")
        source, state = source.expanduser(), state.expanduser()
        if not source.is_absolute() or not state.is_absolute():
            raise ValueError("Demo source and state paths must be absolute")
        python = catl.parent / ("python.exe" if os.name == "nt" else "python")
        if os.name == "nt" and catl.suffix == ".exe":
            python = catl.parent / "python.exe"
        args = ["run", "--config", str(source / "examples/policy.json"),
                "--state-dir", str(state), "--allow-unsandboxed", "--",
                str(python), str(source / "examples/mock_server.py")]
    elif mode == "protected":
        if os.name != "posix" or not sys.platform.startswith("linux"):
            raise ValueError("Protected CATL broker only runs on Linux")
        if not socket.is_absolute():
            raise ValueError("Agent socket path must be absolute")
        # The reviewed protected profile uses immutable, separately installed
        # administrator-owned paths. Custom paths need their own review.
        if str(catl) != '/opt/catl-venv/bin/catl' or str(socket) != '/run/catl-agent/agent.sock':
            raise ValueError("Protected mode requires the reviewed /opt/catl-venv/bin/catl executable and /run/catl-agent/agent.sock socket")
        args = ["shim", "--agent-socket", str(socket)]
    else:
        raise ValueError("Unknown CATL mode")
    return {
        "command": str(catl), "args": args, "enabled": True,
        "lazy": False, "timeout": 45, "connect_timeout": 15,
        # Hermes defaults MCP sampling on; explicitly forbid CATL-mediated tool
        # outputs from obtaining a new inference channel outside the tool policy.
        "sampling": {"enabled": False},
        "events": False,
        "supports_parallel_tool_calls": False,
        "tools": {"include": ["echo_safe", "write_demo"], "resources": False, "prompts": False},
    }


def new_config(current: object, server_name: str, value: dict, *, protected: bool = False) -> dict:
    if current is None:
        current = {}
    if not isinstance(current, dict) or any(not isinstance(k, str) for k in current):
        raise ValueError("Hermes YAML root must be a mapping with string keys")
    result = dict(current)
    original = result.get("mcp_servers")
    if original is None:
        original = {}
    if not isinstance(original, dict):
        raise ValueError("mcp_servers already exists but is not a mapping")
    if server_name in original:
        raise FileExistsError(f"MCP server {server_name!r} already configured; no overwrite permitted")
    if protected:
        active_other = [n for n, srv in original.items()
                        if not isinstance(srv, dict) or srv.get("enabled") is not False]
        if active_other:
            raise PermissionError("Protected profile has enabled/unclassified non-CATL MCP servers: " + ", ".join(active_other))
        # The legacy top-level 'toolsets' is ignored in current Hermes.
        # This dedicated CLI profile uses the current platform_toolsets field.
        if "toolsets" in result:
            raise PermissionError("Remove deprecated top-level toolsets from the dedicated profile; it is ignored by Hermes")
        expected = expected_platform_toolsets(server_name)
        existing = result.get("platform_toolsets")
        if existing is not None and existing != expected:
            raise PermissionError("Existing Hermes platform_toolsets differ; use a clean dedicated profile, never overwrite existing tool choices")
        result["platform_toolsets"] = expected
        agent=result.get("agent")
        if agent is None:
            agent={}
        if not isinstance(agent,dict) or agent.get("disabled_toolsets") not in (None,list(NATIVE_DISABLED_TOOLSETS)):
            raise PermissionError("Existing agent.disabled_toolsets differs; do not override another profile's security policy")
        result["agent"]={**agent,"disabled_toolsets":list(NATIVE_DISABLED_TOOLSETS)}
        violations = validate_restricted_profile(result, server_name)
        if violations:
            raise PermissionError("Protected Hermes profile is incompatible: " + "; ".join(violations))
    result["mcp_servers"] = {**original, server_name: value}
    return result


def assert_safe_config_file(path: Path) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise PermissionError("Refusing Hermes config symlink")
    if path.exists():
        s = path.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
            raise PermissionError("Refusing non-regular/multiply linked Hermes config")
        if os.name == "posix" and (s.st_uid != os.geteuid() or s.st_mode & 0o022):
            raise PermissionError("Hermes config has unsafe owner/permissions")
    # Check *all* path components for symlinks, not merely the last parent.
    cursor = path.parent
    while cursor != cursor.parent:
        if cursor.is_symlink():
            raise PermissionError("Refusing Hermes config ancestor symlink")
        cursor = cursor.parent
    if path.parent.exists():
        s = path.parent.stat()
        if os.name == "posix" and (s.st_uid != os.geteuid() or s.st_mode & 0o022):
            raise PermissionError("Hermes config directory is untrusted")


_NO_EXPECTATION = object()


def apply_config(path: Path, config: dict, expected_bytes: bytes | None | object = _NO_EXPECTATION) -> Path | None:
    import yaml
    assert_safe_config_file(path)
    if not path.parent.is_dir():
        raise FileNotFoundError("Hermes config directory does not exist: " + str(path.parent))
    current_bytes = path.read_bytes() if path.exists() else None
    if expected_bytes is not _NO_EXPECTATION and current_bytes != expected_bytes:
        raise RuntimeError("Hermes config changed after its initial read")
    backup = None
    if current_bytes is not None:
        digest = hashlib.sha256(current_bytes).hexdigest()[:12]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = path.with_name(path.name + f".before-CATL-{stamp}-{digest}.bak")
        fd = os.open(str(backup), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(current_bytes)
            fh.flush()
            os.fsync(fh.fileno())
    new_text = yaml.safe_dump(config, sort_keys=False, allow_unicode=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=".catl-hermes-", suffix=".tmp", delete=False) as fh:
            tmp = Path(fh.name)
            fh.write(new_text)
            fh.flush()
            os.fsync(fh.fileno())
        if os.name == "posix":
            tmp.chmod(0o600)
        # Fail if original content changed since parsing; avoid clobbering edits.
        # A short TOCTOU window remains: configuration should be edited while Hermes is stopped.
        if (path.read_bytes() if path.exists() else None) != current_bytes:
            raise RuntimeError("Hermes configuration changed during modification")
        os.replace(tmp, path)
        return backup
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path, default=Path.home() / ".hermes/config.yaml")
    ap.add_argument("--mode", choices=["demo", "protected"], required=True)
    ap.add_argument("--catl", type=Path, required=True, help="Absolute installed CATL CLI path")
    ap.add_argument("--source-dir", type=Path, help="Absolute checked-out CATL repo (demo)")
    ap.add_argument("--state-dir", type=Path, default=Path.home() / ".catl-demo-eval")
    ap.add_argument("--agent-socket", type=Path, default=Path("/run/catl-agent/agent.sock"))
    ap.add_argument("--server-name", default=None)
    ap.add_argument("--dedicated-profile", action="store_true",
                    help="Explicitly confirm this is a disposable, dedicated Hermes profile, NOT the regular profile")
    ap.add_argument("--apply", action="store_true", help="Write YAML to existing Hermes profile")
    ap.add_argument("--accept-reformat", action="store_true", help="Acknowledge that PyYAML may remove comments/formatting; full byte backup created")
    args = ap.parse_args(argv)
    name = args.server_name or ("catl_eval" if args.mode == "demo" else "catl")
    if not name or not all(c.isascii() and (c.isalnum() or c == "_") for c in name):
        ap.error("Server name must contain only ASCII letters, digits or underscores")
    try:
        assert_safe_config_file(args.config)
        item = entry(args.mode, args.catl, args.source_dir, args.state_dir, args.agent_socket)
        try:
            import yaml
        except ImportError:
            raise RuntimeError("PyYAML required: python -m pip install PyYAML")
        source_bytes = args.config.read_bytes() if args.config.exists() else None
        current = load_config(source_bytes)
        if args.mode == "protected" and args.apply:
            if not args.dedicated_profile:
                raise PermissionError("Protected mode requires --dedicated-profile and an isolated catl-agent OS identity")
            default_config = Path.home() / ".hermes" / "config.yaml"
            if args.config.expanduser().absolute() == default_config.absolute():
                raise PermissionError("Refusing to alter the default Hermes profile in protected mode")
        updated = new_config(current, name, item, protected=(args.mode == "protected"))
        if not args.apply:
            print("PREVIEW ONLY: No changes applied to Hermes.")
            preview={"mcp_servers": {name: item}}
            if args.mode == "protected":
                preview={"platform_toolsets":updated["platform_toolsets"],
                         "agent":updated["agent"],**preview}
            print(yaml.safe_dump(preview, sort_keys=False, allow_unicode=True))
            return 0
        if not args.accept_reformat:
            raise PermissionError("--apply requires --accept-reformat (YAML comments/formatting may change; backup is kept)")
        if args.mode == "protected":
            if os.geteuid() == 0:
                raise PermissionError("Never apply Hermes config as root")
            import pwd
            agent = pwd.getpwnam("catl-agent").pw_uid
            if os.geteuid() != agent:
                raise PermissionError("Protected Hermes config must be edited AS the isolated catl-agent UID")
        backup = apply_config(args.config, updated, expected_bytes=source_bytes)
        print(json.dumps({"applied": True, "profile": str(args.config),
                          "server": name, "backup": str(backup) if backup else None}, indent=2))
        return 0
    except Exception as exc:  # Syntax or schema failures must remain fail-closed without tracebacks
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
