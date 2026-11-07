"""Trusted local operator CLI. No network listeners or remote approval endpoints."""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from .crypto import digest, get_or_create_key, strict_loads
from .policy import Policy
from .store import State


def _state(folder: Path) -> State:
    return State(folder / "audit.sqlite3", get_or_create_key(folder / "audit.key"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="catl", description="Caledapt Agent Trust Layer, v0.10.0rc1 Linux incident-quarantine candidate")
    sub = p.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="Preflight Linux broker state, identities and signed audit; no auto-repair")
    doctor.add_argument("--config", type=Path, required=True)
    doctor.add_argument("--state-dir", type=Path, required=True)
    doctor.add_argument("--anchor-path", type=Path, required=True)
    doctor.add_argument("--agent-uid", type=int, required=True)
    doctor.add_argument("--operator-uid", type=int, required=True)
    doctor.add_argument("--backend-uid", type=int, required=True)
    doctor.add_argument("--strict", action="store_true", help="Treat unverified host controls as blockers")
    audit_host = sub.add_parser("host-audit", help="Read-only systemd sandbox property checks; not a pentest")
    audit_host.add_argument("--broker-unit", default="catl-broker.service")
    audit_host.add_argument("--backend-unit", default="catl-backend.service")
    audit_host.add_argument("--broker-user", default="catl-broker")
    audit_host.add_argument("--backend-user", default="catl-tools")
    run = sub.add_parser("run", help="Run a pinned MCP stdio tool server behind the gateway")
    run.add_argument("--config", required=True, type=Path)
    run.add_argument("--backend-user", help="POSIX: drop child to a distinct non-root account; requires root supervisor")
    run.add_argument("--allow-unsandboxed", action="store_true", help="DEMO ONLY: acknowledge child runs without OS identity separation")
    run.add_argument("--pass-env", action="append", default=[], help="Explicitly forward an environment variable to the child")
    run.add_argument("--backend-workdir", type=Path, help="Working directory for child; NOT a sandbox")
    run.add_argument("--state-dir", required=True, type=Path)
    run.add_argument("backend", nargs=argparse.REMAINDER, help="-- executable [arguments]")
    pending = sub.add_parser("pending", help="Inspect live requests in a trusted terminal")
    pending.add_argument("--state-dir", required=True, type=Path)
    for name in ("approve", "reject"):
        item = sub.add_parser(name, help="Decide a pending request from a trusted interactive terminal")
        item.add_argument("--state-dir", required=True, type=Path)
        item.add_argument("--by", required=True)
        item.add_argument("id")
    verify = sub.add_parser("verify", help="Verify local keyed receipt chain")
    verify.add_argument("--state-dir", required=True, type=Path)
    overlay = sub.add_parser("overlay", help="Open the minimisable trusted desktop operator overlay")
    overlay.add_argument("--operator-socket", type=Path, help="Protected broker control socket (recommended)")
    overlay.add_argument("--state-dir", type=Path, help="Legacy demo: direct access to state")
    overlay.add_argument("--config", type=Path, help="Legacy demo: policy location")
    overlay.add_argument("--unsafe-direct-state", action="store_true", help="DEMO ONLY; direct access to broker signing key")
    overlay.add_argument("--no-topmost", action="store_true", help="Don't keep window floating above other windows")
    anchor = sub.add_parser("anchor-init", help="Explicitly create a protected, independent audit checkpoint")
    anchor.add_argument("--state-dir", type=Path, required=True)
    anchor.add_argument("--anchor-path", type=Path, required=True)
    anchor.add_argument("--accept-current-verified-head", action="store_true")
    broker = sub.add_parser("broker", help="Linux broker with identity-pinned operator and agent sockets")
    broker.add_argument("--config", type=Path, required=True)
    broker.add_argument("--state-dir", type=Path, required=True)
    broker.add_argument("--anchor-path", type=Path, required=True)
    broker.add_argument("--agent-socket", type=Path, required=True)
    broker.add_argument("--operator-socket", type=Path, required=True)
    broker.add_argument("--agent-uid", type=int, required=True)
    broker.add_argument("--operator-uid", type=int, required=True)
    broker.add_argument("--backend-user", help="Legacy root-only supervised subprocess identity")
    broker.add_argument("--backend-socket", type=Path, help="v0.5: connect to an independently supervised backend socket")
    broker.add_argument("--backend-uid", type=int, help="v0.5: expected backend service kernel UID")
    broker.add_argument("--agent-gid", type=int, help="v0.5 rootless IPC group for agent; distinct from operator group")
    broker.add_argument("--operator-gid", type=int, help="v0.5 rootless IPC group for operator")
    backend_service = sub.add_parser("backend-service", help="v0.5: Linux unprivileged tool backend socket service")
    backend_service.add_argument("--socket", required=True, type=Path)
    backend_service.add_argument("--broker-uid", required=True, type=int)
    backend_service.add_argument("--broker-gid", required=True, type=int)
    backend_service.add_argument("--pass-env", action="append", default=[])
    backend_service.add_argument("--backend-workdir", type=Path)
    backend_service.add_argument("backend", nargs=argparse.REMAINDER)
    broker.add_argument("--pass-env", action="append", default=[])
    broker.add_argument("--backend-workdir", type=Path)
    broker.add_argument("backend", nargs=argparse.REMAINDER)
    shim = sub.add_parser("shim", help="Keyless stdio MCP client for the agent-facing broker socket")
    shim.add_argument("--agent-socket", type=Path, required=True)
    operator = sub.add_parser("operator", help="Trusted admin RPC; never reads the audit key")
    operator.add_argument("--operator-socket", type=Path, required=True)
    op = operator.add_subparsers(dest="operation", required=True)
    for command in ("status", "pending", "verify", "incidents"):
        op.add_parser(command)
    reconcile = op.add_parser("reconcile", help="Explicit human reconciliation of an uncertain action")
    reconcile.add_argument("action_id")
    reconcile.add_argument("--reference", required=True, help="External read-back evidence or incident ticket")
    toggle = op.add_parser("feature")
    toggle.add_argument("name", choices=["gateway_enabled","approvals_enabled","verification_enabled","audit_enabled"])
    toggle.add_argument("state", choices=["on","off"])
    tool = op.add_parser("tool")
    tool.add_argument("name")
    tool.add_argument("state", choices=["on","off"])
    bulk = op.add_parser("all-tools")
    bulk.add_argument("state", choices=["on","off"])
    for command in ("approve", "reject"):
        item = op.add_parser(command)
        item.add_argument("id")
    pin = sub.add_parser("pin", help="Print SHA-256 pin for a reviewed MCP tool definition")
    pin.add_argument("tool_definition", type=Path)
    args = p.parse_args(argv)
    try:
        if args.command == "host-audit":
            from .host_audit import run as host_audit_run
            result = host_audit_run(args.broker_unit, args.backend_unit, args.broker_user, args.backend_user)
            print(json.dumps(result, indent=2))
            return 0 if result["passed"] else 3
        if args.command == "doctor":
            from .doctor import run_checks
            output = run_checks(config=args.config, state_dir=args.state_dir,
                anchor_path=args.anchor_path, agent_uid=args.agent_uid,
                operator_uid=args.operator_uid, backend_uid=args.backend_uid,
                strict=args.strict)
            print(json.dumps(output, indent=2, ensure_ascii=False))
            return 0 if output["ok"] else 2
        if args.command == "overlay":
            from .overlay import launch
            if args.operator_socket and not args.unsafe_direct_state:
                return launch(operator_socket=args.operator_socket, topmost=not args.no_topmost)
            if args.unsafe_direct_state and not args.operator_socket and args.state_dir and args.config:
                return launch(state_dir=args.state_dir, config=args.config, direct_state=True,
                              topmost=not args.no_topmost)
            raise ValueError("overlay_requires_broker_socket_or_explicit_unsafe_demo")
        if args.command == "shim":
            from .broker import shim as forward
            forward(args.agent_socket)
            return 0
        if args.command == "anchor-init":
            from .anchor import AnchorGuard
            if not args.accept_current_verified_head:
                raise PermissionError("explicit_current_head_acknowledgement_required")
            state = _state(args.state_dir)
            verification = state.verify()
            if not verification["valid"]:
                raise PermissionError("receipt_chain_invalid_cannot_bootstrap")
            if state.controls()["gateway_enabled"]:
                raise PermissionError("pause_gateway_before_anchor_bootstrap")
            if args.anchor_path.resolve().is_relative_to(args.state_dir.resolve()):
                raise ValueError("anchor_must_be_outside_state_directory")
            guard = AnchorGuard(args.anchor_path, state.key)
            guard.bootstrap(verification["count"], verification["head_mac"])
            print(json.dumps({"anchor_created": str(args.anchor_path), "count": verification["count"],
                              "head_mac": verification["head_mac"]}, indent=2))
            return 0
        if args.command == "backend-service":
            from .external_backend import BackendService, validate_service_environment
            from .gateway import SubprocessBackend
            command = args.backend[1:] if args.backend and args.backend[0] == "--" else args.backend
            if not command:
                raise ValueError("backend_service_command_required")
            # Validate before creating the child: otherwise a root invocation could
            # start a privileged tool process and then fail to create the service.
            if sys.platform != "linux" or os.geteuid() == 0:
                raise PermissionError("backend_service_requires_nonroot_linux")
            validate_service_environment(args.socket, broker_uid=args.broker_uid,
                                         broker_gid=args.broker_gid)
            # This child shares the tool service's unprivileged identity.
            backend = SubprocessBackend(command, allow_unsandboxed=True,
                                        pass_env=tuple(args.pass_env), workdir=args.backend_workdir)
            try:
                service = BackendService(backend, args.socket, broker_uid=args.broker_uid,
                                         broker_gid=args.broker_gid)
                import signal
                signal.signal(signal.SIGTERM, lambda _sig, _frame: service.shutdown())
                signal.signal(signal.SIGINT, lambda _sig, _frame: service.shutdown())
                service.serve()
            finally:
                backend.close()
            return 0
        if args.command == "broker":
            from .broker import BrokerServer
            from .gateway import Gateway, SubprocessBackend
            command = args.backend[1:] if args.backend and args.backend[0] == "--" else args.backend
            if args.anchor_path.resolve().is_relative_to(args.state_dir.resolve()):
                raise PermissionError("anchor_must_be_outside_state_directory")
            # Protected state and pinned policy are verified BEFORE any subprocess launch.
            policy = Policy.from_file(args.config)
            state = State(args.state_dir / "audit.sqlite3", get_or_create_key(args.state_dir / "audit.key"),
                          anchor_path=args.anchor_path)
            state.assert_anchor()
            if args.backend_socket is not None:
                if args.backend_user or command or args.backend_workdir or args.pass_env:
                    raise ValueError("external_backend_options_mutually_exclusive_with_subprocess")
                if args.backend_uid is None or args.agent_gid is None or args.operator_gid is None:
                    raise ValueError("external_backend_requires_uid_and_channel_groups")
                if os.geteuid() == 0:
                    raise PermissionError("rootless_external_broker_must_not_run_as_root")
                if args.backend_uid in (0, os.geteuid(), args.agent_uid, args.operator_uid):
                    raise PermissionError("backend_identity_not_independent")
                from .external_backend import SocketBackend
                backend = SocketBackend(args.backend_socket, backend_uid=args.backend_uid)
            else:
                if args.backend_uid is not None or args.agent_gid is not None or args.operator_gid is not None:
                    raise ValueError("subprocess_mode_does_not_accept_external_backend_options")
                if not args.backend_user or not command:
                    raise ValueError("legacy_broker_requires_backend_user_and_command")
                if os.geteuid() != 0:
                    raise PermissionError("legacy_subprocess_broker_requires_root_use_external_backend")
                import pwd
                backend_identity = pwd.getpwnam(args.backend_user)
                if backend_identity.pw_uid in (args.agent_uid, args.operator_uid):
                    raise PermissionError("backend_must_not_share_agent_or_operator_identity")
                backend = SubprocessBackend(command, backend_user=args.backend_user, allow_unsandboxed=False,
                                            pass_env=tuple(args.pass_env), workdir=args.backend_workdir)
            try:
                supervisor = BrokerServer(Gateway(policy, state, backend), state, policy,
                                          agent_socket=args.agent_socket, operator_socket=args.operator_socket,
                                          agent_uid=args.agent_uid, operator_uid=args.operator_uid,
                                          agent_gid=args.agent_gid, operator_gid=args.operator_gid)
                import signal
                signal.signal(signal.SIGTERM, lambda _sig, _frame: supervisor.shutdown())
                signal.signal(signal.SIGINT, lambda _sig, _frame: supervisor.shutdown())
                supervisor.serve()
            finally:
                backend.close()
            return 0
        if args.command == "operator":
            from .broker import OperatorClient
            client = OperatorClient(args.operator_socket)
            if args.operation in ("status", "verify", "pending", "incidents"):
                result = (client.status() if args.operation == "status" else
                          client.verify() if args.operation == "verify" else
                          client.list_pending() if args.operation == "pending" else client.open_incidents())
            elif args.operation == "reconcile":
                if not sys.stdin.isatty():
                    raise PermissionError("interactive_terminal_required_for_reconciliation")
                incident = next((x for x in client.open_incidents() if x["action_id"] == args.action_id), None)
                if incident is None:
                    raise ValueError("incident_not_found")
                print(json.dumps(incident, indent=2, ensure_ascii=False))
                phrase = f"RECONCILE {args.action_id}"
                if input(f"External effect MUST be checked first. Type '{phrase}' to confirm: ") != phrase:
                    raise PermissionError("reconciliation_confirmation_mismatch")
                result = {"accepted": client.reconcile_incident(args.action_id, "", args.reference,
                          "I_HAVE_RECONCILED_THE_EXTERNAL_EFFECT")}
            elif args.operation in ("approve", "reject"):
                if not sys.stdin.isatty():
                    raise PermissionError("interactive_terminal_required_for_decisions")
                entry = next((r for r in client.list_pending() if r["id"] == args.id), None)
                if entry is None:
                    raise ValueError("request_not_pending")
                print(json.dumps(entry, indent=2, ensure_ascii=False))
                phrase = f"{args.operation.upper()} {args.id}"
                if input(f"Type '{phrase}' to confirm: ") != phrase:
                    raise PermissionError("operator_confirmation_mismatch")
                result = {"accepted": client.decide(args.id, "", args.operation == "approve")}
            elif args.operation == "feature":
                result = client.set_feature(args.name, args.state == "on", "")
            elif args.operation == "tool":
                result = client.set_tool(args.name, args.state == "on", "", set())
            else:
                result = client.set_all_tools(args.state == "on", "", set())
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        if args.command == "pin":
            data = strict_loads(args.tool_definition.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("name"), str):
                raise ValueError("tool_definition_invalid")
            print(json.dumps({"name": data["name"], "sha256": digest(data)}, indent=2))
            return 0
        if args.command == "run":
            from .gateway import serve
            command = args.backend[1:] if args.backend and args.backend[0] == "--" else args.backend
            if not command:
                p.error("a backend command is required after --")
            policy = Policy.from_file(args.config)
            serve(policy, _state(args.state_dir), command, backend_user=args.backend_user,
                  allow_unsandboxed=args.allow_unsandboxed, pass_env=tuple(args.pass_env),
                  workdir=args.backend_workdir)
            return 0
        state = _state(args.state_dir)
        if args.command == "pending":
            print(json.dumps(state.list_pending(), indent=2, ensure_ascii=False))
            return 0
        if args.command == "verify":
            result = state.verify()
            print(json.dumps(result, indent=2))
            return 0 if result["valid"] else 2
        if args.command in ("approve", "reject"):
            match = next((row for row in state.list_pending() if row["id"] == args.id), None)
            if match is None:
                print("Request missing, already decided, or expired", file=sys.stderr)
                return 2
            if not sys.stdin.isatty():
                print("Interactive trusted terminal required for decisions", file=sys.stderr)
                return 2
            print(json.dumps(match, indent=2, ensure_ascii=False))
            prompt = f"TYPE {args.command.upper()} {args.id} TO CONFIRM: "
            typed = input(prompt)
            if typed != f"{args.command.upper()} {args.id}":
                print("Confirmation mismatch", file=sys.stderr)
                return 2
            accepted = state.decide(args.id, args.by, approve=args.command == "approve")
            print("Decision recorded" if accepted else "No pending request")
            return 0 if accepted else 2
    except (ValueError, PermissionError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"catl: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
