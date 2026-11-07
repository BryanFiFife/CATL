#!/usr/bin/env python3
"""Read-only/echo-only CATL stdio MCP contract smoke for Hermes Agent evaluation.

Run under the unprivileged CATL agent UID after protected broker/backend startup.
No operator socket, keys, direct state access or privileged actions are required.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


def validate_replies(replies: list[dict], *, tool: str, expect: str, expected_text: str | None = None) -> dict:
    """Validate a real initialize/list/call exchange without trusting CLI exit alone."""
    if len(replies) != 3 or any(not isinstance(r, dict) for r in replies):
        raise AssertionError("three_MCP_replies_required")
    by_id = {r.get("id"): r for r in replies}
    if set(by_id) != {1, 2, 3} or any(r.get("jsonrpc") != "2.0" for r in replies):
        raise AssertionError("MCP_response_ids_or_envelope_invalid")
    init = by_id[1].get("result", {})
    if init.get("protocolVersion") != "2025-11-25":
        raise AssertionError("CATL_legacy_protocol_handshake_failed")
    listed = by_id[2].get("result", {}).get("tools", [])
    if not isinstance(listed, list):
        raise AssertionError("MCP_tool_catalogue_invalid")
    if expect == "disarmed":
        # The protected gateway deliberately advertises no tools when paused.
        if listed:
            raise AssertionError("disarmed_gateway_advertised_tools")
    elif tool not in {
        t.get("name") for t in listed if isinstance(t, dict)
    }:
        raise AssertionError("expected_reviewed_tool_not_listed")
    call = by_id[3]
    if expect == "disarmed":
        if call.get("error", {}).get("message") != "operator_disabled_gateway_or_audit":
            raise AssertionError("disarmed_gateway_did_not_fail_closed")
    elif expect == "approval-required":
        if call.get("error", {}).get("message") != "human_approval_required":
            raise AssertionError("approval_barrier_not_enforced")
    elif expect == "armed":
        result = call.get("result")
        if not isinstance(result, dict) or result.get("isError") is True or "error" in call:
            raise AssertionError("armed_tool_returned_an_error")
        blocks = result.get("content", [])
        if not isinstance(blocks, list) or not any(
            isinstance(b, dict) and b.get("type") == "text"
            and (expected_text is None or b.get("text") == expected_text)
            for b in blocks
        ):
            raise AssertionError("armed_tool_did_not_return_expected_text")
    else:
        raise ValueError("invalid_smoke_mode")
    return {"passed": True, "mode": expect, "tool": tool,
            "protocolVersion": init["protocolVersion"],
            "advertised_tool_count": len(listed),
            "call_outcome": call.get("error", {}).get("message", "success")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-socket", required=True, type=Path)
    parser.add_argument("--expect", required=True,
                        choices=("disarmed", "armed", "approval-required"))
    parser.add_argument("--tool", default="echo_safe")
    parser.add_argument("--message", default="hello Hermes CATL evaluation")
    args = parser.parse_args(argv)
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "hermes-catl-eval", "version": "0.1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": args.tool, "arguments": {"message": args.message}}},
    ]
    wire = "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n"
                   for r in requests)
    process = subprocess.run(
        [sys.executable, "-m", "catl", "shim", "--agent-socket", str(args.agent_socket)],
        input=wire, text=True, capture_output=True, timeout=30, check=False)
    if process.returncode:
        raise RuntimeError("CATL_shim_failure:" + process.stderr[-500:])
    replies = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
    print(json.dumps(validate_replies(
        replies, tool=args.tool, expect=args.expect,
        expected_text=args.message if args.tool == "echo_safe" and args.expect == "armed" else None
    ), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
