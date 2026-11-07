> **New in v0.5:** For a protected Linux deployment, use [rootless broker setup](DEPLOY_ROOTLESS_LINUX.md) rather than the legacy single-process examples below.

> **Important:** The examples in this guide are legacy single-process evaluations only. For protected Linux usage, read [DEPLOY_ROOTLESS_LINUX.md](DEPLOY_ROOTLESS_LINUX.md); the GUI must connect through the broker operator socket, not open state directly.

# 🔌 Integration guide — CATL v0.5.0

## Operate as an MCP stdio gateway

1. Review every tool implementation and its descriptor. Use `python -m catl pin definition.json` to generate a full-descriptor pin. Do not auto-pin untrusted production servers.
2. Build JSON policy with `agent_id`, `tool_pins` and `rules`, optionally `postconditions`. A policy's `allow` or `approve` rule permits only the named pinned tool, subject to its conditions.
3. Protect policy, executable, state directory, HMAC key and operator terminal. Remove agent bypass routes. Use a verified, restricted execution account or external OS/container sandbox for consequential tools.
4. Register the CATL command as a stdio MCP server in a compatible harness. Point its downstream command at the protected legacy MCP server.
5. Verify policy denials, one-use approvals, action receipts and side effects under realistic data and errors. Do not let a generated sample policy serve as a production security policy.

## Example policy

```json
{
  "agent_id": "operator-supervised-worker",
  "tool_pins": {"write_demo": "64_lowercase_sha256_hex_of_reviewed_entire_tool_descriptor"},
  "rules": [{"tool": "write_demo", "effect": "approve", "conditions": []}],
  "postconditions": {
    "write_demo": {
      "kind": "file_sha256",
      "root": "/absolute/trusted/output",
      "path_pointer": "/filename",
      "digest_pointer": "/sha256"
    }
  }
}
```

Replace the placeholder pin with the output from `catl pin`, and ensure the output directory already exists. `filename` must be relative inside the root. `sha256` must be lowercase hexadecimal. The root directory is an operator-supplied trustworthy configuration, not an agent-selected argument. The digest is part of the exact approved call, not an independently supplied semantic expectation.

## POSIX process identity

**Legacy example only:** this path needs a privileged supervisor to change child users. The v0.5 rootless broker avoids that permanently privileged supervisor in normal operation; follow the rootless deployment guide instead. The gateway checks it cannot launch the backend under its own UID or UID zero. Avoid making the backend account a member of any group that can access secrets.

```sh
python -m catl run --config /etc/catl/policy.json \
  --state-dir /var/lib/catl/worker --backend-user catl-tool \
  -- python /opt/approved-tool-server/server.py
```

**Security warning:** CATL can only verify the UID separation, not that the backend lacks network or privileged filesystem capabilities. Operator-supplied OS policy is needed for full containment. For a systemd deployment, consider separate service accounts, capabilities, file ACLs, `ProtectSystem`, `ProtectHome`, `NoNewPrivileges`, `PrivateTmp`, `RestrictAddressFamilies` and network restrictions as appropriate. These controls have not been shipped as a production profile.

## Windows

`--backend-user` is explicitly unsupported in this release on Windows. `--allow-unsandboxed` can be used for local demonstrations only. Do not configure privileged tools on Windows until you have established and tested an independent restricted service identity/ACL boundary outside CATL.

## Failure classes

| Result | Meaning |
|---|---|
| `policy_denied` | No rule permits this specific pinned tool and arguments |
| `human_approval_required` | No usable one-time approval for the exact call binding |
| `tool_not_pinned_or_unavailable` | Tool not present or descriptor has changed |
| `preflight_failed` | Catalogue unavailable, malformed, repeating cursor, timeout or other preflight error |
| `tool_transport_failure` | Backend timed out/crashed; external side effects may have occurred |
| `postcondition_failed_side_effect_possible` | Backend said success, but expected filesystem postcondition was not observed |
| `multi_round_trip_not_supported` | Modern MCP retry cannot be safely brokered in this subset |

## Composition with Caledapt projects

AgentInterdict, MandateLease, EvidenceClock and Assentia are separate libraries, **not** bundled or integrated into CATL v0.5. A future hardened orchestration adapter could connect the products behind an independently reviewed boundary.

## First-run operator controls

The state starts **DISARMED**. From a trusted desktop with `tkinter` available:

```bash
python -m catl overlay --operator-socket /run/catl-operator/operator.sock
```

Inspect the pinned tool list, enable only the tools required, and press **RESUME**. The same state path must be used by the overlay and running MCP gateway. For a privileged POSIX deployment, the GUI requires a separately designed operator-to-supervisor authentication mechanism; do not grant a normal graphical desktop user blanket access to root-owned signing secrets. In that deployment, use an approved trusted administrative workflow for control changes until an independently authenticated broker is delivered.
