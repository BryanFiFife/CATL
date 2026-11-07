# 🧱 CATL v0.5.0 — architecture and trust boundaries

## Protected Linux mode

```text
Agent UID                  Operator UID
   │ agent Unix socket        │ operator Unix socket
   │ (MCP methods only)       │ (control/approval RPC only)
   ▼                          ▼
┌─────────────────────────────────────────────┐
│ Broker UID / trusted supervisor             │
│ - pinned policy + schemas                  │
│ - full tool catalogue checks               │
│ - HMAC signing key + protected SQLite      │
│ - audit chain + separate signed checkpoint │
│ - exact consent state + operator controls  │
└─────────────────────────────────────────────┘
                          │
                          ▼
     AF_UNIX backend socket (kernel peer UID checked)
                          │
                          ▼
         Separately supervised backend UID / MCP server
                          │
                          ▼
                   External systems
```

**Execution boundary:** only tool calls that go through this broker are checked. A process which directly owns filesystem/network/financial authority outside CATL can bypass it. Ensure OS policy denies those alternate routes.

## IPC protocol

- Three filesystem `AF_UNIX` sockets, mode `0660` in *owner-controlled, group-traversable* directories. Broker checks exact agent/operator peer UIDs; backend service checks exact broker UID and broker checks backend UID using Linux `SO_PEERCRED`. Groups only provide socket reachability, not approval authority. State and signing key remain mode `0700` under broker-owned directories.
- No HTTP/REST, TCP/IP, pickle-based deserialization, browser approval origin, remote updater or telemetry. Messages are bounded, newline-delimited JSON with duplicate JSON keys rejected.
- Agent socket forwards only the previously supported MCP JSON-RPC tool subset. Operator socket accepts only `status`, `pending`, `verify`, `set_feature`, `set_tool`, `set_all_tools`, `decide`.
- The operator label is derived from kernel-validated UID; client-supplied usernames have no authority. `catl overlay` uses `OperatorClient`, without receiving the HMAC key or SQLite path.
- The agent shim is stateless per MCP message; each call establishes a short local socket connection. A bounded server-side connection budget and idle timeout limit easy connection exhaustion but do not prevent all DoS.

## Checkpointing

SQLite receipts form a keyed SHA-256 HMAC chain. A second HMAC-authenticated checkpoint stores `{receipt_count, receipt_head_mac}` in a **different protected directory**. Every anchored receipt-changing transaction:

1. Acquires a POSIX `flock` on the checkpoint lock file.
2. Validates the entire existing receipt chain against the independent checkpoint.
3. Begins an SQLite `BEGIN IMMEDIATE` transaction, performs the requested state change and appends the event.
4. Commits SQLite, then atomically writes/fsyncs the checkpoint file.

Note the checkpoint lock is acquired before the SQLite transaction in the actual implementation; the order above is descriptive. There is **no atomic cross-file transaction** between SQLite commit and checkpoint rewrite, so crashes may intentionally leave a mismatch. A mismatch blocks further protected actions rather than silently re-anchoring.

Approval request, decision and consumption events, as well as all operator control changes, now enter the receipt chain. A validly signed historical control row must also match the latest signed control-change event. Once an approval's `request_id` appears in a `approval_consumed` receipt, reverting a database row to an earlier approved state cannot make it reusable.

The check currently scans the complete chain (O(n)) on protected actions. This is deliberately conservative for evaluation but unsuitable for unbounded large-scale histories without independently authenticated checkpoint blocks.

## Subprocess and OS restrictions

**v0.5 protected path:** a non-root broker connects to an independently supervised tool backend socket; only the backend UID launches the tool subprocess. The backend service checks the broker's peer UID and restricts exposed MCP methods. This removes root from the *normal* broker's startup path, but the host administrator must provision accounts, groups and permissions beforehand. The old privileged `--backend-user` broker path remains for **legacy controlled evaluation**, not the recommended deployment. **UID separation is not a full sandbox:** enforce filesystem mounts, network egress, CPU/memory, executable integrity, operator session safety and cgroups externally.

Windows AppContainer/restricted tokens, Windows named-pipe security descriptors, macOS sandbox and independently verified production installers are *not* part of v0.5.

## Protocol limits

Agent gateway accepts `2025-11-25` legacy handshake and `2026-07-28` tool-only request metadata. Backend remains legacy stdio. No Streamable HTTP, OAuth, full modern upstream backend, tasks, MRTR, resources/prompts/sampling or subscriptions.

Official specification: https://modelcontextprotocol.io/specification/2026-07-28/server/tools
