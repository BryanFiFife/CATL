# 🐧 CATL v0.5 — rootless Linux deployment architecture

> **Evaluation deployment, not an automatic host hardening tool.** Deploy only after verifying filesystem ACLs, service identities and tool permissions on a disposable machine. This guide is a blueprint, not a one-command installer.

## Trust separation

| Process | Suggested OS account | Controlled data | Required group memberships |
|---|---|---|---|
| CATL broker | `catl-broker` | Policy, signed state, HMAC key, independent anchor | `catl-agent-ipc`, `catl-operator-ipc`, `catl-backend-ipc` |
| AI agent/shim | `catl-agent` | Agent prompts and untrusted tool requests | `catl-agent-ipc` **only** |
| Operator overlay | interactive human account | Operator controls, approvals | `catl-operator-ipc` **only** |
| Tool backend service | `catl-tools` | Approved tool execution, scoped working directory | `catl-backend-ipc` **only** |

No process above should run as root during ordinary operation. A trusted administrator may need root **only during initial account/group setup and OS service provisioning**. Use distinct UIDs for all four identities and distinct IPC groups.

## Directories and permissions

A trusted installer creates four directories, one protected state directory and an independent checkpoint directory. The broker's agent and operator *socket directories* must be owned by `catl-broker` (not group-writable), group-owned by the corresponding IPC groups and mode `0710`. The backend socket directory is owned by `catl-tools`, group-owned by `catl-backend-ipc` and mode `0710`. Actual socket files are mode `0660`, owned by the service account and the intended group. Kernel `SO_PEERCRED` **also verifies the exact peer UID on every connection**. Put no private keys or state database in those group-traversable directories.

State/key and separate anchor directories must be owned only by `catl-broker` and mode `0700`. Tool backend state/work directories must be writable by `catl-tools` but **not** by `catl-broker`, `catl-agent`, or the operator as a matter of least privilege. Ensure the operator is *not* a member of the agent IPC group, and neither is the backend. An agent under the same user account as the human operator defeats this separation.

Verify with `stat`, `id`, `namei -l`, and systemd unit inspection before enabling.

## Service startup order

1. Create service identities, groups, protected directories, sockets' parent directories and tool-specific working directory with the ownership above. No agent process should have write access to policy, state, or anchor.
2. Install CATL source or wheel using a trusted build and verify its recorded SHA-256 hashes. The backend model server/tool command must be reviewed and pinned separately.
3. As **`catl-broker`**, initialise state and an external anchor while the gateway is disarmed:

   ```bash
   catl anchor-init --state-dir /var/lib/catl/state \
     --anchor-path /var/lib/catl-anchor/head.json \
     --accept-current-verified-head
   ```

4. As **`catl-tools`**, launch the separately supervised backend socket service (example UIDs/GIDs are *placeholders*; obtain actual numeric values from `id`):

   ```bash
   catl backend-service --socket /run/catl-tools/tools.sock \
     --broker-uid <broker_UID> --broker-gid <backend_IPC_GID> \
     --backend-workdir /var/lib/catl-tools/work -- \
     python3 /opt/catl/tool-server.py
   ```

5. As **`catl-broker`**, launch the key-owning broker, **without** root:

   ```bash
   catl broker --config /etc/catl/policy.json \
     --state-dir /var/lib/catl/state \
     --anchor-path /var/lib/catl-anchor/head.json \
     --agent-socket /run/catl-agent/agent.sock \
     --operator-socket /run/catl-operator/operator.sock \
     --agent-uid <agent_UID> --operator-uid <operator_UID> \
     --agent-gid <agent_IPC_GID> --operator-gid <operator_IPC_GID> \
     --backend-socket /run/catl-tools/tools.sock --backend-uid <tools_UID>
   ```

6. Under **`catl-agent`**, point the harness at `catl shim --agent-socket /run/catl-agent/agent.sock`. Under the trusted human OS account, launch `catl overlay --operator-socket /run/catl-operator/operator.sock`.
7. Verify the actual operator via the protected operator socket, check the pinned tool catalogue, then *explicitly arm* the gateway. By default fresh/reconstructed state is disarmed.

## systemd hardening to evaluate per service

`User=`, `Group=`, `SupplementaryGroups=`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `ReadWritePaths=` and `RestrictAddressFamilies=AF_UNIX` for broker/agent/tool service where supported. Assess seccomp `SystemCallFilter=`, mount restrictions, `CapabilityBoundingSet=`, cgroup limits and network egress policies separately. These controls are deployment responsibilities; CATL does **not** install them automatically. An MCP backend that legitimately uses network access may require a narrower custom egress policy rather than an unconditional network ban.

## Failure states

- Missing or modified anchor: fail closed; no automatic recovery.
- Expired/unapproved tool action: deny; no fallback.
- Missing external backend: reject or surface uncertain transport failure; never bypass to direct execution.
- Backend timeout after intent: external side effect may have occurred; reconcile before retrying.
- Stolen operator OS identity: CATL cannot distinguish the attacker from that user; use MFA/screen lock/session controls outside CATL.
- Backend escalation beyond UID/process sandbox: threat remains; deploy OS MAC, cgroups, filesystem and network restrictions.

## Local test

Use only in a disposable Linux environment where root is available to create *synthetic* test UIDs:

```bash
PYTHONPATH=src python tests/integration_rootless_e2e.py
```

The script checks distinct peer UIDs, group-gated sockets, signed approvals, replay blocking, audit verification and backend inability to read the broker's HMAC key. It does not validate a production host's service manager, kernel LSM policy or network isolation.

## 🩺 v0.6 release-candidate deployment check

After provisioning the state/key, checkpoint and UIDs, run this **under `catl-broker`**:

```bash
catl doctor --config /etc/catl/policy.json \
  --state-dir /var/lib/catl/state --anchor-path /var/lib/catl-anchor/head.json \
  --agent-uid <agent_UID> --operator-uid <operator_UID> --backend-uid <tools_UID>
```

A nonzero exit indicates failed structural preflight. Even a zero exit retains explicit warnings about host sandboxing and human identity; `--strict` treats warnings as blockers. The diagnostic never creates a missing key or audit anchor. Back up SQLite state before running a release candidate against existing state: the state opener may perform compatible schema migration.

Evaluation-only hardening templates are available at `packaging/systemd/`. They contain placeholders for numerical UIDs/GIDs, intentionally do not create local users or host ACLs, and **have not been tested on an actual production systemd host**. In particular, validate the backend's ability to operate when all IP socket families are denied. Review AppArmor/SELinux, mount/device restrictions and process capabilities separately.

### v0.6 signed throttling change

The existing mutable `tool_rate` table is no longer used for enforcement. Permitted tool attempts record an authenticated `rate_permit` receipt. This changes receipt counts and increases time proportional to ledger size. Never prune the signed ledger without a reviewed archive/rotation protocol that preserves the independent anchor.
