# CATL v0.11.0rc2 — open-source Linux release candidate

> **Apache-2.0 open-source release candidate.** This release is developer-tested security software, not an independent security certification.

CATL (Caledapt Agent Trust Layer) is a local-first security gateway for AI agents and Model Context Protocol (MCP) tools. It adds a trust boundary between an agent and consequential tool execution using default-deny policy, pinned tool definitions, schema validation, human approval, separated Linux identities and tamper-evident audit state.

## Highlights

- **Apache License 2.0** — commercial use, modification and redistribution are permitted under the licence terms.
- Functional Linux installer in `tools/catlinstall.py`.
- Release-manifest verification before privileged changes.
- Canonical `/opt/catl/venv`, `/etc/catl`, state, anchor and tool-work paths.
- Dedicated broker/agent/tool OS identities and separate IPC groups.
- Reviewed systemd templates rendered with actual non-root UID/GID values.
- State/anchor preservation and refusal of ambiguous automatic recovery.
- Separately provisioned operator public verification key.
- Fresh anchor bootstrap under the broker identity.
- Static post-install verification with `systemd-analyze verify`.
- Live activation path requiring both units active and then passing `catl host-audit`.
- Offline/prebuilt-wheel support for curated deployment environments.
- Human-in-the-loop exact-action approvals and replay protection in the core broker.
- Fail-closed uncertain-action handling and audit verification.

## Acceptance evidence

The rc2 installer work recorded:

- installer regression suite: **31 passed / 0 failed / 0 errors**;
- deterministic hostile-manifest sweep: **1,000 rejected / 0 unexpected accepts**;
- disposable Linux install: **pass**;
- post-install verification: **pass**;
- idempotent reinstall preserving state/anchor: **pass**;
- broker systemd offline security score: **1.3 / OK**;
- backend systemd offline security score: **1.3 / OK**.

The unchanged rc1 core baseline records **278 passing Linux regressions** and a real four-UID signed rootless E2E covering unsigned-forgery denial, tool execution, approval/replay control, audit verification, channel isolation and broker-key denial.

## Install

```bash
git clone https://github.com/BryanFiFife/CATL.git
cd CATL
python3 tools/catlinstall.py --check --source-root .

sudo python3 tools/catlinstall.py --install \
  --source-root . \
  --operator-user "$USER" \
  --operator-public-key /path/to/operator-public.hex
```

See [`INSTALL_LINUX.md`](INSTALL_LINUX.md) for the complete deployment guide.

## Security scope

CATL protects tool paths that are actually routed through its broker. It does not magically constrain an agent that still has a direct shell, alternate plugin registry, unrestricted network credential or another unmediated route to the same capability.

The protected release scope is currently Linux-focused. Windows/macOS protected runtimes, independent penetration testing, FIDO2 physical-presence assurance, independently operated witness infrastructure and provider-specific settlement verification remain outside the accepted rc2 scope.

## Licence

CATL is licensed under the **Apache License 2.0**. See [`../LICENSE`](../LICENSE) and [`../NOTICE`](../NOTICE).

Apache-2.0 permits commercial use, modification and redistribution subject to its terms, including preservation of required notices and its patent provisions.
