# CATL hardened Linux systemd evaluation profiles — 7 November 2026

**Status: reviewable STATIC templates, not a live security attestation.** Both service examples preserve four-UID Unix peer authentication and default-deny IP egress. They do not modify or install any running service.

## Hardening increments

- Crash-loop limits: `StartLimitIntervalSec=60`, `StartLimitBurst=3`, `Restart=on-failure`, `RestartSec=3` protect against unlimited process restarts resetting the in-memory agent request budget.
- Cgroup resource bounds: broker `MemoryMax=768M`, backend `MemoryMax=1536M`, both `MemorySwapMax=0` and `TasksMax=64`. These defaults must be benchmarked against the target workload; do not relax without an explicit risk review.
- Secret-leak reduction: `LimitCORE=0`, `KeyringMode=private`, plus existing umask 0077.
- Kernel/namespace protection: `ProtectClock=yes`, `ProtectHostname=yes`, `ProtectProc=invisible`, `RestrictNamespaces=true`; a conservative deny-list `SystemCallFilter=~@mount @swap @reboot @raw-io`, returning EPERM.
- Service teardown: `KillMode=control-group`, `TimeoutStopSec=10`, `OOMPolicy=stop`.
- Existing restrictions remain: no privileges, no network, only AF_UNIX, no ambient caps, strict read-only filesystem with narrow writable paths.

## Local evidence

On Linux with systemd 257, both sanitized templates (nonexistent accounts, UIDs and executable replaced **only in temporary verification copies**) passed `systemd-analyze verify`. `systemd-analyze security --offline=yes` reported exposure score **1.6 (OK)** for both sanitized templates. **This is static scoring, not proof of live enforcement or executable correctness.** Six unit-template regression tests also passed from an isolated project fixture.

See `tests/test_systemd_profile_hardening_v011.py`. These source tests have not yet been executed against the complete private CATL checkout in this evaluation runtime; they are included for subsequent native regression.

## Real-host blockers

1. Set up `catl-agent`, `catl-operator`, `catl-broker`, and `catl-tools` accounts with reviewed IPC groups and no accidental overlap.
2. Inspect service paths, pinned policy/key ownership and executable trust; enforce external LSM/seccomp/egress controls and remove unmediated Hermes capabilities.
3. Install templates only after tailoring account names, UID/GIDs, paths, legitimate file writes and workspace; run `systemd-analyze verify` and `systemd-analyze security` on the exact final units.
4. Run services and verify `catl doctor --strict`, `catl host-audit`, kernel SO_PEERCRED denial across identities, restricted `/proc`, network denial, bounded cgroup stress, and controlled restart.
5. Perform recovery and independent penetration testing.

**Do not check off the OS hardening roadmap milestone yet.** No unit was installed or started by this development step.
