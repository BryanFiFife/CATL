# CATL live systemd resource and egress preflight — 9 November 2026

**Status: scoped defensive code change; not live host acceptance or production GA.**

## Defect and threat scenario

The existing `catl host-audit` inspected an active unit's service identity,
`IPAddressDeny=any`, `AF_UNIX` restriction, capabilities and writable
paths. It did **not** reject `MemoryMax=infinity`,
`TasksMax=infinity`, positive `MemorySwapMax`, core dumps, or explicit
`IPAddressAllow` exceptions. A weakened service could therefore satisfy
the earlier property-only preflight despite violating the reviewed profile.

## Implementation

- `src/catl/systemd_runtime_gates.py` checks *effective* values returned
  by `systemctl show`: finite `MemoryMax` within the reviewed
  broker (768 MiB) / backend (1536 MiB) ceilings; explicit
  `MemorySwapMax=0`; `1 <= TasksMax <= 64`; `LimitCORE=0`;
  no explicit `IPAddressAllow` exceptions; and nine additional service
  isolation/teardown settings.
- `src/catl/host_audit.py::assess_unit` incorporates every check into
  its existing `passed` decision and returns granular failure reports.
- `tests/test_host_audit.py` now supplies the required live service
  properties and checks the integrated preflight rejection path.
- `tests/test_systemd_runtime_gates.py` covers the two reviewed
  identities, missing properties, unbounded/malformed values, widened
  network allowance and every expected strict property.

**Scoped local evidence:** 12/12 isolated `systemd_runtime_gates`
unittests passed on Python 3.13.5 in this development session. The complete
private CATL test suite was **not** rerun against an installed service. A
new host-side proof is required; passing mock properties does not certify
any unit.

## Host acceptance required before checking off the roadmap

1. Provision independent Linux broker/agent/operator/backend UIDs, secure
   IPC permissions, reviewed unit files and root-owned executable paths.
2. Start both systemd units under a disposable, restricted test profile.
   Run `systemctl show catl-broker.service` and
   `systemctl show catl-backend.service`; run `catl host-audit`.
3. Deliberately test systemd drop-in changes to `MemoryMax`,
   `MemorySwapMax`, `TasksMax`, `LimitCORE` and
   `IPAddressAllow`: the audit must fail closed every time.
4. Separately prove **kernel enforcement**, not merely service-manager
   properties: cgroup memory/pid bounds under load, deny tested egress,
   AppArmor/SELinux rules, seccomp restrictions, direct tool-bypass denial,
   no writable policy/key paths, and cross-UID socket denial.
5. Attach exact host, kernel, unit configuration, command transcripts and
   negative-test evidence; review results before any production claim.

**Known limitations:** this is read-only introspection of reported systemd
properties, not host protection. It does not prove effective LSM enforcement,
network namespace isolation, syscall filter behaviour, hardware presence,
or that the audited unit is the only route to a tool. Combined Linux
hardening/hardware presence milestone remains **unchecked**.

GitHub Actions remain manual-only. No automatic hosted workflow was run.
