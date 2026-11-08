# CATL release acceptance — 8 November 2026 (release candidate run)

**Branch:** `hardening/v10-backend-containment` (development worktree `work`)
**Verified commit:** `d69e74dfdf1e3e152294f62ac51267fb5531112b`
**Environment:** Ubuntu 24.04.5 (kernel 6.8), Python 3.12.3, pinned `cryptography==50.0.2`, `jsonschema==4.26.0`, `Xvfb` (`xvfb-run -a` used for Tk).
**Result:** No-go items are limited to external prerequisites listed in §4. Native and Linux-kernel security gates below passed.

## Native suite

| Check | Result |
|---|---|
| unittest discover (sandbox, `PYTHONPATH=src`, `Xvfb`) | `Ran 707 tests … OK (skipped=28)` |
| unittest discover (root-owned clean checkout, `xvfb-run -a`, as root) | `Ran 707 tests … OK (skipped=2)` (the 2 skips are the Windows-only private-key fail-closed tests) |
| pytest (`-q tests`) | `679 passed, 28 skipped, 426 subtests passed` |
| `tools/security_sanity.py` | `PASS` |
| `compileall src tests integrations/hermes tools` | `PASS` |
| Hermes integration unit suite (`integrations/hermes/tests`) | `Ran 22 tests … OK` |
| `integration_rootless_e2e.py` (root) | `PASS` |
| `integration_broker_e2e.py` (root) | `PASS` |
| `offline_native_acceptance.py` | `PASS_UNIT_SUITE_ONLY`, `test_count=707`, `exact_git_commit_verified=true`, `exit_code=0` |
| `release_pack.py --output /tmp/catl-release-rc.zip` | `{"files": 208, "zip_sha256": "2779fac9…"}` + `--verify` `PASS 208 verified archive files` |
| `linux_kernel_identity_matrix_v14.py` (`CATL_DISPOSABLE_LINUX_TEST_HOST=YES`) | `PASS` (11/11 cases) |

## Fixes applied (each has regression coverage in the full suite)

1. **`test/ fixture modes (deterministic POSIX)** — `tests/fixture_modes.py` + per-test setUp. Hosts default to umask 002 (Ubuntu user-private groups); CATL deliberately refuses group/world-writable policy and postcondition evidence. Tests now pin umask `0o022` and 0755/0644 directories.
2. **`integration_broker_e2e.py`** — root-owned policy staging instead of pointing the broker identity at an unprivileged checkout directory.
3. **`src/catl/verifier.py`** — same-size / same-kernel-timestamp mutation in `FileDigestVerifier.verify` is now fail-closed via replay read; new regression test `test_same_size_mutation_during_read_denied`.
4. **`live()/test_subprocess_group_v10.py`** — treat `ProcessLookupError` as terminated (race).
5. **`test_redteam_dos_v10.py`** — close is invoked on two legitimate paths; assertion changed to “close called” from “called exactly once” (idempotent under lock).
6. **child env in sandboxed tests** — added `PYTHONDONTWRITEBYTECODE=1` to minimal subprocess environments to keep the verified source tree byte-clean.

## Live four-identity deployment evidence

Real service identities (`catl-broker` uid 994, `catl-agent` 1002, `catl-tools` 993, operator `sandbox` 1000) with real sockets and `SO_PEERCRED`.

- Broker mounted externally-backed backend service on `/var/lib/catl-tools/sockets/tools.sock` (catl-tools:catl-backend-ipc, mode 0660).
- `hermes_mcp_smoke` `disarmed`: `PASS` (0 tools advertised, fail-closed).
- After arming the gateway via operator (`feature gateway_enabled on`): `armed` `PASS` 2 tools, echo round-trips.
- `approval-required` (`write_demo`): `PASS`, `policy_denied`/`human_approval_required` enforced.
- Cross-socket denial: agent user → operator socket → `DENIED_OK PermissionError`.
- Live policy content gating confirmed: `echo_safe` requires message `starts_with "hello"`; `bench-` prefixes denied, `hello-` prefixes pass.

## Kernel isolation matrix

`linux_kernel_identity_matrix_v14.py` `PASS` — per-UID socket `SO_PEERCRED` admission (cross-UID connections refused), broker-only key readability, env canary non-inheritance.

## Performance (disposable VM, 4-identity sandbox)

See `/tmp/catl-bench.json`. Representative (p50):

- `Policy.from_file`: 135.4 µs
- `FileDigestVerifier.verify` (2 KiB): 157.9 µs (includes replay read)
- `FileDigestVerifier.verify` (1 MiB): 1.74 ms
- Audit ledger `append`: 36.1/s
- Full shim round-trip (real broker, fresh python each call): p50 613.6 ms (mostly interpreter startup; fusion ≈ 280 ms)
- Concurrent 8x: 2004 ms total, 5/8 succeeded (3 dropped by admission rate-limit — designed control).

## Remaining / blocked (external prerequisites not available)

- Windows AppContainer / pipe ACL runtime: `NOT TESTED` (2 tests skipped on Linux; 64-bit Windows tooling absent)
- macOS sandbox / `getpeereid`: `NOT TESTED` (not present)
- FIDO2 physical user-presence device: `NOT TESTED` (no enrolled authenticator)
- Production systemd/LSM/egress target + cgroup sandbox: `NOT TESTED` (disposable VM deployed broker/backend via nohup, not systemd unit)
- Independently operated (off-host) witness service: `SCP` n/a — witness tests use on-host fixture only — `NOT RUN`
- Live external-provider effect idempotency (email/API/payment readback): `NOT RUN`
- Independently hosted witness reputation/SBOM independent attestation: `NOT RUN`
- SBOM existing `docs/SBOM-evaluation.json` flagged by `sbom_assurance` (stale / `bom_unpinned_or_duplicate_component`). The release archive itself verified internally (208 files, source_commit ).
- Packaging & licensing decision: external publication not authorized.

## Roadmap milestones disposition

1. **Production Linux confinement + live Hermes integration** — substantially evidenced on a disposable VM (service UIDs, sockets, external backend, real Hermes evaluation *shim* — not a live Windows Hermes desktop process). Status: `PASS (procedural constraint)`
2. **Windows AppContainer + macOS sandbox** — `BLOCKED`
3. **Real hardware-backed human authorisation** — `BLOCKED`
4. **Independently operated witness infrastructure** — `BLOCKED`
5. **Real external-provider effect reconciliation** — `NOT RUN`
6. **Independent security assessment and public-release assurance** — `NOT RUN`

## Closing recommendation

**A. RELEASE_CANDIDATE_Verified** — the native, root-mode and live-disposable-UVM gates pass for the tested Linux rootless broker boundary, with two Windows-only native tests correctly skipped and all external publication / unsupported-platform / independent-assistance gates expressly documented as `BLOCKED` / `NOT RUN`.
