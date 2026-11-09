# CATL offline verification and release handoff — 9 November 2026

**Candidate:** Linux-focused `0.11.0rc1` source, **evaluation only, NOT production GA**.

## Scope and source identity

The current development candidate is maintained in `hardening/v011-live-systemd-gates-20261109`.
The tests below were run in an isolated Linux runtime on reconstructed files that
were checked **byte-for-byte** against GitHub's corresponding Git blob SHAs.
This is a **source-exact selected-files test**, not a checkout of the complete
private 216+ file repository and not a production protected-host evaluation.

**Runtime:** Linux x86-64, Python 3.13.5; systemd-analyze 257.
The isolated environment has cryptography 46.0.4, rather than CATL's pinned
50.0.2, so the full application/dependency matrix was **not** rerun.

## Independently rerun here

| Test | Result | Source identity |
| --- | --- | --- |
| `tests/test_systemd_runtime_gates.py` | **12 passed** | Git blob `9a45c0f3b531beaf222cd0e6040851b492321689` |
| `tests/test_host_audit.py` | **8 passed** | Git blob `0bf71cc96e3bbbe145349c1660c37eb6ccb21fb5` |
| `tests/test_build_release_sbom.py` | **6 passed** | Git blob `deccc371c1da6ce2178a168d0e93170370420ca6` |
| `tests/test_publish_github_release.py` | **9 passed** | Git blob `021186afffcebc56b7ee0593d9a18236fede4fb9` |
| `tests/test_systemd_mutation_regression.py` | **1 passed (10,000 deterministic hostile property mutations)** | Git blob `69664c537468bc9f40b920b39cb1ba1a92d73984` |
| Python compilation of selected `src`, `tests`, `tools` | **PASS** | Source-exact isolated subset |
| `tools/build_release_sbom.py --check` | **PASS** against byte-exact `pyproject.toml`, audit requirements and `docs/SBOM-evaluation.json` | Actual pinned six-component evaluation inventory |
| `systemd-analyze verify` on broker/backend evaluation templates | **PASS (2 files)** | Unavailable account, group and ExecStart values replaced in temporary verification copies only |
| `systemd-analyze security --offline=yes` | **1.6 / OK for both sanitized templates** | Static score, not live enforcement |

Total isolated unittest cases: **36 passed, zero failures**; one case
performs **10,000 fixed-seed** negative service-property mutations.

Source-exact production functions in scope:
`src/catl/systemd_runtime_gates.py` Git blob
`edc123ef37955f87343f63e649942be0442be279`,
`src/catl/host_audit.py` Git blob
`14397a0015b39b55e3a45e1941b360f63ceec34e`,
`tools/build_release_sbom.py` Git blob
`39612ccabea85e6b6624cde1d4e352e85d82b1ab`, and
`tools/publish_github_release.py` Git blob
`1580588976d2781e62b1bb344e2a5c2d704f18e2`.

The original systemd unit template Git blob IDs were independently matched:
broker `9bbe457b0fa9d6a7fc9c9c5849d7b8d05b0c430c`,
backend `f7e803a42a1095b97bf66b2ebbfc135a557dcca6`.

## Earlier evidence, not reproduced now

The 8 November 2026 Ubuntu VM report records full native acceptance
(707 unittest discovery, 679 pytest passes with platform-specific skips,
22 Hermes integration tests, Linux 4-identity checks).
See `docs/CATL_ACCEPTANCE_RC_2026-11-08.md`.
**Those numbers are historical Hermes-reported evidence at an earlier
commit, not tests rerun on the current GitHub release source.**

## Unverified release blockers

- **No complete current native source checkout execution**, full regression,
  rootless production service load, real Hermes effective-registry bypass check,
  live kernel/LSM/cgroup/egress containment or independent pen-test.
- No Windows AppContainer executable or named-pipe hostile host acceptance.
- No macOS entitled sandbox helper or Mac-native peer-socket acceptance.
- No physical FIDO2 human-presence key enrolment/test.
- No independently hosted witness or independently verified artifact signing.
- No live provider-side email/API/payment settlement readback and crash drills.
- `docs/SBOM-evaluation.json` is an exact six-component **pinned audit
  inventory**, not installed/wheel-complete dependency SBOM, a vulnerability scan,
  or a license audit.
- No authenticated GitHub Release API write or binary upload operation is
  available through this ChatGPT GitHub connection. The repository source
  can nevertheless be delivered as GitHub's automatically generated ZIP for
  a pinned commit/branch. **A source ZIP is not a published GitHub Release.**

The combined six broad roadmap milestones remain **unchecked**.
The `LICENSE` still prohibits redistribution/production use without
express permission. Free availability does not itself grant open-source
rights. No automated GitHub Actions were run or authorised for this work.

## Repeat the full native gate when an authenticated checkout becomes available

```bash
python tools/offline_native_acceptance.py --repo . \
  --expected-commit "$(git rev-parse HEAD)" --out /tmp/catl-offline-acceptance

python tools/release_pack.py --output /tmp/CATL-v0.11.0rc1-source.zip
python tools/release_pack.py --verify /tmp/CATL-v0.11.0rc1-source.zip
```

These commands are a **required next gate**, not evidence that they have
already run successfully at the new commit.

## Subsequent focused acceptance — 9 November mount/namespace fix

Following the earlier 36/36 result above, a false-positive systemd
host-audit path was discovered and corrected. The isolated suite is now
**40/40 unittest**, **40/40 pytest with 113 subtests**, and the fixed-seed
10,000 hostile service-property regression remains passing.
An additional test exercises the full `systemctl show` parsing and
`host_audit.run()` path using simulated responses.
See [correction evidence](MOUNT_NAMESPACE_GUARD_2026-11-09.md).
The external and full-native exclusions above still apply.
