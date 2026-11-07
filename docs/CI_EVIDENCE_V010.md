# ✅ CATL v0.10.0rc1 — remote CI evidence

**GitHub Actions run:** [#42376729850](https://github.com/BryanFiFife/CATL/actions/runs/42376729850)  
**Code-tested commit:** `53b5c4994b6537167db2ee08fb0f7ccffcbae89a`  
**Result:** 10/10 scoped jobs successful; no skipped or failed jobs.

- ✅ Linux graphical and SO_PEERCRED 4-identity broker E2E (including **root-invoked separate-UID red-team agent socket flood**) — PASS.
- ✅ Ubuntu Python 3.11 and 3.13 regressions — PASS.
- ✅ macOS Python 3.11 and 3.13 **portable** regressions — PASS; not macOS protected broker.
- ✅ Windows Python 3.11 and 3.13 **portability/fail-closed** checks — PASS; Windows protected broker **not implemented**.
- ✅ Independent package smoke and wheel install — PASS.
- ✅ Static code and dependency scanner — PASS on configured thresholds/data at run time; not a vulnerability-free certificate.
- ✅ Linux host preflight/recovery *synthetic* tests — PASS; not real deployed-host attestation.

The developer also obtained 260/260 local Linux/Xvfb tests on both source and fresh extraction of the 114-member release archive, and reproduced the old v0.9 failures on disposable fixtures. This is **internal evidence only**. It does not satisfy the independent penetration-test, production Linux host containment, remote outcome readback or hardware-backed operator-identity gates.

This CI evidence pertains to the code commit above. Documentation/checksum-only updates after that commit should also be checked by CI; do not substitute a green CI badge for independent review.
