# CATL v0.11 CI and release evidence

**Scope:** private release candidate, **not** production certification.

- Initial v0.11 publication `cbffbd028ffb1055f67873104d44d650f3630afd` failed Linux CI from a fixture-only unprivileged socket chown.
- Fixture repair `87c6f7f290f01c7e5cc5634455850a9359227474`: [GitHub Actions run 42385453874](https://github.com/BryanFiFife/CATL/actions/runs/42385453874), **10/10 jobs succeeded**. Python 3.11 and 3.13 headless Linux: **278 tests run, 14 skipped** per environment. Graphical Linux: **278 run, 8 skipped**, followed by a passing four-UID signed broker integration. Windows portability, macOS regressions, security scans, recovery and package tests passed.
- Hermes work `2dbcf3073ce3235c2854b72b07f4082a17546aac`: [GitHub Actions run 42386041814](https://github.com/BryanFiFife/CATL/actions/runs/42386041814); headless Linux Python 3.13 **283 run, 14 skipped**. Check its complete workflow verdict.
- Follow-up regression: checker rejects MCP `isError` and a mismatched echo, rather than treating any text response as success. Check the latest-commit matrix before handoff.

**Not verified by CI:** a full real Hermes Agent UI session, Hermes alternative-tool confinement, hardware-backed user presence, verified external business side effects, production-host isolation, witnessed off-host audit, signed reproducible distribution or an independent penetration test.

See [Hermes evaluation](HERMES_EVALUATION.md), [operator signing](OPERATOR_SIGNING_V011.md), [red-team scope](RED_TEAM_ASSESSMENT_V011.md) and [production gates](PRODUCTION_ACCEPTANCE_V09.md).
