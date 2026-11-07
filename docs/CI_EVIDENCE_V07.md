# ✅ CATL v0.7.0rc1 — CI evidence

GitHub Actions matrix: **pending the first reviewable commit** to the private release candidate branch. This file will be updated only after verified workflow results.

Local Linux Python 3.13: 222/222 tests passed with a virtual display; isolated rollback drill succeeded; four-UID rootless broker integration succeeded in three successive runs; static systemd-analyze verify succeeded for rendered templates.

The Windows job validates portability and Linux-only fail-closed restrictions, not native Windows protected execution. The macOS job runs portable code tests, not a protected broker.

First candidate GitHub run [42331445836](https://github.com/BryanFiFife/CATL/actions/runs/42331445836) passed 9/10 jobs; the new Bandit gate found a medium-confidence B108 warning for a forbidden temporary-path literal in the host-audit denylist. The audit now instead requires an exact, role-specific allowlist of writable directories and has two additional regression tests. A fresh CI run is required before marking the gate passed.
