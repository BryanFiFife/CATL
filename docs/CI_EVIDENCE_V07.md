# ✅ CATL v0.7.0rc1 — CI evidence

GitHub Actions matrix: **pending the first reviewable commit** to the private release candidate branch. This file will be updated only after verified workflow results.

Local Linux Python 3.13: 220/220 tests passed with a virtual display; isolated rollback drill succeeded; four-UID rootless broker integration succeeded in three successive runs; static systemd-analyze verify succeeded for rendered templates.

The Windows job validates portability and Linux-only fail-closed restrictions, not native Windows protected execution. The macOS job runs portable code tests, not a protected broker.
