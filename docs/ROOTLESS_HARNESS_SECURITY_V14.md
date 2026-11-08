# CATL rootless four-UID integration harness hardening — v14

This update corrects two issues in `tests/integration_rootless_e2e.py`:

1. The old `ENV = {**os.environ, ...}` passed arbitrary parent-process environment values to synthetic agent, backend and operator identities, including signing/session tokens and dynamic library or Python startup directives. The test runner now constructs a minimal child environment from fixed values, a pinned source path and no inherited credentials.
2. The harness used Python `assert` for its acceptance conditions; `python -O` or `PYTHONOPTIMIZE` removes them. The harness now refuses optimized execution with `integration_assertions_disabled` before creating any OS identities or launching services.

## Evidence and limitations

- Four scoped regression tests passed on a disposable, dependency-light local fixture of the updated import/startup boundary. The same four tests failed against the original fixture.
- The full real four-UID broker/shim/approval/replay scenario was **not run** against the current GitHub checkout in this environment. A fixture is not a substitute for the real system.
- Privileged tests must only run on a disposable Linux test VM/container. The harness uses synthetic UIDs and chowns temporary paths.
- No GitHub Actions jobs were invoked.
- Public GA stays blocked until full native and real host acceptance, live Hermes, independent witness, hardware approval, independent pentest and an authorised public licence.
