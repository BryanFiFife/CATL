# Contributing to CATL

Thanks for helping improve **CATL — Caledapt Agent Trust Layer**.

CATL sits on a security boundary between AI agents and real tool execution, so contributions are welcome but changes that affect authority, approvals, IPC, audit integrity, release provenance or sandboxing need especially clear evidence.

## Good contributions

We welcome:

- bug fixes with a minimal reproducer;
- MCP interoperability improvements;
- security-hardening changes;
- tests for bypasses, races, replay and malformed input;
- documentation and deployment improvements;
- new integrations that preserve CATL's fail-closed model;
- performance improvements that do not weaken the trust boundary.

## Before opening a pull request

1. Fork/branch from the current `main`.
2. Keep changes focused.
3. Add or update tests for behavioural changes.
4. Run the relevant standard-library test suite locally.
5. Do not include credentials, private keys, customer data or proprietary fixtures.
6. Do not weaken a security control just to make a test pass.

For a broad local check:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_*.py' -v
python tools/security_sanity.py
python -m compileall -q src tests integrations/hermes tools
```

Some Linux identity/systemd tests require an isolated disposable host and elevated privileges. Do not run privileged test code on a machine you are unwilling to modify.

## Security vulnerabilities

Do **not** open a normal public issue for a working security bypass.

Use the private reporting route described in [SECURITY.md](SECURITY.md).

## Pull-request expectations

For trust-boundary changes, include:

- threat scenario;
- attacker prerequisites;
- previous behaviour;
- new behaviour;
- regression test;
- known residual risk.

Claims such as "secure", "production safe" or "prevents prompt injection" need evidence and a clearly bounded threat model.

## Licence

Unless explicitly stated otherwise, contributions intentionally submitted for inclusion in CATL are provided under the project's [Apache License 2.0](LICENSE).

By contributing, you represent that you have the right to submit the contribution under those terms.
