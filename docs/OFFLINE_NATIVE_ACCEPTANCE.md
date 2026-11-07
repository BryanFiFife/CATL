# Offline native unit-suite acceptance — manual, CI-free

Use `tools/offline_native_acceptance.py` **only on a trusted full local CATL Git checkout**. This is a read-only integrity preflight followed by native unit tests; it does not fetch/pull code, install packages, upload logs, run GitHub Actions or alter running Hermes.

## Run

```bash
# In an existing local CATL checkout, after installing its pinned test dependencies:
python tools/offline_native_acceptance.py --repo . --expected-commit "$(git rev-parse HEAD)" --out /tmp/catl-offline-acceptance
cat /tmp/catl-offline-acceptance/acceptance.json
```

Use a fresh directory **outside** the repository for `--out`. The runner exits nonzero on source tampering, dirty tracked files, unexpected commit SHA, manifest/schema/index mismatch, test failures, zero discovered tests and timeouts. It leaves `native-unittest.log` and `acceptance.json` for review.

## Covered in default mode

- Pinned Git HEAD / clean tracked checkout; exact match between Git-tracked file set and `RELEASE_MANIFEST.json` (excluding the manifest and checksum index themselves)
- Verify each trusted path is a regular non-symlink file with trusted ancestor directories; SHA-256 every listed file; compare against `SHA256SUMS.txt`
- Run **all `test_*.py` unittest files** with restricted inherited environment; enforce bounded execution and kill the immediate test process group on Linux timeout
- Report number of tests discovered, skips, return code and immutable hash of the log

## NOT covered — must remain open

- The separate `integration_broker_e2e.py` and `integration_rootless_e2e.py` files **are not matched by `test_*.py`** and are not run by this tool.
- It does **not** install/start systemd services, run the real Hermes workload, test AppContainer or macOS sandbox, verify remote write/readback, perform external penetration tests or attest human presence.
- It is **not** an OS sandbox. Tests executed from a trusted checkout may themselves spawn processes or access the network. Never run unreviewed test code or store private secrets in the test account's home directory.
- The manifest is an unsigned integrity check, **not** a guarantee of repository authenticity. Independently verify the commit and trusted key/provenance before running code.
- A result of `PASS_UNIT_SUITE_ONLY` is **not** production acceptance; skipped tests and unsupported platform gates must be reviewed.

## Development evidence

The runner itself passed **12/12 isolated regression tests** on Linux using disposable local Git repositories. Cases included valid suite execution, failed tests, timeouts, environment-secret stripping, malformed manifests, duplicate JSON manifest keys, wrong HEAD, dirty source, checksum index tampering, path traversal, symlinks and unsafe output placement. **The complete native CATL checkout was not available in the test container**, so a full native result is still outstanding. The GitHub Actions workflow remains manual-only.
