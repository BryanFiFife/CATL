# CATL native-source regression and Linux integration acceptance — 8 November 2026

**Tested provenance:** private GitHub PR #10, source archive named `CATL-feature-six-roadmap-foundations-20261107.zip`, pinned parent GitHub commit `ba5fc502310d30117fa92544bc96bbd6322094d9`. This report documents tests of the extracted files, not tests run by GitHub Actions. The GitHub ZIP has no `.git` directory; consequently `offline_native_acceptance.py` cannot independently verify a local commit ID from that extraction. The source file-set comparison showed 168 expected files; the original manifest had two stale report hashes, which were repaired using the actual file bytes after verifying those two files' Git blob IDs against GitHub.

## Native suite and corrections

- Initial full run on Linux/Python 3.13 using `PYTHONPATH=src CATL_CI_HEADLESS=1 xvfb-run -a python -m unittest discover -s tests -v`: **479 executed, 2 failures, 7 skipped**. Both failed tests were stale assumptions from before the modern MCP and independent witness/platform-evidence additions.
- `test_rootless_security.py` now pins the exact four backend methods, including `server/discover`, while continuing to deny prompt/resource methods.
- `test_static_security.py` now permits the exact reviewed `urllib.request` client symbols within `witness_protocol.py` and AF_UNIX socket inspection in `platform_proofs.py`, without permitting networking in the broker or other modules.
- `tools/security_sanity.py` now permits the scoped witness HTTPS client and read-only Windows token `ctypes` APIs while maintaining a default-deny import and dynamic-execution scan. A new 5-test fixture verifies that expanding the imports, enabling TCP socket families, using shell execution or adding `exec` is still detected.
- Added a 2-test **real subprocess** modern MCP upstream bridge: stateless modern server discovery → tool catalogue → policy-controlled dispatch; explicitly rejects silent fallback to legacy upstream.
- The user-provided archive's original manifest entries for `docs/RED_TEAM_ASSESSMENT_V010.md` and `reports/local-verification-v010.json` were stale despite matching GitHub's actual Git blob hashes. Updated both SHA-256 values; do not modify those historical reports to match stale checksums.
- **Final native suite with Xvfb and GUI enabled (no `CATL_CI_HEADLESS`): 486 discovered, 484 passed, 2 skipped (Windows-only native private-key tests), 0 failures, ~42.6 seconds.** The five operator GUI widget tests passed under the virtual display rather than being excluded.
- **Second runner:** `xvfb-run -a python -m pytest -q tests` passed **484 tests + 172 subtests**, with the same two Windows-only skips, in ~46.1 seconds. The headless variant also passed 479 pytest tests, 7 skips and 172 subtests.
- **Static tool:** `python tools/security_sanity.py` passed after narrowing exemptions; five dedicated negative tests validate that unrelated network and runtime execution primitives still fail.
- **Release builder:** 171 indexed source/asset files and 2 integrity metadata files, 173 ZIP entries total; deterministic archive hash and clean-extraction full native regression are acceptance checks. The release manifest is unsigned and must not be treated as a provenance signature.

## Local integration coverage

- `PYTHONPATH=src python tests/integration_rootless_e2e.py` passed on a disposable root-capable Linux test container with four synthetic UIDs and real Unix peer credentials, Ed25519 operator approval, replay rejection, independently supervised backend and MCP shim traffic.
- `PYTHONPATH=src python tests/integration_broker_e2e.py` passed with separate broker/client identities and anchored audit.
- `PYTHONPATH=integrations/hermes python -m unittest discover -s integrations/hermes/tests -v` passed **22/22** synthetic-Hermes and kernel UID-ACL tests. This is not a live installed Hermes runtime or proof against all native tool bypasses.
- The static sanity scan, Python compilation, CLI help and release file-set verification are additional acceptance checks.

## What remains unverified

- **Not production GA:** no Windows AppContainer/pipe service tested on Windows; no macOS signed sandbox and getpeereid test on a Mac; no real FIDO2 device with one-use broker challenge and durable counters; no systemd-managed production host with egress/LSM constraints; no independent off-host witness or real SMTP/payment/API provider-side settlement and readback; no independent external penetration test and signed reproducible supply-chain provenance.
- The Linux test container uses Python **3.13.5**, `jsonschema` **4.26.0**, and `cryptography` **46.0.4**. The project declares `cryptography==50.0.2`; repeat native tests under that pinned version in an isolated build before release approval. Current Linux UID tests use synthetic accounts, not an actual production host image.
- Linux witness source-IP allowlisting does not prevent saturation by 16 stalled clients from an **allowed** source. Host firewall/source admission, rate limiting, and witness operating-system controls remain necessary.
- Tests exercising Windows/macOS fail-closed behaviours are not evidence of operating-system containment.

## Safe reproductions

```bash
export PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1
unset CATL_CI_HEADLESS # run all five Tk GUI tests under Xvfb
xvfb-run -a python -m unittest discover -s tests -v
xvfb-run -a python -m pytest -q tests
python tests/integration_rootless_e2e.py       # disposable Linux root-capable test container ONLY
python tests/integration_broker_e2e.py         # disposable Linux test container ONLY
PYTHONPATH=integrations/hermes python -m unittest discover -s integrations/hermes/tests -v
python tools/security_sanity.py
python -m compileall -q src tests integrations/hermes tools
python tools/release_pack.py --output /tmp/catl-release-evaluation.zip
python tools/release_pack.py --verify /tmp/catl-release-evaluation.zip
```

**Release decision:** this run proves native Linux regression/integration functionality for the tested build, not safe production deployment across all supported platforms. The six combined roadmap milestones remain **unchecked**.
