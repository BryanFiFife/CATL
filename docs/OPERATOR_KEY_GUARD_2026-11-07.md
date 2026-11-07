# CATL operator software signing key hardening — 7 November 2026

**Scoped source patch, not production certification.** The Linux broker's human approval uses a software-held Ed25519 key. Native CATL currently checks POSIX file mode and ownership, but its operator private-key loader and test-key provisioner did not explicitly refuse Windows, where POSIX mode checks cannot prove a suitable ACL. Key generation also lacked a preflight on group/world writable or symlinked parent directories.

## Changes

- On non-POSIX hosts, reject private operator key loads and key generation before accessing secret files. This is deliberate fail-closed behaviour; Windows AppContainer/ACL protected broker support remains unimplemented.
- Refuse private operator signing key files with more than one hard link.
- Before generating software keys, refuse symlink parent directories and group/world-writable or wrongly owned parent directories on POSIX.
- Preserve POSIX protected signing, Ed25519 verification and existing no-overwrite semantics. Public verification is not blocked by the private-key platform guard.

## Local evidence

The exact changed helper implementation was extracted into an isolated offline test module with real `cryptography` Ed25519 keys, while the full CATL native source is not mounted in this container. **11/11 standalone adversarial tests passed** on Linux/Python 3.13: real signature verifies, patched Windows platform denies both signing/generation without files, group/world-writable parent denial, symlink parent and private-key denial, hardlink denial, broad private-key mode denial, no overwrite, and public-key readback.

The matching native-source test `tests/test_operator_key_platform_v011.py` is added to the repo but **its complete native CATL suite is still unexecuted here**. Don't equate mocked Windows `os.name` with a genuine Windows ACL test.

## Remaining gates

Live broker signing on target protected Linux host; independent operator/agent/backend UIDs; true hardware human presence; actual Windows ACL/AppContainer implementation; independent penetration testing. None may be marked complete based on this patch alone. GitHub Actions remains manual-only.
