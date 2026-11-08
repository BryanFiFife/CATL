# CATL release Git execution boundary — 8 November 2026

**Scope:** Offline source packaging, source-to-Git proof, guarded Ed25519 release signing and native unit-suite acceptance. This document is a developer-run regression report, **not a public-production certification**.

## Exploit reproduced before patch

Read-only-looking Git commands can invoke executable repository or environment configuration. A disposable repository with `GIT_CONFIG_COUNT=1`, `core.fsmonitor=<script>` and a marker-writing, harmless shell script caused the old `release_pack._tracked_files()` path to execute the script. A repository-local `.git/config` fsmonitor setting had the same effect. A fake `git` binary prepended to `PATH` also changed the executable used by the release tooling.

A separate test confirmed that `git diff --no-ext-diff --no-textconv` still executes a repository-defined `.gitattributes` `filter.<driver>.clean` command when detecting modified tracked files. Disabling fsmonitor or external diff is **not sufficient**.

## Change

- Git subprocesses now run with a fresh, restricted environment: OS system PATH, `LC_ALL=C`, no inherited `GIT_*` metadata, no global/system Git config, and read-only optional locking mode.
- Git is invoked with replacement objects disabled, fsmonitor overridden to `false`, external diff disabled and hook execution path replaced.
- The release builder **does not invoke Git worktree diff**. It compares each packaged file's actual bytes to its immutable committed Git blob identifier; modified tracked source continues to fail before an archive can be accepted.
- The offline native runner **does not invoke `git status`**. Its existing exact source-tree scanner checks every tracked file and mode, rejects untracked executable files (including ignored bytecode), and compares actual bytes with the committed Git tree, before and after running tests.
- The guarded signer and ZIP source-equivalence verifier share the restricted Git subprocess helper from the source-controlled release-pack module. The native runner implements the same protection without importing other repository code before verifying the checkout.

## Independent local test evidence

`tests/test_git_subprocess_env_v13.py` reproduces and blocks inherited fsmonitor injection, repository fsmonitor injection, attacker `PATH` resolution, `GIT_DIR`/`GIT_WORK_TREE` redirection, and `.gitattributes` clean-filter invocation. The inherited-config and clean-filter attacks were executed with harmless marker files in disposable temporary repositories. These tests never contact GitHub, push code, use real credentials or execute CI.

The packaging/signing and native-runner regressions are listed in the development evidence accompanying the patch. **Only the exact local tested source hashes, not the test-report text alone, constitute the reproducibility link.**

## Security boundaries not closed by this patch

A trusted, administrator-controlled OS Git binary is still assumed. An attacker controlling `/usr/bin/git`, the running Python interpreter, the installed packages, or the signing account is outside this specific control. A real broker/Hermes deployment, separate systemd/LSM/cgroup confinement, hardware-backed operator presence, off-host witness, remote provider effects and independent penetration tests are still **open** public-production release gates. Do not treat this source-hardening result as an independent security assessment.
