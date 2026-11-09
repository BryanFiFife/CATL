# CATL Linux installer acceptance — 9 November 2026

**Candidate branch:** `features/installer-bootstrap`

**Source commit tested before release metadata refresh:** `eb183e8dc1e648d2d15822eb928d765aa901b538`

This report records work actually executed in the isolated Linux development container. It does not claim an independent penetration test or production certification.

## Installer unit/security regression

Command:

```bash
python3 -m unittest discover -s tests -p 'test_catl_installer.py' -v
```

Result: **31 tests passed, 0 failed, 0 errors**.

Covered areas include manifest/hash validation, traversal/symlink rejection, Python discovery, reviewed systemd-template enforcement, non-root UID/GID substitution, operator-key validation, state/anchor recovery refusal, ownership/mode checks, subprocess failure propagation, package-failure transaction ordering, static-install flow, live-activation call ordering and host-audit invocation.

## Adversarial manifest sweep

A deterministic 1,000-case hostile manifest sweep exercised traversal, absolute paths, malformed digests, backslash paths and parent-component attacks.

Result: **1,000 rejected / 0 unexpected accepts**.

No `os.system`, `shell=True`, `eval` or `exec` execution path is present in the installer.

## Disposable Linux installation

The installer was executed as root inside a disposable Linux container using a synthetic CATL package fixture and the repository's reviewed systemd/policy/tmpfiles inputs.

Verified mechanics:

- package installed into `/opt/catl/venv`
- dedicated `catl-broker`, `catl-agent`, and `catl-tools` identities
- separate agent/operator/backend IPC groups
- operator account restricted to operator IPC membership
- broker state and independent anchor owned by `catl-broker`, mode `0700`
- tool work directory owned by `catl-tools`, mode `0700`
- `/etc/catl` restricted to root/broker group
- policy/operator-public-key modes `0640`
- anchor bootstrap completed
- `--verify-installed --no-systemd-activate` passed
- a second installer run passed without resetting state/anchor

The first attempted source build also exposed the expected no-network PEP-517 dependency issue. The installer was extended with a verified prebuilt-wheel path; subsequent offline fixture installation passed.

## systemd static analysis

The rendered broker and backend units both passed:

```bash
systemd-analyze verify ...
```

Offline security analysis:

- `catl-broker.service`: **1.3 / OK**
- `catl-backend.service`: **1.3 / OK**

The rendered units retain the reviewed no-capability, AF_UNIX-only, private-network, strict filesystem and resource restrictions.

## Core CATL evidence relationship

GitHub comparison establishes that CATL core source at the installer candidate is unchanged from public `v0.11.0-rc1`; the branch changes are installer/test/release-metadata only.

Existing rc1 evidence records **278 passing Linux regression tests** and a real four-UID signed rootless E2E covering unsigned-forgery denial, tool call, approval/replay, audit, channel isolation and key denial. Those core tests were not freshly rerun in this container because a complete repository archive was unavailable through the execution sandbox.

## Remaining scope boundary

This container is not booted with systemd as PID 1, so real `systemctl enable/restart` could not be executed here. The normal installer path nevertheless requires those operations, verifies both services are active, and runs CATL `host-audit` afterward.

A real target Linux host should therefore run the final installer and `--verify-installed` before calling the deployment production-ready.

Windows/macOS protected runtimes, independent penetration testing, FIDO2 physical-presence proof, independent witness infrastructure and external-provider settlement are outside this Linux release-candidate acceptance.
