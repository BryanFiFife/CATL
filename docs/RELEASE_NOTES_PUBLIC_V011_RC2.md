# CATL v0.11.0rc2 — Linux installer release candidate

> **Public evaluation candidate; not independent production certification.**

This candidate keeps the v0.11 protected broker/approval/audit architecture and adds a tested Linux installer plus clearer deployment verification.

## What changed from rc1

- functional `tools/catlinstall.py` Linux installation path
- release-manifest verification before privileged changes
- canonical `/opt/catl/venv`, `/etc/catl`, state, anchor and tool-work paths
- dedicated broker/agent/tool OS identities and separate IPC groups
- reviewed systemd templates rendered with actual non-root UID/GID values
- state/anchor preservation and refusal of ambiguous automatic recovery
- separately provisioned operator public verification key
- fresh anchor bootstrap under the broker identity
- static post-install verification with `systemd-analyze verify`
- live activation path requiring both units active and then passing `catl host-audit`
- offline/prebuilt-wheel support for curated deployment environments
- 31 installer regression tests and a 1,000-case hostile-manifest sweep

## Acceptance evidence

In the isolated Linux development container:

- installer tests: **31 passed / 0 failed / 0 errors**
- hostile manifest cases: **1,000 rejected / 0 unexpected accepts**
- disposable install: **pass**
- post-install verification: **pass**
- idempotent reinstall preserving state/anchor: **pass**
- broker systemd static security score: **1.3 / OK**
- backend systemd static security score: **1.3 / OK**

The CATL core code used by rc1 already recorded 278 passing Linux regressions and a four-UID signed rootless E2E. The installer branch did not alter that core logic until this rc2 version-label update.

## Important remaining scope boundary

The development container cannot create a nested PID namespace and is not booted with systemd as PID 1, so live `systemctl enable/restart` was not rerun here. The normal installer path performs those operations and requires `catl host-audit` to pass afterward. A real target Linux host should run the final `--verify-installed` gate before production use.

Windows/macOS protected runtimes, independent penetration testing, FIDO2 physical-presence proof, independent witness infrastructure and external-provider settlement are outside this Linux release-candidate scope.

## Licence

The repository licence remains evaluation-only unless and until the copyright holder explicitly replaces it. Public availability does not itself grant redistribution, deployment or commercial-use rights.
