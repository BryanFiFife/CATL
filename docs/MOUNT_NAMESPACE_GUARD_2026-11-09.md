# CATL mount/namespace escape acceptance fix — 9 November 2026

**Status:** new source-level Linux host-audit hardening, NOT a production
deployment acceptance or third-party security certificate.

## Reproduced defect

At source commit `8fe01fe3ec2fe7468d5f46ae4f8cbe52302c3877`,
`catl.host_audit.assess_unit` returned `passed=True` on the otherwise
reviewed broker profile with any one of the following extra properties:

- `BindPaths=/tmp:/etc/catl`
- `NetworkNamespacePath=/run/netns/host`
- `JoinsNamespaceOf=untrusted.service`

These effective service settings could expose an unreviewed host path,
writable bind mount or shared namespace even while existing sandbox checks
appeared compliant. See the [systemd.exec reference](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
for bind mounts and namespace configuration.

## Code change and source-native coverage

`src/catl/systemd_runtime_gates.py` now rejects every non-empty
effective `BindPaths`, `BindReadOnlyPaths`,
`NetworkNamespacePath`, `JoinsNamespaceOf`, `RootDirectory`,
`RootImage` and `TemporaryFileSystem` entry for the *specific reviewed*
CATL broker/backend service profiles. An alternative profile may permit
individual mounts only after explicit policy review and a separate test suite.

New tests prove both the direct property checker and the integrated
`catl.host_audit.assess_unit` refusal. The existing 10,000 fixed-seed
hostile-property mutation regression was expanded to include all seven
new keys; malformed values fail closed.

## Local independent evidence

- `PYTHONPATH=src python -m unittest discover -s tests -p test_*.py`:
  **39 passed**, 0 failed, against isolated source-exact files.
- `PYTHONPATH=src python -m pytest tests -q`: **39 passed**, 110
  additional subtests, 0 failures.
- `python -m compileall` on the selected source/tests/tools: PASS.
- Broker/backend static `systemd-analyze verify`: **2/2** passed,
  after temporary substitutions for unavailable service users, groups and
  executables; offline exposure scores **1.6 OK** each.
- The three changed Python files were verified byte-identical to the GitHub
  Git blob IDs after patches, using `git hash-object`.

**Scope limit:** the execution environment did not have a complete
authenticated private Git checkout, target systemd service installation,
live rootless broker, AppArmor/SELinux enforcement, physical FIDO2 hardware,
real external providers, macOS/Windows hosts or a separate witness machine.
No entire current CATL 707-case test run or independent penetration test
has been performed in this verification session.

The broad production Linux gate and all other combined roadmap milestones
remain **OPEN**. These improvements are appropriate for a clearly marked
evaluation source candidate only. GitHub Actions remain manual-only.
