# CATL + Hermes v1.4: protected-profile *evaluation* verifier

**Status: PRIVATE EXPERIMENTAL.** These files are the locally tested integration
security checks, copied into this repository for review and reproducibility.
They **do not make CATL a complete Hermes sandbox** and do not certify the
production host, the CATL broker, or any real Hermes process. See the root
`docs/ROADMAP_STATUS_2026-11-07.md` for open release gates.

## What is actually implemented

- Read-only preflight of Hermes' runtime-resolved CLI toolsets and actual tool
  names, with independent config-hash and UID checks. It explicitly checks the
  raw tool registry rather than relying on a collapsed `tool_search` summary.
- Requires a root-controlled Python virtual environment, verifying file and
  directory owners, write permissions, symlinks and importable module paths.
- Requires the verifier script and its imports to be root-controlled, outside
  the agent's editable workspace. The untrusted-Python diagnostic always exits
  nonzero; it cannot signal protected release readiness.
- Bounded subprocess communication, group cleanup, strict snapshot evidence.
- Disposable synthetic-Hermes tool registry checks and a real Linux kernel
  four-UID UNIX socket ACL and `SO_PEERCRED` fixture, **not the CATL broker**.

## Run the isolated test subset without GitHub Actions

Requires Python 3.11+, `PyYAML`, Linux and (for the real-UID fixtures) a disposable
root-capable container with `setpriv`/`runuser`. Run only on an isolated lab host;
these tests use synthetic UIDs and temporary Unix sockets.

```bash
PYTHONPATH=integrations/hermes python -m unittest discover \
  -s integrations/hermes/tests -v
```

The kernel/UID tests skip on unsupported or unprivileged hosts. **Do not run
as root on a production workstation.** Check skips rather than calling them
passed security gates.

## Protected verifier installation (administrator)

Do **not** run the verifier from an agent-controlled checkout. After reviewing
files and securing their provenance, install only the needed helper files
under a root-owned tree (`/opt/catl-security` below):

```bash
sudo install -d -o root -g root -m 0755 /opt/catl-security
for file in hermes_effective_guard.py hermes_audit.py strict_yaml.py profile_guard.py; do
  sudo install -o root -g root -m 0644 "integrations/hermes/$file" "/opt/catl-security/$file"
done
```

Install Hermes in a **separate root-controlled virtual environment** and run
its dedicated CLI profile under the isolated `catl-agent` account. After
provisioning protected sockets and policies, inspect its read-only inventory:

```bash
sudo -u catl-agent env -i PATH=/usr/bin:/bin LANG=C.UTF-8 \
  /usr/bin/python3 /opt/catl-security/hermes_effective_guard.py \
    --hermes-python /opt/hermes-venv/bin/python \
    --hermes-home /home/catl-agent/.hermes/profiles/catl-eval \
    --agent-uid "$(id -u catl-agent)" --expect armed
```

This is only an inspection snapshot. The operator and host OS must
independently protect the verifier, imports, profile, plugin registry and
Hermes launcher from agent modification. The full Hermes runtime has not been
executed or proven confined by these tests. No claims of live enforcement,
external-action verification, independent pentesting, signed build provenance,
Windows/macOS secure broker or hardware human presence are made.

The full **downloadable** integration package (with installer, signed ZIP and
more tests) is separate and pins the historical CATL core commit
`f1d7184fb32e7dce2f3f85c8983bdc37e8578e6f`.
