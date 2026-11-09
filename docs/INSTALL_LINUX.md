# CATL Linux installation

> **Supported release scope:** Linux protected-broker deployment. CATL is still an evaluation release candidate, not an independently certified security product.

The installer is `tools/catlinstall.py`. It verifies the release manifest before privileged changes, installs CATL into `/opt/catl/venv`, provisions dedicated service identities, preserves existing state/anchors, renders only the reviewed systemd templates, bootstraps fresh anchored state, and fails closed when host verification fails.

## Requirements

- Linux with Python 3.11+
- root access for installation only
- systemd and `systemd-analyze`
- `useradd`, `groupadd`, `usermod`, and `runuser`
- an existing non-root human operator account
- a separately generated Ed25519 operator public key in CATL's raw 32-byte hex format
- internet access for dependency installation, or a trusted local wheelhouse/prebuilt CATL wheel

Ordinary broker/backend operation must remain non-root.

## 1. Verify the source

```bash
python3 tools/catlinstall.py --check --source-root .
```

A manifest/hash mismatch aborts the process.

## 2. Generate the operator signing key as the operator

Do **not** generate or store the private operator key under the broker/service accounts. From an operator-controlled Python environment containing this CATL source/package, use the v0.11 operator-key tooling described in [OPERATOR_SIGNING_V011.md](OPERATOR_SIGNING_V011.md).

The installer receives only the public key:

```text
<64 hexadecimal characters>
```

Keep the private key outside `/etc/catl`, the release archive, CI artifacts and service accounts.

## 3. Install

Example:

```bash
sudo python3 tools/catlinstall.py --install \
  --source-root . \
  --operator-user "$USER" \
  --operator-public-key /path/to/operator-public.hex
```

For an offline/reproducible package install:

```bash
sudo python3 tools/catlinstall.py --install \
  --source-root . \
  --operator-user "$USER" \
  --operator-public-key /path/to/operator-public.hex \
  --wheelhouse /path/to/verified-wheelhouse \
  --package-wheel /path/to/caledapt_agent_trust-*.whl
```

The installer refuses automatic recovery when state exists without its independent anchor, or an anchor exists without corresponding state.

## 4. Static/container acceptance

For a disposable container or a host where systemd is not PID 1:

```bash
sudo python3 tools/catlinstall.py --install \
  --source-root . \
  --operator-user "$USER" \
  --operator-public-key /path/to/operator-public.hex \
  --no-systemd-activate
```

This still installs and verifies the package, identities, filesystem permissions, policy, operator public key, anchor and rendered unit files, and runs `systemd-analyze verify`. It deliberately does not claim live service-manager acceptance.

## 5. Verify an installed host

```bash
sudo python3 tools/catlinstall.py --verify-installed \
  --operator-user "$USER"
```

With normal activation enabled, verification requires both services to be active and then executes CATL's `host-audit` against their effective systemd configuration.

## Installed trust separation

The installer creates/uses:

- `catl-broker` — policy, audit state and independent anchor
- `catl-agent` — untrusted agent-side IPC identity
- `catl-tools` — restricted backend/tool identity
- the existing human operator account — operator IPC only
- distinct `catl-agent-ipc`, `catl-operator-ipc`, and `catl-backend-ipc` groups

Protected state and anchor directories are broker-owned mode `0700`; the tool work directory is tool-service-owned mode `0700`; runtime socket directories use the reviewed group-gated `0710` layout.

## Upgrade/state rules

Installation is idempotent for an unchanged configuration. Existing policy, audit state and anchor are preserved. A changed operator public key is rejected rather than silently rotated. Back up state and the independent anchor before an upgrade.

## Security boundary

Passing the installer and `host-audit` does not constitute independent penetration-test certification, hardware-backed human-presence proof, or universal protection against tool paths that bypass CATL. See [SECURITY.md](../SECURITY.md) and [DEPLOY_ROOTLESS_LINUX.md](DEPLOY_ROOTLESS_LINUX.md).
