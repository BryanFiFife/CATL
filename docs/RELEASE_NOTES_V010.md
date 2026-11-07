# 🛡️ CATL v0.10.0rc1 — Red-team hardened release candidate

**Status:** Private, controlled Linux evaluation only. Not security-certified.

### Added
- Privileged operator-availability reserve independent of hostile agent socket traffic.
- Per-agent-connection limit (64 requests); admission remains bounded to 8 concurrent agents.
- Backend event queue overflow stops the reader without blocking; malformed frame floods trip a fault.
- MCP result-content type allowlist and safe, non-local HTTPS resource display links; untrusted extra result fields stripped.
- Strict rejection of complete results mixed with multi-round-trip continuation fields.
- Pinned JSON output schemas support all valid JSON top-level types (not objects only).
- CI privileged job fork-pull-request exclusion; red-team cross-UID saturation test runs with the existing protected Linux identity job.
- Red-team assessment with confirmed baseline exploits, reproducer source, mitigations and residual gates.

### Compatibility/security implications
- Additional unrecognised MCP result fields/content types now fail closed or are omitted by design. Some unreviewed backend servers may need an adapter.
- Resource links and embedded resources with `file:`, `javascript:`, `data:`, private/loopback URLs or non-HTTPS schemes are rejected rather than relayed. CATL never dereferences resource links.
- Operator actions still require protected Linux UID access, **not hardware-backed proof of human presence**.
- Existing state formats and overlay behaviour are unchanged.

### Release gates
- All new targeted tests passed in the developer environment; the full clean-packaged suite and remote GitHub checks must pass before release evidence can be finalised.
- Real host containment, independent pentest, provider-backed external effects, independent audit witness and signed artefact provenance remain outstanding. No production/general-availability claim is made.
