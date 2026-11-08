# MCP 2026-07-28: complete result cache contract (v16)

The official MCP 2026-07-28 schema requires `resultType`, `ttlMs` and
`cacheScope` on successful results. CATL's modern adapter previously wrote
cache fields for `tools/list` and `server/discover` only, omitting them from
`tools/call`. A modern client validating the schema could reject an otherwise
successful protected tool execution. The adapter also preserved unchecked
upstream cache hints if they were present.

`catl.protocol.modernize()` now pins every successful response to:

- `resultType = "complete"`
- `ttlMs = 0`
- `cacheScope = "private"`

This is an intentional fail-closed no-cache policy. Operator-controlled tool
visibility, signed approvals and audit posture can change at any moment.
Tool results must not be treated as public or reusable authorization.

Regression `tests/test_modern_response_cache_contract_v16.py` covers ordinary
and structured tool calls, unsafe upstream hints, discovery, tools/list,
errors, unsupported MRTR and server identity. Reproduction against the
byte-identical original `src/catl/protocol.py` Git blob produced four
errors/failures; all 8 tests pass against the correction.

References:
- https://modelcontextprotocol.io/specification/2026-07-28/basic/index
- https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.json

This is a focused adapter-level regression, **not** the full CATL native suite,
Hermes deployment acceptance or approval to publish a release.
