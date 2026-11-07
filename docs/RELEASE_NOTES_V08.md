# 🔐 CATL v0.8.0rc1 — pinned result-contract firewall

- The gateway treats unknown modern MCP `resultType` values and `input_required` as unsupported, with an audit record that a side effect may already have happened.
- For any PINNED tool declaring `outputSchema`, successful `structuredContent` must exist as an object and validate against the pinned local JSON Schema Draft 2020-12. Remote schema resolution is denied.
- Backend metadata is stripped; the gateway never interprets a backend-supplied CATL-approval flag as trusted authority.
- Result-schema or result-kind mismatch does not automatically retry an action. The caller receives `backend_result_unverified_side_effect_possible`.
- Twelve new tests, including through the full gateway with signed audit receipts, assert these boundaries. Existing regression and Linux integration gates must continue to pass.

**Non-goals:** This is not a full implementation of MCP Multi Round-Trip Requests, Tasks, HTTP or external-effect verification. Host hardening and independent penetration testing remain release gates.
