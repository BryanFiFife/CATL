# CATL v0.9 — focused engineering security review

The primary issue addressed here is **automatic duplicate action exposure after
ambiguous dispatch**, observed in v0.8 despite its signed `dispatch_intent` log.
The previous gateway returned errors but allowed subsequent calls to the same
permitted tool. A malicious or over-eager agent could retry a payment or email.

New boundary: unique dispatch IDs and ledger-derived quarantine that survives
restart and ordinary tool toggles. Pre-v0.9 receipt pairs are handled conservatively.
Operator reconciliation requires a separate local UID-authenticated channel,
explicit acknowledgement, and a bounded external reference. Raw tool arguments
are not returned in the incident listing. No automatic re-execution exists.

Adversarial tests cover timeout, missing terminal record/crash, unexpected
result, upstream RPC error, tool-level error, on/off toggle, forged and
replayed reconciliation, old audit rows, corruption, and GUI reporting.

**Known limits:** the operator reference is human-supplied, not provider-signed;
no hardware challenge or off-host independent witness exists; the Linux host
sandbox and external action verifier remain deployment-dependent; full current
MCP interoperability is not demonstrated. A signed ledger alone cannot stop a
compromised process that is authorised to access the backend directly. The
security critical path must still undergo independent penetration review.
