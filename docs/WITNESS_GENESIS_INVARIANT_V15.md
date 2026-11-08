# CATL witness snapshot consistency — v15

`GENESIS` is the only valid MAC at sequence zero. After the first signed audit
receipt, the positive sequence must carry a lowercase 64-character hex MAC.
The witness service now rejects impossible `(sequence, head_mac)` combinations
before signing or database mutation. This protects an independent witness
against an authenticated but faulty or malicious sender that could otherwise
advance its durable sequence to a fictitious genesis and deny subsequent
legitimate checkpoints.

The validation is a protocol invariant and applies to in-memory, durable and
HTTP witness transports through their shared `_head` guard. Existing valid
zero/GENESIS and positive/hex snapshots remain supported. The new six-case
regression suite lives in `tests/test_witness_genesis_v15.py`.

**Important:** This is not independent host deployment evidence. Public-release
acceptance still requires the complete integration suite, a separately owned
witness host with pinned keys and real TLS, hardware operator approval, and
independent review. No public release is authorised by this fix.
