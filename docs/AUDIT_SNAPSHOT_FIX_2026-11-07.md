# CATL native audit snapshot consistency — 7 November 2026

## Finding

Previously, `State.verify()` performed a receipt-chain scan **outside** the checkpoint lock and then called `assert_anchor()`, which reacquired the checkpoint lock and performed a second scan. An append between those scans can make the function return a stale `count` and `head_mac` with `valid: true` because the second scan authenticates a newer checkpoint. Every anchored verification also performs two complete O(N) HMAC-chain passes.

## Repair

The new implementation obtains the anchor lock first, then performs **one** verified receipt-chain scan and compares its resulting head against the independent anchor before releasing the lock. Unanchored evaluation mode performs one verified scan and explicitly returns `externally_anchored: false`. Database errors are reported as `valid: false` instead of propagating from this read-only health-check method.

The local anchor remains HMAC-backed and stored separately; this does not create a remote/hardware witness or address a compromised broker identity. The complete ledger must still be scanned for each verification and may be expensive at scale. Production throughput and crash consistency remain open test gates.

## Executed local evidence

- 7/7 isolated method-level tests passed.
- A deterministic old-vs-new fixture reproduces the prior mismatch: old code can return `valid: true` and a stale `(0, GENESIS)` snapshot after the later anchor check authenticates `(1, NEW)`.
- A reference implementation of the replacement returns invalid for the mismatch and performs only one head scan.
- Fake-anchor concurrency test confirms that a writer waits until the receipt scan and anchor check finish.
- SQLite failure handling and unanchored status were exercised.
- New native CATL regression tests were added for a **future run against the actual repository**. They were syntax-checked but **not executed** here: the full private repository source is only accessible via the GitHub connector, not a local checkout.

## What this does not prove

This is not a full native CATL suite pass, not actual Hermes integration, not protection against coordinated DB+anchor tampering, not a hardware attestation, and not an independent penetration test. The six combined release milestones stay open.

## Required native acceptance

On a trusted checkout of the exact commit, run:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_native_audit_snapshot_v011.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

The second command is the full native unit suite. Real Linux four-UID smoke tests remain separate. GitHub Actions are deliberately manual-only.
