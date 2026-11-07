# Native JSON numeric decoding hardening — 7 November 2026

**Scope:** CATL `src/catl/crypto.py` with verified original Git blob `9ca67f3f2e3f198faf60805463b383a1c75f0f84`, on pinned `main` commit `50e32da1da0dafb452a84e222eac52a81f1ebb5e`.

## Root cause

`strict_loads` supplied `parse_constant` to reject explicit JSON `NaN` and `Infinity`, but Python's `json.loads` still interprets exponent overflow such as `{"amount":1e999}` as `float('inf')`. It also underflows a nonzero value such as `1e-9999` to zero. Those values violate the intended bounded numeric representation. Overflow may later fail elsewhere; rejecting at the shared decoder is the correct boundary.

## Patch

`parse_float=_finite_json_float` checks `math.isfinite` and refuses a zero result if the original mantissa has any nonzero digit. Ordinary finite numbers and true zero exponents remain valid. The existing duplicate-key and explicit-constant rejection is preserved. No Python third-party dependencies are added.

## Offline evidence

- Existing original source fetched from private GitHub and verified against the Git blob hash before patch.
- New `tests/test_native_json_numbers_v012.py` runs using the **actual** `catl.crypto` module, not a duplicated parser.
- **13/13 focused unittest cases passed**. They cover normal finite values, nonfinite exponent overflow, nonzero underflow, legitimate true zeros, nested tool argument frames, explicit NaN/Infinity, duplicate JSON keys, maximum wire size, object-only framing and HMAC canonicalisation.
- Deterministic 15,000-input numeric corpus with seed `20261107`: **7,786 accepted as finite/nonzero**, **3,465 rejected for underflow**, **3,749 rejected for overflow**, **0 unexpected outcomes**.
- `python -m py_compile` passed for both changed Python files.

## Reproduce (no GitHub Actions)

From a trusted full CATL checkout:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_native_json_numbers_v012.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Open acceptance

**The full native repository test suite, real broker IPC, native Hermes workload, protected Linux host and independent penetration test were NOT executed in this test environment.** The source was transferred via GitHub connector; the working container cannot directly clone this private repository. A full offline checkout and host evaluation remain necessary. This patch does not expand CATL's supported MCP methods, Windows/macOS isolation or hardware operator presence.
