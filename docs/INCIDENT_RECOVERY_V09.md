# 🚨 CATL v0.9 — uncertain-action quarantine and safe recovery

## What changed

Every protected `tools/call` dispatch now has a 128-bit random `action_id`, with a keyed,
checkpointed `dispatch_intent` receipt written **before** the backend is invoked.
CATL correlates this with its terminal receipt (where present). It quarantines a tool
if any dispatch does not have a terminal receipt after a crash, the backend times out,
returns a malformed reply, reports an error, or fails independent postcondition checks.
A new gateway process recovers this state from signed receipt history. The ordinary
tool on/off switch does **not** clear quarantine. The tool disappears from the agent's
available catalogue and all subsequent tool calls are denied until reconciliation.

Older v0.8 dispatch receipts lack `action_id`. CATL conservatively pairs legacy
intent/outcome records by tool + binding; unmatched intents and uncertain outcomes
become migration incidents. Operators must review those before normal use.

## Response procedure (trusted human operator)

1. Pause the gateway, isolate the agent, and preserve the HMAC key, audit SQLite
   database and independent checkpoint **without rewriting** them. Inspect the last
   intended call, the agent's prompt, and the backend's logs. **Never retry** first.
2. Check the true outcome on the *independent target system*, e.g. look up the
   provider's message ID or transaction record. Document whether it occurred.
3. Open the minimisable CATL overlay and select the quarantined action, or use:

   ```bash
   catl operator --operator-socket /run/catl/operator.sock incidents
   catl operator --operator-socket /run/catl/operator.sock reconcile \
       <action-id> --reference ticket:external-check-2026-001
   ```

   The CLI requires a real interactive terminal and an exact confirmation phrase.
   `ticket:`, `readback:` and `incident:` identifiers are supported; **do not put
   passwords, personal data or raw API responses in the reference**.
4. Confirm any downstream duplicate or partial action is corrected according to
   the target system's own procedures. The operator reconciliation records the
   reference in a signed receipt and removes the quarantine **without repeating**
   the original call. Enable a tool only after the incident is investigated.
5. Verify `catl operator ... verify` and audit controls before resuming execution.

## What CATL does NOT prove

- An operator-supplied reference is **not an independently verified external effect**.
- A reported successful tool result without a trusted postcondition is a backend
  claim, not a provable payment/email/remote API outcome.
- A compromised operator OS identity can authorize reconciliation; UID-based
  IPC does not supply independent human authentication or hardware presence.
- An already dispatched action may complete after the user presses PAUSE.
- HMAC receipts and a separate local checkpoint can be rewritten together by a
  fully compromised trusted account. They are not a remote witness.
- Rollback/crash between database and checkpoint updates may require an
  administrator to investigate; never auto-heal a mismatch.

## Testing

`python -m unittest discover -s tests -p test_incident_quarantine_v09.py -v`

`python tools/incident_drill.py` runs a disposable synthetic quarantine and
reconciliation exercise, does not contact any external system, and never touches
live CATL state.
