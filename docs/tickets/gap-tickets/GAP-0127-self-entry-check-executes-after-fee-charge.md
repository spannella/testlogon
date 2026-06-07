# GAP-0127: Self-entry check executes after fee charge

**Status**: No change needed (verified guard correct, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-014 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-014.md`); see also `docs/tickets/writeups/BCAST-014.md`

## Location
`broadcast_lottery.py:~420`

## Problem / Impact
broadcaster attempting to enter own lottery is charged the entry fee before `BROADCASTER_CANNOT_ENTER` 403 is raised; fee write succeeds with no entry record

## Fix
move `user_id == config["broadcaster_id"]` check before `_charge_entry_fee()`

## Notes
This gap was identified by the second-pass as-built review of BCAST-014. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
