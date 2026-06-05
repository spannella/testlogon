# GAP-0150: No pytest unit tests for group call service

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CALL-012 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/CALL-012.md`); see also `docs/tickets/writeups/CALL-012.md`

## Location
`tests/test_group_calls.py`

## Problem / Impact
No pytest unit tests for group call service

## Fix
create test file using moto + `monkeypatch` for `_get_conversation_participant_ids` per §4.3

## Notes
This gap was identified by the second-pass as-built review of CALL-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
