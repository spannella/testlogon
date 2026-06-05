# GAP-0145: Missing timeline system message on recording completion

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CALL-009 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/CALL-009.md`); see also `docs/tickets/writeups/CALL-009.md`

## Location
`app/routers/call_recording.py:322`

## Problem / Impact
users cannot discover recordings from the conversation view without a separate panel

## Fix
call `emit_call_timeline_event` with `event_type="call.recording_available"` after status update per §4.1

## Notes
This gap was identified by the second-pass as-built review of CALL-009. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
