# GAP-0369: Worker completes job then tries illegal "published" transition

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-003.md`); see also `docs/tickets/writeups/VOD-003.md`

## Location
`app/services/transcode_worker.py:202`

## Problem / Impact
Worker completes job then tries illegal "published" transition

## Fix
change to `to_status="pending_review"` and add explicit "encoding" transition after claim

## Notes
This gap was identified by the second-pass as-built review of VOD-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
