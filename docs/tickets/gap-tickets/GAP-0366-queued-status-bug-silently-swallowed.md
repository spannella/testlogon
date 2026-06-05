# GAP-0366: "queued" status bug silently swallowed

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-001.md`); see also `docs/tickets/writeups/VOD-001.md`

## Location
`app/routers/transcode_jobs.py:103`

## Problem / Impact
"queued" status bug silently swallowed

## Fix
change `to_status="queued"` to `to_status="pending_encoding"`

## Notes
This gap was identified by the second-pass as-built review of VOD-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
