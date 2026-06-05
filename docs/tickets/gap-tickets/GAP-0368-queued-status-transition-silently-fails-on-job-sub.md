# GAP-0368: "queued" status transition silently fails on job submission

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-003.md`); see also `docs/tickets/writeups/VOD-003.md`

## Location
`app/routers/transcode_jobs.py:103`

## Problem / Impact
same bug as VOD-001 §3.1; video stays in "created" after job submit; `ByStatusCreatedAt` GSI for "pending_encoding" always empty, breaking admin dashboards

## Fix
change `to_status="queued"` to `to_status="pending_encoding"`

## Notes
This gap was identified by the second-pass as-built review of VOD-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
