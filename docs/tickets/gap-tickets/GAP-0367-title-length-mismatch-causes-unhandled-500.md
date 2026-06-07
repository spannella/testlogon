# GAP-0367: Title length mismatch causes unhandled 500

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-002.md`); see also `docs/tickets/writeups/VOD-002.md`

## Location
`app/routers/vod.py:72`

## Problem / Impact
Title length mismatch causes unhandled 500

## Fix
change `max_length=500` to `max_length=256` in `VideoUploadPresignIn.title`

## Notes
This gap was identified by the second-pass as-built review of VOD-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
