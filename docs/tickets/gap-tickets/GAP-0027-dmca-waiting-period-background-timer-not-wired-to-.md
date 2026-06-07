# GAP-0027: DMCA waiting-period background timer not wired to startup

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: MOD-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MOD-002.md`); see also `docs/tickets/writeups/MOD-002.md`

## Location
`app/main.py:482-483`

## Problem / Impact
DMCA waiting-period background timer not wired to startup

## Fix
add `_dmca_timer_loop` async background task registered on startup per section 3.7

## Notes
This gap was identified by the second-pass as-built review of MOD-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
