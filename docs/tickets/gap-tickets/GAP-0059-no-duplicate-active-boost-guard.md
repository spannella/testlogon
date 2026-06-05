# GAP-0059: no duplicate-active-boost guard

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-012 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-012.md`); see also `docs/tickets/writeups/ADS-012.md`

## Location
`app/services/content_boost.py:create_boost`

## Problem / Impact
user can create multiple simultaneous boosts for same content, paying budget multiple times

## Fix
query GSI2 for active boosts before write; raise ValueError if one exists

## Notes
This gap was identified by the second-pass as-built review of ADS-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
