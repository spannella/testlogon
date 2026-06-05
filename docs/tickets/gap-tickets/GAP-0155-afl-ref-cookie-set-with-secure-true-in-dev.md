# GAP-0155: afl_ref cookie set with Secure=True in dev

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CREATOR-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/CREATOR-004.md`); see also `docs/tickets/writeups/CREATOR-004.md`

## Location
`app/routers/affiliate_links.py:~174`

## Problem / Impact
cookie silently dropped by browser in HTTP dev environment; redirect flow untestable locally

## Fix
set secure=not S.dev_mode when setting afl_ref cookie matching mock billing pattern

## Notes
This gap was identified by the second-pass as-built review of CREATOR-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
