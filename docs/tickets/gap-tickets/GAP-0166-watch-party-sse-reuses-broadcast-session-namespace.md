# GAP-0166: Watch party SSE reuses broadcast session namespace

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENGAGE-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENGAGE-004.md`); see also `docs/tickets/writeups/ENGAGE-004.md`

## Location
`app/routers/watch_party.py:266`

## Problem / Impact
more practically

## Fix
prefix party SSE keys with a watch-party namespace (`wp_sse:{party_id}`) or create a separate `_WATCH_PARTY_SUBSCRIBERS` dict in a dedicated `watch_party_sse.py` module

## Notes
This gap was identified by the second-pass as-built review of ENGAGE-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
