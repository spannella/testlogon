# GAP-0293: `BroadcastPriceEditor.tsx` component does not exist

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: LCOM-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/LCOM-004.md`); see also `docs/tickets/writeups/LCOM-004.md`

## Location
`BroadcastPriceEditor.tsx`

## Problem / Impact
broadcaster cannot set or clear broadcast-exclusive prices from the UI despite the backend endpoints at `app/routers/broadcast.py:2227` being fully implemented

## Fix
create `BroadcastPriceEditor.tsx` per ticket spec §3.9 and add it to each shelf item row in `ProductShelfManager.tsx`

## Notes
This gap was identified by the second-pass as-built review of LCOM-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
