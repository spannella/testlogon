# GAP-0292: `BroadcastPrice.tsx` component does not exist

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: LCOM-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/LCOM-004.md`); see also `docs/tickets/writeups/LCOM-004.md`

## Location
`BroadcastPrice.tsx`

## Problem / Impact
no viewer-facing UI shows struck-through original price, effective broadcast price, LIVE DEAL badge, or expiry countdown

## Fix
create `BroadcastPrice.tsx` per ticket spec §3.8 and integrate into `ProductShelf.tsx` `ProductShelfCard`

## Notes
This gap was identified by the second-pass as-built review of LCOM-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
