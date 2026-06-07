# GAP-0290: `ShelfProductPicker.tsx` dialog does not exist

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: LCOM-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/LCOM-002.md`); see also `docs/tickets/writeups/LCOM-002.md`

## Location
`ShelfProductPicker.tsx`

## Problem / Impact
broadcaster has no UI to select a shelf product to share in chat; the `POST .../chat/product` API endpoint at `app/routers/broadcast.py:1698` is fully built but unreachable from the UI

## Fix
create `ShelfProductPicker.tsx` (per ticket spec §3.7) and wire "Share Product" button in `BroadcastChat.tsx`

## Notes
This gap was identified by the second-pass as-built review of LCOM-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
