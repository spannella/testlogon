# GAP-0289: `ProductLinkCard.tsx` component does not exist

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: LCOM-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/LCOM-002.md`); see also `docs/tickets/writeups/LCOM-002.md`

## Location
`ProductLinkCard.tsx`

## Problem / Impact
product link messages sent by the broadcaster render as plain text or nothing, blocking the core viewer UX

## Fix
create `ProductLinkCard.tsx` (per ticket spec §3.5) and add `kind === "product_link"` branch in `BroadcastChat.tsx` render loop

## Notes
This gap was identified by the second-pass as-built review of LCOM-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
