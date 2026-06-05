# GAP-0147: No billing props wired into `ConversationView.tsx` or `CallSessionOverlay.tsx`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CALL-011 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/CALL-011.md`); see also `docs/tickets/writeups/CALL-011.md`

## Location
`ConversationView.tsx`

## Problem / Impact
No billing props wired into `ConversationView.tsx` or `CallSessionOverlay.tsx`

## Fix
wire hook in ConversationView and pass billing props to overlay per §4.2/4.3

## Notes
This gap was identified by the second-pass as-built review of CALL-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
