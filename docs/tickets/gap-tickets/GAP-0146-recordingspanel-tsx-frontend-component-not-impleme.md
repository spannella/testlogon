# GAP-0146: `RecordingsPanel.tsx` frontend component not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CALL-010 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/CALL-010.md`); see also `docs/tickets/writeups/CALL-010.md`

## Location
`RecordingsPanel.tsx`

## Problem / Impact
post-call recording discovery relies entirely on ephemeral upload toast; users who miss the toast have no UI path to find recordings

## Fix
create `RecordingsPanel` component querying `GET /messages/recordings?conversation_id={id}` per §4.1

## Notes
This gap was identified by the second-pass as-built review of CALL-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
