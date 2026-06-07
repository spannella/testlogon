# GAP-0339: `process_deletion()` in `gdpr_service.py` does not delete Messages, Conversations, or Participants

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PRIVACY-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PRIVACY-001.md`); see also `docs/tickets/writeups/PRIVACY-001.md`

## Location
`process_deletion()`

## Problem / Impact
User messages remain in DynamoDB after "full account deletion"; GDPR Article 17 compliance breach

## Fix
add deletion steps for Messages/Conversations (DM handling) and Participants tables mirroring the ticket §7 design

## Notes
This gap was identified by the second-pass as-built review of PRIVACY-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
