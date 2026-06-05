# GAP-0265: Auto-escalate does not write escalation flag to case

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-008 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-008.md`); see also `docs/tickets/writeups/KYC-008.md`

## Location
`app/services/kyc_risk_scoring.py`

## Problem / Impact
Auto-escalate does not write escalation flag to case

## Fix
add DDB `update_item` writing `review.escalated`, `review.escalation_reason`, `review.escalated_at` in the critical-tier branch

## Notes
This gap was identified by the second-pass as-built review of KYC-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
