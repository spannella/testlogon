# GAP-0268: Feature gating not applied to endpoints

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-009 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-009.md`); see also `docs/tickets/writeups/KYC-009.md`

## Location
`require_kyc_tier`

## Problem / Impact
multiple routers (messaging, billing, newsfeed, etc.)

## Fix
apply `Depends(require_kyc_tier(N))` to each endpoint in priority order per Phase 2–4 rollout plan

## Notes
This gap was identified by the second-pass as-built review of KYC-009. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
