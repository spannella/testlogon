# GAP-0274: `kyc.case.created` event not dispatched from the router

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-011.md`); see also `docs/tickets/writeups/KYC-011.md`

## Location
`kyc.case.created`

## Problem / Impact
the router logs an audit event `"kyc_case_created"` at line 548 but never calls `emit_kyc_event`; `kyc.case.created` does not appear in any service-layer call path that originates from the user-facing create endpoint; the kyc_partner_api fires it only for partner-originated flows

## Fix
add `_emit_kyc_event_safe(event="kyc.case.created", ...)` in `create_kyc_case()` in the router or in `STORE.create_case()` in the service

## Notes
This gap was identified by the second-pass as-built review of KYC-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
