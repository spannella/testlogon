# GAP-0278: `list_templates` uses a full-table Scan instead of the `status-updated-index` GSI

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-017 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-017.md`); see also `docs/tickets/writeups/KYC-017.md`

## Location
`list_templates`

## Problem / Impact
at scale, scanning the entire `kyc_document_templates` table on every admin list request is unbounded and expensive; the `status-updated-index` GSI (`PK=status, SK=updated_at`) was designed for exactly this query but is bypassed; only the `get_required_templates_for_tier` method (line 371) uses the GSI correctly

## Fix
replace the `scan()` loop in `list_templates` with a `query()` on `status-updated-index` when `status` is supplied, and a parallel query over all statuses otherwise

## Notes
This gap was identified by the second-pass as-built review of KYC-017. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
