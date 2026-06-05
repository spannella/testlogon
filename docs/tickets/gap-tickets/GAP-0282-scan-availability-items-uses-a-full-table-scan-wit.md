# GAP-0282: `_scan_availability_items` uses a full-table Scan with a `begins_with` filter on PK

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-019 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-019.md`); see also `docs/tickets/writeups/KYC-019.md`

## Location
`_scan_availability_items`

## Problem / Impact
DynamoDB `begins_with` is a `FilterExpression`, not a `KeyConditionExpression`; the scan fetches ALL items from the `kyc_cases` table and discards non-`ADMIN#` rows; the `kyc_cases` table is the primary application table containing thousands of case items; on a busy table this scan is slow, expensive, and will return incomplete results when more than one 1 MB page of non-ADMIN items exists before all ADMIN items are scanned

## Fix
move admin availability records to a GSI-friendly PK/SK layout (e.g., query `entity_type = "kyc_admin_availability"`) or add a dedicated `admin_availability` table; as a minimal fix, loop `LastEvaluatedKey` until all pages are consumed and document the O(N) cost

## Notes
This gap was identified by the second-pass as-built review of KYC-019. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
