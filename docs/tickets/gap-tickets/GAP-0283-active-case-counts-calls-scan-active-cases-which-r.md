# GAP-0283: `_active_case_counts` calls `_scan_active_cases` which runs three separate GSI queries (one per status) and returns all active cases to count assignments in Python

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-019 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/KYC-019.md`); see also `docs/tickets/writeups/KYC-019.md`

## Location
`_active_case_counts`

## Problem / Impact
every call to `auto_assign`, `list_admin_workloads`, `workload_dashboard`, or `get_admin_availability` triggers this multi-query/scan; in a production system with thousands of under-review cases this is an O(N) operation on the critical path of assignment scoring; the ticket suggested using a dedicated `assigned-admin-index` GSI on the `kyc_cases` table

## Fix
add an `assigned_admin_sub` GSI to `kyc_cases` and count per-admin via direct GSI queries instead of loading all active cases into memory

## Notes
This gap was identified by the second-pass as-built review of KYC-019. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
