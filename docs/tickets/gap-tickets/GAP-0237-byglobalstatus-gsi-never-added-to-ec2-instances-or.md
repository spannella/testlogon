# GAP-0237: `ByGlobalStatus` GSI never added to `ec2_instances` or `k8s_pods`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-012 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/INFRA-012.md`); see also `docs/tickets/writeups/INFRA-012.md`

## Location
`ByGlobalStatus`

## Problem / Impact
`ByGlobalStatus` GSI never added to `ec2_instances` or `k8s_pods`

## Fix
add `ByGlobalStatus` GSI with `partition_key="status"`, `sort_key="created_at"` to both tables in `local-ddb-init.py` and update `list_all_instances()` / `list_all_pods()` to use `query()` on the GSI

## Notes
This gap was identified by the second-pass as-built review of INFRA-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
