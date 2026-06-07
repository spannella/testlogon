# GAP-0226: Auto-registration in host inventory never happens

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-004 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/INFRA-004.md`); see also `docs/tickets/writeups/INFRA-004.md`

## Location
`app/services/k8s_launcher.py:196-197`

## Problem / Impact
Auto-registration in host inventory never happens

## Fix
after storing the pod record, call `host_inventory.create_host(user_sub, label=f"{label} (K8s)", hostname=result["service_hostname"], port=22, protocol="ssh", source="k8s_auto", group="K8s Containers")` and write back `host_id` ��� Effort: S

## Notes
This gap was identified by the second-pass as-built review of INFRA-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
