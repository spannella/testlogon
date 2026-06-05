# GAP-0227: Host inventory not cleaned up on pod termination

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/INFRA-004.md`); see also `docs/tickets/writeups/INFRA-004.md`

## Location
`app/services/k8s_launcher.py:260-286`

## Problem / Impact
Host inventory not cleaned up on pod termination

## Fix
call `host_inventory.delete_host(user_sub, item["host_id"])` inside `terminate_pod()` if `host_id` is non-empty

## Notes
This gap was identified by the second-pass as-built review of INFRA-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
