# GAP-0224: Host inventory not cleaned up on instance termination

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/INFRA-003.md`); see also `docs/tickets/writeups/INFRA-003.md`

## Location
`app/services/ec2_launcher.py:320-357`

## Problem / Impact
Host inventory not cleaned up on instance termination

## Fix
retrieve `item["host_id"]`, call `host_inventory.delete_host(user_sub, host_id)` inside `terminate_instance()`

## Notes
This gap was identified by the second-pass as-built review of INFRA-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
