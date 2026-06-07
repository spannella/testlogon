# GAP-0223: Auto-registration in host inventory never happens

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/INFRA-003.md`); see also `docs/tickets/writeups/INFRA-003.md`

## Location
`app/services/ec2_launcher.py:196-202`

## Problem / Impact
Auto-registration in host inventory never happens

## Fix
after storing the instance, call `host_inventory.create_host(user_sub, label=f"{label} (EC2)", hostname=result["public_ip"], port=22, protocol="ssh", source="ec2_auto", group="EC2 Instances")` and write the returned `host_id` back to the DDB record

## Notes
This gap was identified by the second-pass as-built review of INFRA-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
