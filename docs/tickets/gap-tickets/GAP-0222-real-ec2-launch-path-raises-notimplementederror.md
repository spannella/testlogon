# GAP-0222: Real EC2 launch path raises `NotImplementedError`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-003 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/INFRA-003.md`); see also `docs/tickets/writeups/INFRA-003.md`

## Location
`NotImplementedError`

## Problem / Impact
when `S.ec2_mock_enabled = False` (i.e., in production with real AWS), `launch_instance()` hits `raise NotImplementedError("Real EC2 launch not implemented yet")`; same for `stop_instance` (line ~273), `start_instance` (~302), `terminate_instance` (~332), `reboot_instance` (~370)

## Fix
implement `_real_ec2_launch()` using `boto3.client("ec2").run_instances(...)`, add EC2 client to `app/core/aws.py` following the existing `sns_client()` pattern

## Notes
This gap was identified by the second-pass as-built review of INFRA-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
