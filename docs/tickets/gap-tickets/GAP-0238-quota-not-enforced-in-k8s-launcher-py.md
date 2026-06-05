# GAP-0238: quota not enforced in `k8s_launcher.py`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-012 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/INFRA-012.md`); see also `docs/tickets/writeups/INFRA-012.md`

## Location
`k8s_launcher.py`

## Problem / Impact
quota not enforced in `k8s_launcher.py`

## Fix
add `enforce_k8s_quota(user_sub, preset)` call in `k8s_launcher.py` matching the pattern in `ec2_launcher.py`

## Notes
This gap was identified by the second-pass as-built review of INFRA-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
