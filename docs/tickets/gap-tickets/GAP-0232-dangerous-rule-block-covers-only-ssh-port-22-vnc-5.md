# GAP-0232: Dangerous-rule block covers only SSH port 22; VNC (5900-5999), RDP (3389), and IPv6 (::/0) are not blocked

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-009 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/INFRA-009.md`); see also `docs/tickets/writeups/INFRA-009.md`

## Location
`app/services/security_groups.py:145-157`

## Problem / Impact
Dangerous-rule block covers only SSH port 22; VNC (5900-5999), RDP (3389), and IPv6 (::/0) are not blocked

## Fix
extend `is_dangerous_rule` to also flag port ranges covering 3389, 5900-5999, and source `::/0`; or generalise to a configurable blocklist of (port-range, source) pairs

## Notes
This gap was identified by the second-pass as-built review of INFRA-009. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
