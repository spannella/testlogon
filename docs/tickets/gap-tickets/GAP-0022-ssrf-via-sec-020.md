# GAP-0022: SSRF via SEC-020

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: INFRA-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/INFRA-011.md`); see also `docs/tickets/writeups/INFRA-011.md`

## Location
`app/services/ssh_bastion.py:65-83`

## Problem / Impact
no RFC-1918/metadata IP denylist in bastion hop validation

## Fix
after normalising the IP, call `addr.is_private() or addr.is_loopback() or addr.is_link_local()` and raise `InvalidHop` if true; also reject hostnames that resolve to these ranges (DNS rebinding guard)

## Notes
This gap was identified by the second-pass as-built review of INFRA-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
