# GAP-0373: tenant_id not validated at key serve time

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-010 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-010.md`); see also `docs/tickets/writeups/VOD-010.md`

## Location
`app/routers/vod_drm.py:67-71`

## Problem / Impact
endpoint validates asset_id in token vs query param but never checks tenant_id claim; attacker can supply their own tenant_id in the URL while using a valid token for a different tenant

## Fix
extract and compare token tenant_id against a required tenant_id query parameter (matches spec §6.1)

## Notes
This gap was identified by the second-pass as-built review of VOD-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
