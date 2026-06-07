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

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Resolved alongside GAP-0372 (VOD-010): GET /v1/vod/drm/key/{key_id} now requires the tenant to match the verified entitlement token's tenant_id claim (403 tenant_mismatch / 403 missing_tenant), with an optional tenant query param. Regression covered by tests/test_gap_0372_vod_drm_tenant.py.
