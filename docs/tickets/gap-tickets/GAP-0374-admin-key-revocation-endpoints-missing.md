# GAP-0374: admin key revocation endpoints missing

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-010 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/VOD-010.md`); see also `docs/tickets/writeups/VOD-010.md`

## Location
`app/routers/vod_drm.py`

## Problem / Impact
spec §4.3 and §6.5-6.7 require POST /drm/keys/revoke and POST /drm/keys/{asset_id}/revoke-all (admin-only); neither exists; compromised keys cannot be invalidated without redeploying

## Fix
add admin endpoints with require_admin_session dependency; write to a ContentKeys DynamoDB table revocation record

## Notes
This gap was identified by the second-pass as-built review of VOD-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
