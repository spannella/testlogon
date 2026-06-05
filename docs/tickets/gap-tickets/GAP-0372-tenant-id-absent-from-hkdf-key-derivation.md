# GAP-0372: tenant_id absent from HKDF key derivation

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-010 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/VOD-010.md`); see also `docs/tickets/writeups/VOD-010.md`

## Location
`app/services/vod_drm_keys.py:57-78`

## Problem / Impact
two tenants sharing the same video_id (e.g. re-upload) receive identical AES-128 keys; cross-tenant key reuse is a confidentiality violation

## Fix
include tenant_id in HKDF salt or info string (salt = sha256(f"{tenant_id}|{asset_id}")) and require tenant_id query param in GET /v1/vod/drm/key/{key_id} validated against the entitlement token claim

## Notes
This gap was identified by the second-pass as-built review of VOD-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
