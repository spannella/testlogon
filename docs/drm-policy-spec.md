# DRM Policy Specification (VWD-004)

## DRM profile matrix

| Profile | Platform coverage | Packaging expectation |
|---|---|---|
| `widevine` | Chrome/Android | DASH or CMAF with Widevine signaling |
| `fairplay` | Safari/iOS/tvOS | HLS with FairPlay signaling |
| `playready` | Edge/Windows TV ecosystems | DASH/HLS with PlayReady signaling |
| `multi_drm` | Mixed fleets | CMAF packaging with profile-specific license paths |

## Entitlement claim contract

Contract version: `2026-03-drm-entitlement-v1`.

Required claims:

- `asset_id`
- `tenant_id`
- `session_id`
- `device_id`
- `profile`
- `issued_at_epoch`
- `expires_at_epoch`
- `key_id`
- `key_rotation_seconds`
- `per_content_key`
- `offline_allowed`

## Key policy

- `per_content_key=true` is default and recommended.
- `key_rotation_seconds` minimum is `60`.
- `expires_at_epoch` must be greater than `issued_at_epoch`.

## License API contract

- Request model: `DrmLicenseRequest`
  - Includes profile, content identity, device/session identity, and challenge payload.
- Response model: `DrmLicenseResponse`
  - Includes profile, key id, encoded license payload, expiry, and optional renewal URL.

## Source of truth

- Contract models: `app/contracts/drm_entitlement_contract.py`
- Validation service: `app/services/drm_entitlement_service.py`
