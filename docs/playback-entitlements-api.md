# Playback Entitlements API

This document describes the playback entitlement endpoints under `/v1/playback`,
including request/response shapes and deterministic error codes.

## Issue entitlement

`POST /v1/playback/entitlements/issue`

### Request body

```json
{
  "tenant_id": "tenant-1",
  "asset_id": "asset-1",
  "session_id": "session-1",
  "device_id": "device-1",
  "profile": "widevine",
  "audience": "playback",
  "ttl_seconds": 120
}
```

### Success response

```json
{
  "entitlement": {
    "token": "<signed-token>",
    "expires_at_epoch": 1700000120,
    "audience": "playback",
    "ttl_seconds": 120,
    "jti": "<token-id>"
  },
  "issued_for": "actor-sub"
}
```

### Common issue errors

- `invalid_ttl`
- `ttl_exceeds_max`
- `invalid_audience`
- `invalid_claims`
- `secret_not_configured`

## Revoke entitlement

`POST /v1/playback/entitlements/revoke`

You may revoke by:
- token id (`jti`), or
- tenant-scoped session (`tenant_id` + `session_id`).

### Request body (session revocation)

```json
{
  "tenant_id": "tenant-1",
  "session_id": "session-1",
  "expires_at_epoch": 4100000100
}
```

### Common revoke errors

- `invalid_revocation_request`
- `invalid_revocation_expiry`

## Protected playback check

`GET /v1/playback/protected/ping`

Requires `Authorization: Bearer <token>`.

### Success response

```json
{
  "ok": true,
  "claims": {
    "tenant_id": "tenant-1",
    "asset_id": "asset-1",
    "session_id": "session-1",
    "device_id": "device-1",
    "profile": "widevine",
    "aud": "playback",
    "iat": 1700000000,
    "exp": 1700000120,
    "jti": "<token-id>"
  }
}
```

### Common validate errors

- `missing_bearer`
- `invalid_format`
- `token_too_large`
- `invalid_header`
- `invalid_header_alg`
- `invalid_header_typ`
- `invalid_signature`
- `invalid_payload`
- `missing_claims`
- `invalid_claim_type`
- `invalid_claims`
- `invalid_timestamp`
- `invalid_audience`
- `token_not_yet_valid`
- `token_expired`
- `token_revoked`
- `session_revoked`
- `replay_detected`

## Notes

- Protected routes are validated in middleware; validated claims are reused by the route handler to avoid double-validation.
- Error payloads are returned as `{ \"detail\": { \"code\": \"...\", \"message\": \"...\" } }`.
