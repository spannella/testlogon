# Messaging WebRTC TURN Credentials Policy

## Purpose
Define TURN credential issuance policy for direct 1:1 WebRTC calls.

## Eligibility checks
TURN credentials are issued only when all conditions hold:
- TURN issuance feature is enabled (`MESSAGING_WEBRTC_TURN_ENABLED=true`).
- TURN configuration exists (`MESSAGING_WEBRTC_TURN_URLS`, `MESSAGING_WEBRTC_TURN_SECRET`).
- The call session exists.
- Requesting user is a participant (`caller_user_id` or `callee_user_id`).
- Call state is one of: `invited`, `accepted`, `connected`.

## TTL policy
- Default credential TTL: **600 seconds** (`MESSAGING_WEBRTC_TURN_TTL_SECONDS`).
- Credential username format: `<expires_at_unix>:<actor_user_id>`.
- Credential value: Base64(HMAC-SHA1(secret, username)).

## ICE server response contract
Service returns:
- `ttl_seconds`
- `expires_at`
- `ice_servers[]` entries with:
  - `urls[]`
  - `username`
  - `credential`

## Error contract
- `feature_disabled`
- `turn_not_configured`
- `call_not_found`
- `forbidden`
- `invalid_state`

## Observability
Credential issuance emits metrics with outcome/reason labels via
`record_turn_credential_issue(outcome, reason)`.
