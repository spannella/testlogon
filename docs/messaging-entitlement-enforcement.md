# Messaging Entitlement Enforcement (CCE-041)

Messaging routes now enforce `internal_api_package` entitlements for the `messaging.*` namespace when commercialization is enabled.

## Covered operations

- `send_message` on `POST /messaging/conversations/{conversation_id}/messages`
- `upload_attachment` on `POST /messaging/conversations/{conversation_id}/messages/image`
- `download_attachment` on `GET /messaging/conversations/{conversation_id}/messages/{message_id}/attachment`
- `presence_heartbeat` on `POST /messaging/presence/heartbeat`
- `stream_events` on `GET /messaging/events/stream`

## Enforcement behavior

- Denials return HTTP 403 with deterministic payload:
  - `detail.code = internal_api_entitlement_denied`
  - `detail.reason` in `{no_entitlement, expired_entitlement, exhausted}`
- Successful consumes write usage events into `entitlement_usage_events` with the resolved internal meter.
- Usage events are queryable by `entitlement_id` via service helpers.

## Notes

- Enforcement is gated by `CATALOG_COMMERCIALIZATION_ENABLED`.
- Request idempotency for usage consumption is keyed by entitlement + meter + request id.
