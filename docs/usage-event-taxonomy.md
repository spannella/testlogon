# Usage Event Taxonomy

This document defines canonical usage event sources and idempotency-key patterns for metering.

## Goals
- Keep event source naming consistent across product surfaces.
- Provide deterministic idempotency key patterns for retry-safe writes.
- Preserve backward compatibility for existing file-manager usage sources.

## Canonical messaging + newsfeed sources

### Unit-like actions
- `messaging_send`
  - emitted when a message is successfully persisted/sent.
- `newsfeed_post`
  - emitted when a post is successfully created.

### Transfer actions
- `messaging_attachment_upload`
- `messaging_attachment_download`
- `newsfeed_attachment_upload`
- `newsfeed_attachment_download`

## Idempotency key patterns

Use `|`-delimited deterministic keys:

1. Messaging send
   - Pattern: `user_id|messaging_send|conversation_id|message_id`
   - Example: `u123|messaging_send|conv_42|msg_99`

2. Newsfeed post
   - Pattern: `user_id|newsfeed_post|post_id`
   - Example: `u123|newsfeed_post|post_abc`

3. Messaging/newsfeed attachment transfer
   - Pattern: `user_id|<source>|attachment_key|operation_id`
   - Example: `u123|messaging_attachment_upload|uploads/a.png|req-123`

## Backward compatibility

The metering service keeps all existing file-manager sources valid (e.g. `api_upload`, `download`, `shared_download`, `delete_soft`) while adding the new messaging/newsfeed sources above.

No existing event type/source combinations are removed by this taxonomy update.
