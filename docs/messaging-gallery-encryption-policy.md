# Messaging gallery encrypted-content policy (MGL-010)

This policy defines what encrypted messages can expose through the conversation gallery endpoint (`GET /messaging/conversations/{conversation_id}/gallery`).

## Policy

For messages marked encrypted (`is_encrypted` or with an `encryption` envelope):

1. **Image/Video/File galleries**
   - Do **not** return encrypted messages in these tabs.
   - Rationale: avoid leaking attachment-like metadata from encrypted payload contexts.

2. **Links gallery**
   - Return an item **only if** a preview URL (`preview.url`) exists.
   - Expose only:
     - `message_id`
     - `conversation_id`
     - `sender_id`
     - `created_at`
     - `type=link`
     - `url=preview.url`
   - Redact/omit preview-enrichment fields (`title`, `thumbnail_url`) for encrypted messages.

3. **No preview metadata present**
   - If encrypted message has no `preview.url`, omit it from gallery responses entirely.

## Security goals

- Prevent plaintext or derived-content leakage through gallery payloads.
- Keep encrypted behavior deterministic across tabs.
- Preserve least-privilege metadata exposure.
