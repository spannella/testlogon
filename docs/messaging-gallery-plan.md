# Messaging conversation galleries plan

## Goal
Add conversation-scoped galleries that let users browse historical media shared in a DM or group conversation:

- Image gallery
- Video gallery
- File gallery
- Links gallery

Each gallery should show only artifacts sent inside the currently selected conversation.

## Scope
- Applies to both 1-on-1 and group conversations.
- Includes historical items from existing messages plus new messages moving forward.
- Excludes content the viewer is not authorized to access.

## UX proposal

### Entry points
- Add a **Media & Links** action in the conversation header.
- Open a right-side panel or dialog containing tabbed galleries:
  - Images
  - Videos
  - Files
  - Links

### Per-item metadata
Each gallery item should display:
- Sender
- Sent timestamp
- Quick preview (thumbnail/card when available)
- Open/download action
- **Jump to message** action

### Empty/error states
- Empty state per tab (e.g., "No images yet").
- Recoverable API error state with retry.

## Data and API design

### Why a dedicated API
Avoid forcing the client to load/scan entire message history for each tab in large conversations.

### Endpoint shape (proposed)
`GET /messaging/conversations/{conversation_id}/gallery`

Query params:
- `type`: `image | video | file | link`
- `cursor`: pagination cursor
- `limit`: page size

Response:
- `items[]` (normalized gallery item)
  - `message_id`
  - `conversation_id`
  - `sender_id`
  - `created_at`
  - `type`
  - `url`
  - `thumbnail_url` (optional)
  - `title` / `file_name` / `content_type` / `size` (type-dependent)
- `next_cursor`

## Gallery classification rules
Use deterministic mapping from message payloads:
- **Images**: `kind == image` with valid `image.url`
- **Videos**: `kind == video` with valid `file.url`
- **Files**: `kind == file` (optionally include `audio`)
- **Links**: message has `preview.url`

## Backend plan

### Phase 1: Functional delivery
- Add gallery read endpoint with auth/participant checks equivalent to message reads.
- Filter by conversation + type.
- Return reverse-chronological paginated results.
- Exclude revoked/deleted messages.

### Phase 2: Scale optimization
- Add a materialized index for gallery items keyed by conversation and timestamp.
- Populate index on message create/edit/delete/revoke events.
- Keep API contract unchanged while swapping implementation to indexed reads.

## Frontend plan

### Phase 1: Core UI
- Add gallery panel components and tabs.
- Add React Query hooks for gallery endpoint (infinite pagination).
- Implement base item renderers:
  - image/video grids
  - file/link lists

### Phase 2: UX polish
- Lazy-loading and virtualization for large galleries.
- Better video poster/thumb fallbacks.
- Better link cards from preview metadata.
- Deep-linking to message timeline for **Jump to message**.

## Security and privacy
- Enforce strict participant authorization.
- Respect conversation retention/deletion rules.
- Do not surface plaintext from encrypted messages unless decryptable in-client policy permits it.
- Handle expired signed URLs gracefully (show metadata, action disabled/retry flow).

## Edge cases
- Messages edited to remove/change attachments.
- Revoked/deleted messages disappearing from galleries.
- User leaves group mid-history (enforce existing visibility policy).
- Duplicate links or files sent multiple times (show each event in timeline order).

## Testing plan

### Backend
- Unit tests for type filters and classification.
- Pagination/cursor correctness tests.
- Auth tests (participant vs non-participant).
- Revoked/deleted retention behavior tests.

### Frontend
- Component tests per tab: loading/empty/error/content.
- Hook tests for pagination and cache behavior.
- Interaction tests for open/download/jump-to-message.

### Contract
- Add or extend messaging contract drift tests for new gallery schema and endpoint.

## Rollout
1. Feature flag: `messaging_gallery_enabled`.
2. Internal dogfood + QA against DM and group scenarios.
3. Staged rollout (small cohort to full rollout).
4. Monitor endpoint latency, error rate, and query volume.

## Suggested delivery sequencing
- **Sprint 1**: API contract + backend phase 1 + baseline gallery UI.
- **Sprint 2**: polish features, jump-to-message, stronger tests.
- **Sprint 3**: scale index implementation + operational dashboards.
