# Follow-ups: rich comments & messaging (backend-dependent)

This note records messaging/comment enhancements requested in the demo-review pass that are **blocked
on backend (or dev-environment) changes**, so they are not implemented client-side yet. The client work
that the backend already supports shipped in the same change set (see below).

## Shipped in this change set (backend-supported)
- **Delivered/Read receipts now persist & render.** `delivered_to_count` / `read_by_count` are persisted
  to Room (`MessageEntity` + `messages` schema **v9**, `MIGRATION_8_9`) and mapped through
  `Message.toEntity` / `MessageEntity.toDomain`, so the Sent → Delivered → Read indicator survives the
  Room render path (previously the counts were transient and every message showed "Sent"). The indicator
  is now check-glyph based (✓ / ✓✓ / ✓✓ in the primary tint).
- **Thread UX polish:** asymmetric chat bubbles, date dividers ("Today"/"Yesterday"), check-icon receipts.
- **Newsfeed comment replies** — `repliesSupported` enabled (backend accepts `parent_comment_id`); replies
  render threaded/indented.
- **Comment tipping** — `POST /posts/{id}/comments/{cid}/tip` wired (preset amounts; shows "Tipped $X.XX").
- **GIF / sticker comments** — composer GIF/sticker picker + `kind=gif|sticker` create fields wired,
  reusing the shared `/ui/stickers/*` catalog. (See dev-data caveat below.)

## Blocked on BACKEND changes
1. **Raw image-upload comments.** The comment create schema accepts `gif_url` / `sticker_id` only — there is
   no media-upload field for comments (unlike messages, which have an image attachment pipeline). "Image
   comments" therefore = GIF/sticker today. Needs a comment image-attachment endpoint to support arbitrary
   user images.
2. **Reactions on comments.** No comment-reaction endpoint exists (`/posts/{id}/reactions` is post-level
   only; comments expose a `tip` action but no emoji reactions). Needs a
   `/posts/{id}/comments/{cid}/reactions` endpoint.
3. **Video-comment parity.** `POST /ui/videos/{id}/comments` accepts `text` only — no `parent_comment_id`,
   `gif_url`, `sticker_id`, or tip endpoint. Video comments cannot reach newsfeed-comment parity (replies /
   GIF / stickers / tips) without backend support.
4. **True end-to-end encryption.** Only a feature flag exists (`messaging_encrypted_messages_enabled`) and
   a per-message `is_encrypted` field; there is no key-exchange / E2EE protocol. "Encrypted messages" is a
   server capability flag, not real client-side encryption.

## Blocked on DEV-DATA / environment (work on a real backend)
5. **GIF comments can't post on the dev backend.** The dev GIF provider returns **relative, non-`https`**
   mock URLs (`/mock/gifs/...`), but the comment API validates `gif_url` must be `https://`. So a real GIF
   send 422s on dev. The client code is correct for a production GIF provider (Tenor/Giphy https URLs).
6. **Sticker catalog empty after reset.** The dev backend's sticker collections are wiped on reset and
   require an admin seed (`/v1/admin/stickers/collections`), so the sticker tab shows an empty state on dev.

## Per-message scheduled send (client gap, backend ready)
- The backend supports per-message scheduling (`/messaging/conversations/{id}/messages/{id}/schedule` +
  `deliver_at`), but the client only schedules **mass** campaigns. A 1:1 "schedule send" composer option
  could be added client-side without backend work.
