---
id: AND-135
title: GIFs, stickers, custom emoji
milestone: M3
epic: E19
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on:
  - AND-124
blocks: []
---

# AND-135 — GIFs, stickers, custom emoji

## 1. Overview & Goal

Extend the message composer delivered in AND-124 ("Send text message") so users can
compose, send, and render three new rich message content types: animated **GIFs**,
**stickers** (server-hosted sticker-collection images), and **custom emoji** (workspace-scoped
named images rendered inline). The ticket covers the picker UI surfaced from the composer,
the wire format for the two new send endpoints
(`POST /messaging/conversations/{conversation_id}/messages/gif` and
`POST /messaging/conversations/{conversation_id}/messages/sticker` — CORRECTED: the backlog's
`/messages/gif`, `/messages/sticker` shorthand does not match the actual conversation-scoped
paths verified in the OpenAPI index), the custom-emoji catalog fetch + inline substitution
path, and rendering of all three types in the message list. (NOTE: the backend calls the
sticker grouping a "collection", not a "pack"; this spec uses "collection" for wire fields and
keeps "pack" only as informal UI language.)

Goal: a user can open a unified media picker from the composer, search/browse GIFs, browse
sticker packs, and insert custom emoji into outgoing text; each type sends to the backend
and renders correctly (animated where applicable) both optimistically and after server
acknowledgement. Out of scope: photo/video/file attachments (separate ticket), emoji
*reactions* (E20), and authoring/uploading new custom emoji (admin web only).

The deliverable lives in `feature-chat` and consumes shared infrastructure from
`core-network`, `core-model`, `core-data`, and `core-ui`. GIF/sticker/custom-emoji image
loading reuses Coil with animated-image decoders.

## 2. Context & References

- Composer, optimistic-send pipeline, and `MessageRepository` are defined by **AND-124**
  (hard dependency). This ticket adds new `OutgoingMessage` subtypes and new send calls; it
  must reuse AND-124's optimistic insert → ack reconciliation → failure-retry state machine
  rather than introducing a parallel one.
- Message-list rendering scaffold and `MessageItem` composable come from the conversation
  screen (E18). New content types add new branches to the existing renderer.
- Web reference (CORRECTED paths): GIF/sticker send live in
  `src/api/endpoints/messaging.ts` (`sendGifMessage`, `sendStickerMessage`); GIF
  search/trending and sticker collections live in `src/api/endpoints/stickers.ts`;
  custom-emoji catalog + resolve live in `src/api/endpoints/customEmojis.ts`. DTO shapes are
  in `src/api/types.ts`. NOTE: the backend message model is NOT a discriminated `content`
  union — `MessageOut` is a flat object with a `kind` enum discriminator and per-kind flat
  fields (`gif_url`, `sticker_url`, `text`, …). Confirm exact field names against
  `/openapi.json` before freezing the Moshi models.
- Auth/transport (CORRECTED/CLARIFIED): the web client sends the CSRF token from the
  `ui_csrf` cookie as the `X-CSRF-Token` header AND a `Authorization: Bearer <accessToken>`
  header (see `src/api/client.ts`); it is not cookie-session-only. On 401 it performs a
  single-flight `POST /ui/session/refresh` and retries once. The Android port must decide
  whether it mirrors the Bearer-token transport or a pure cookie session (see OQ-5);
  `core-network` provides the cookie jar / CSRF / single-flight refresh.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, Coil (animated decoders), Paging 3 (GIF search results), Room 2.6 +
  DataStore. minSdk 24, compile/targetSdk 35, JDK 17.

## 3. Functional Requirements

FR-1 — **Picker entry point.** The composer (AND-124) gains a media-picker affordance
(IconButton, "Add media", `R.string.composer_add_media`). Tapping it opens a
`ModalBottomSheet` with three tabs: **GIF**, **Stickers**, **Emoji**. The active tab and
search text survive recomposition and configuration change.

FR-2 — **GIF tab.** Shows a search field plus a staggered/grid result list. Empty query
shows a trending/default feed. Results paginate (Paging 3) as the user scrolls. Selecting a
GIF immediately closes the sheet and sends a GIF message (no separate "send" step).

FR-3 — **Sticker tab.** Shows the user's available sticker packs (horizontal pack selector)
and a grid of stickers for the selected pack. Selecting a sticker closes the sheet and sends
a sticker message.

FR-4 — **Custom-emoji tab.** Shows the workspace custom-emoji catalog as a searchable grid.
Selecting a custom emoji inserts its `:shortcode:` token into the composer text field at the
caret (it does **not** send by itself); the text message is then sent normally via AND-124's
text path, and `:shortcode:` tokens are rendered inline as images in the message list.

FR-5 — **Optimistic send.** GIF and sticker sends insert an optimistic message bubble
immediately (status = `SENDING`), reconcile on the server ack (status = `SENT`, real id),
and on failure flip to `FAILED` with a retry affordance — identical lifecycle to AND-124
text sends.

FR-6 — **Rendering.** The message list renders: GIF messages as an auto-playing animated
image (with poster/preview while loading); sticker messages as a fixed-size (max 128dp)
image; text messages containing `:shortcode:` tokens with each known shortcode replaced by
its inline custom-emoji image (≈ line-height sized), unknown shortcodes left as literal
text.

FR-7 — **Catalog caching.** The custom-emoji catalog and sticker-pack metadata are cached
in Room and served stale-first; a background refresh updates them. The catalog is needed
both for the picker and for rendering inbound messages, so it must be available even when
the picker has never been opened.

## 4. Technical Design

### 4.1 Module placement
All new code lands in `feature-chat`. Domain models in `core-model`; Retrofit service +
Moshi adapters in `core-network`; Room entities/DAO and repositories in `core-data`; the
inline-emoji rendering helper and animated-image Coil setup in `core-ui`.

### 4.2 Domain model (core-model)
CORRECTED: field names below now track the verified `MessageOut` / `StickerOut` /
`CustomEmojiOut` schemas. `MessageOut` has NO nested `content` object and NO `preview_url`,
`provider_id`, sticker `name`, or `pack_id` fields; GIF/sticker data are flat columns keyed
off the `kind` enum discriminator.
```kotlin
sealed interface MessageContent {
    data class Text(val body: String) : MessageContent          // existing (AND-124)
    // From MessageOut flat fields when kind == "gif":
    data class Gif(val gifUrl: String, val gifAltText: String?,
                   val gifWidth: Int, val gifHeight: Int,
                   val gifProvider: String?) : MessageContent     // no preview_url / provider_id on the wire
    // From MessageOut flat fields when kind == "sticker":
    data class Sticker(val stickerId: String, val stickerCollectionId: String?,
                       val stickerUrl: String, val stickerAltText: String?) : MessageContent
}

data class CustomEmoji(
    val emojiId: String,
    val shortcode: String,   // without surrounding colons
    val name: String,
    val imageUrl: String,    // wire field is `image_url`, NOT `url`
    val contentType: String, // e.g. image/png | image/gif | image/webp — animation is inferred from this; there is NO `animated` boolean
    val ownerScope: String,  // "personal" | "global"
)

data class StickerCollection {              // backend term is "collection", not "pack"
    val collectionId: String,
    val name: String,
    val thumbnailUrl: String?,              // wire field is `thumbnail_url`, NOT `cover_url`
    val description: String,
    val stickerCount: Int,
    val stickers: List<Sticker>,
}
```
`Text` rendering is unchanged on the wire; custom emoji travels inside the text body as
`:shortcode:` and is resolved client-side. NOTE (verified against `src/utils/emoji.ts`): the
web client replaces *built-in Unicode* shortcodes locally before sending (so the backend only
sees the resolved Unicode + remaining *custom* shortcodes); only custom shortcodes survive on
the wire and are resolved for rendering. `animated` is derived from `content_type`.

### 4.3 Outgoing message types (feature-chat / core-data)
Extend AND-124's `OutgoingMessage`:
```kotlin
sealed interface OutgoingMessage {
    val localId: String        // client UUID for optimistic reconciliation
    data class Text(...) : OutgoingMessage
    data class Gif(override val localId: String, val conversationId: String,
                   val gif: GifSendPayload) : OutgoingMessage
    data class Sticker(override val localId: String, val conversationId: String,
                       val stickerId: String, val stickerCollectionId: String) : OutgoingMessage  // CORRECTED: collection, not pack
}
```
CORRECTED — reconciliation key: the send request bodies (`SendGifMessageIn`,
`SendStickerMessageIn`) do **not** accept a `client_id`/idempotency key, and `MessageOut`
does **not** echo one back. The "match the ack's `client_id`" design from earlier drafts is
**not implementable against this backend**. Reconciliation must instead correlate the
optimistic `localId` row with the `MessageOut` returned *synchronously* by the POST (the call
returns `201:MessageOut`), swapping in `message_id` + `created_at`. (Conversation-stream
pushes are de-duplicated by `message_id`.) See OQ-4.

### 4.4 Repository (core-data)
```kotlin
interface MediaMessageRepository {
    suspend fun sendGif(conversationId: String, gif: GifSendPayload): ApiResult<Message>
    suspend fun sendSticker(conversationId: String, stickerCollectionId: String,
                            stickerId: String): ApiResult<Message>     // CORRECTED: collection, not pack

    // CORRECTED: backend GIF search is NOT cursor-paginated — GET /ui/stickers/gifs/search
    // takes only q + limit (max 50) and returns a bare array; trending is a separate
    // GET /ui/stickers/gifs/trending. A single-page list (or a synthetic single-page
    // PagingSource) is the honest model; there is no next_cursor. See §5.3.
    suspend fun gifSearch(query: String, limit: Int = 20): ApiResult<List<GifResult>>
    suspend fun trendingGifs(limit: Int = 20): ApiResult<List<GifResult>>
    suspend fun stickerCollections(): ApiResult<List<StickerCollection>>  // stale-first
    fun customEmoji(): Flow<List<CustomEmoji>>                    // Room-backed, stale-first
    suspend fun refreshCustomEmoji(): ApiResult<Unit>
    suspend fun resolveShortcodes(codes: List<String>): ApiResult<Map<String,String>>  // GET /ui/emojis/custom/resolve
}
```
`sendGif`/`sendSticker` perform optimistic insert via the shared `MessageRepository` (insert
local row, status `SENDING`), POST, then reconcile the `localId` row against the
`201:MessageOut` body returned by the POST (swap in `message_id`/`created_at`). They are
**not** retried automatically (non-idempotent POST with no server idempotency key); failure
surfaces a manual retry. CORRECTED: retry CANNOT reuse a `client_id` for server-side dedup —
the backend exposes none for these endpoints (OQ-4); a manual retry re-POSTs and risks a
duplicate unless the backend is changed.

### 4.5 ViewModel (feature-chat)
The existing `ConversationViewModel` exposes `StateFlow<ConversationUiState>`. Add a nested
picker state plus actions:
```kotlin
data class MediaPickerState(
    val visible: Boolean = false,
    val tab: MediaTab = MediaTab.GIF,
    val gifQuery: String = "",
    val selectedCollectionId: String? = null,    // CORRECTED: collection, not pack
    val collections: Loadable<List<StickerCollection>> = Loadable.Idle,
    val gifResults: Loadable<List<GifResult>> = Loadable.Idle,  // single-page (no cursor)
    val emoji: List<CustomEmoji> = emptyList(),
)
enum class MediaTab { GIF, STICKERS, EMOJI }

fun openMediaPicker(); fun closeMediaPicker(); fun selectTab(tab: MediaTab)
fun onGifQueryChange(q: String); fun onGifSelected(gif: GifResult)
fun onStickerSelected(collectionId: String, stickerId: String)
fun onCustomEmojiSelected(shortcode: String)   // inserts ":$shortcode:" at caret
```
GIF search debounces the query (~300 ms) and `flatMapLatest` into `gifSearch`/`trendingGifs`
(empty query ⇒ trending). CORRECTED: because the backend has no cursor, results are a single
fixed page (limit ≤ 50), so a `Flow<PagingData>` is over-engineering — model the GIF tab as a
plain `Loadable<List<GifResult>>` with its own loading/empty/error state. (If a Paging-3
surface is still desired for ergonomics, use a single-page `PagingSource` that returns
`nextKey = null`.)

### 4.6 Compose UI (feature-chat)
- `MediaPickerSheet(state, onAction)` — `ModalBottomSheet` hosting a `TabRow` + per-tab pane.
- `GifGrid(items: List<GifResult>, onSelect)` — `LazyVerticalStaggeredGrid`, Coil
  `AsyncImage` with the GIF decoder, loading/empty/error states (single page; no append
  footer — see §4.5).
- `StickerPane(collections, selectedCollectionId, onCollectionSelect, onSelect)`.
- `EmojiGrid(emoji, query, onSelect)` — `LazyVerticalGrid`, fixed cell size.
- Message rendering additions in `MessageItem`: `GifBubble`, `StickerBubble`, and
  `EmojiText` (an `InlineTextContent`-based composable that substitutes `:shortcode:` →
  inline image and the cached catalog). CORRECTED: use the regex that matches the web
  reference (`src/utils/emoji.ts`): `:([a-z0-9_]{2,32}):` (case-insensitive). The earlier
  `:([a-z0-9_+-]+):` is wrong — it allows `+`/`-` and any length, which the web
  custom-shortcode matcher does not.

### 4.7 Image loading
Register Coil decoders in the application `ImageLoader` (core-ui): `ImageDecoderDecoder`
(API 28+) / `GifDecoder` (API 24–27) for animated GIFs and animated WebP custom emoji.
Stickers and static emoji use the default decoder. Inline emoji are loaded into
`InlineTextContent` slots sized to font line height.

## 5. API Contract

All paths are relative to the dev base `http://18.222.237.167:8000`. **The shapes below are
VERIFIED against the OpenAPI spec and the web reference client** (sources cited in §16). All
requests carry the `X-CSRF-Token` header (from the `ui_csrf` cookie) and the
`Authorization: Bearer` header used by the web client (see §2 / OQ-5).

### 5.1 Send GIF — `POST /messaging/conversations/{conversation_id}/messages/gif`
(CORRECTED path; `conversation_id` is a path param, not a body field.)
Request body `SendGifMessageIn` (verified):
```json
{ "gif_url": "https://media…/x.gif", "gif_alt_text": "a waving cat",
  "gif_width": 480, "gif_height": 270, "reply_to_message_id": null }
```
Only `gif_url` is required (maxLength 2048); `gif_width`/`gif_height` default 0 (max 4096),
`gif_alt_text` defaults "" (maxLength 256). There is **no** `conversation_id`, `client_id`,
`preview_url`, `provider`, or `provider_id` in the request, and no nested `gif` object.
Response `201: MessageOut` (verified) — flat object, key fields:
```json
{ "message_id": "msg_789", "conversation_id": "conv_123", "sender_id": "u_1",
  "kind": "gif", "gif_url": "…", "gif_alt_text": "…", "gif_width": 480,
  "gif_height": 270, "gif_provider": "tenor", "created_at": 1749124800 }
```
NOTE: discriminator is `kind` (enum incl. `gif`,`sticker`,`text`), id field is `message_id`
(not `id`), `created_at` is an **integer epoch** (not ISO-8601), and there is NO `client_id`
echoed back. Validation errors return `422: HTTPValidationError`.

### 5.2 Send sticker — `POST /messaging/conversations/{conversation_id}/messages/sticker`
Request body `SendStickerMessageIn` (verified):
`{ "sticker_id": "st_42", "sticker_collection_id": "col_1", "reply_to_message_id": null }`
Both `sticker_id` and `sticker_collection_id` are required (CORRECTED: field is
`sticker_collection_id`, not `pack_id`; no `conversation_id`/`client_id` in body).
Response `201: MessageOut`: `{ "message_id": "msg_790", "kind": "sticker",
  "sticker_id": "st_42", "sticker_collection_id": "col_1", "sticker_url": "…",
  "sticker_alt_text": "wave", "created_at": 1749124800, … }` — flat fields, NO sticker
`name` (use `sticker_alt_text`), NO nested `content`.

### 5.3 GIF search — `GET /ui/stickers/gifs/search?q={q}&limit={n}`  (CORRECTED path)
Plus trending: `GET /ui/stickers/gifs/trending?limit={n}` (used when `q` is empty).
Params: `q` (default ""), `limit` (default 20, **max 50**). CORRECTED: there is **no
`cursor` param and no pagination** — the response is a **bare JSON array** of
`GifSearchResult`, not an object with `results`/`next_cursor`:
```json
[ { "id": "abc123", "url": "…", "alt_text": "a waving cat",
    "width": 480, "height": 270 } ]
```
`GifSearchResult` has NO `preview_url` and NO `provider`. These idempotent GETs are eligible
for the bounded backoff retry policy.

### 5.4 Sticker collections — `GET /ui/stickers/collections`  (CORRECTED path)
Response `StickerCollectionListOut`: `{ "collections": [ { "collection_id": "col_1",
  "name": "Animals", "thumbnail_url": "…", "description": "", "sticker_count": 12,
  "is_active": true, "created_at": 1749124800, "stickers": [ { "sticker_id": "st_42",
  "image_url": "…", "alt_text": "wave", "width": 256, "height": 256, "sort_order": 0 } ] } ] }`.
Stickers for one collection can also be fetched lazily via
`GET /ui/stickers/collections/{collection_id}/stickers` → `StickerListOut` (`{ "stickers": [...] }`).
CORRECTED: collection cover field is `thumbnail_url` (not `cover_url`); sticker image field is
`image_url` (not `url`); a sticker has NO `name` (use `alt_text`). Optional: a user's favorite
collections are at `GET /ui/stickers/favorites` (`StickerCollectionListOut`).

### 5.5 Custom-emoji catalog — `GET /ui/emojis/custom`  (CORRECTED path)
Response `CustomEmojiListOut`: `{ "emojis": [ { "emoji_id": "e1", "shortcode": "partyparrot",
  "name": "Party Parrot", "image_url": "…", "content_type": "image/gif",
  "owner_scope": "global", "created_by": "u_1", "alt_text": "", "category": "Uncategorized",
  "created_at": 1749124800, "file_size_bytes": 1024 } ], "global_count": 1,
  "personal_count": 0 }`. CORRECTED: wrapper field is `emojis` (not `emoji`); per-emoji image
field is `image_url` (not `url`); there is **no `animated` boolean** — infer animation from
`content_type` (`image/gif`, `image/webp`). For inbound rendering the web client instead uses
`GET /ui/emojis/custom/resolve?codes=a,b,c` → `ResolveShortcodesOut`
(`{ "resolved": { "<shortcode>": "<image_url>" } }`); the Android port MAY use either the full
catalog (cached, single source of truth) or this resolve endpoint (see §6 / OQ-3).

### 5.6 Retrofit service (core-network)
```kotlin
interface MediaMessageApi {
    @POST("messaging/conversations/{cid}/messages/gif")
    suspend fun sendGif(@Path("cid") cid: String, @Body b: SendGifRequest): Response<MessageDto>
    @POST("messaging/conversations/{cid}/messages/sticker")
    suspend fun sendSticker(@Path("cid") cid: String, @Body b: SendStickerRequest): Response<MessageDto>
    @GET("ui/stickers/gifs/search")  suspend fun searchGifs(
        @Query("q") q: String, @Query("limit") limit: Int = 20): Response<List<GifSearchResult>>
    @GET("ui/stickers/gifs/trending") suspend fun trendingGifs(
        @Query("limit") limit: Int = 20): Response<List<GifSearchResult>>
    @GET("ui/stickers/collections")  suspend fun stickerCollections(): Response<StickerCollectionListResponse>
    @GET("ui/stickers/collections/{cid}/stickers")
    suspend fun collectionStickers(@Path("cid") cid: String): Response<StickerListResponse>
    @GET("ui/emojis/custom")         suspend fun customEmoji(): Response<CustomEmojiListResponse>
    @GET("ui/emojis/custom/resolve") suspend fun resolveShortcodes(
        @Query("codes") codes: String): Response<ResolveShortcodesResponse>
}
```
`searchGifs`/`trendingGifs` deserialize a **bare array** (note the `List<…>` body type — no
wrapper). Responses are wrapped into `ApiResult<T>` by the shared `core-network` call adapter,
which also maps the FastAPI `detail` field (string | `[{msg}]` | `{code,…}`).

## 6. Data & State Management

- **Room (core-data):** `custom_emoji` table (`emoji_id` PK or `shortcode` unique, `image_url`,
  `content_type` (animation inferred — there is no `animated` boolean on the wire),
  `owner_scope`, `fetched_at`) and `sticker_collection` / `sticker` tables (keyed by
  `collection_id` / `sticker_id`, `fetched_at`). CORRECTED field names: `image_url` (not
  `url`), `collection`/`collection_id` (not `pack`/`pack_id`).
  DAOs expose `Flow` reads; repository writes via upsert + a `deleteStale` pass after a
  successful refresh. The custom-emoji `Flow` is the single source of truth for both the
  picker grid and inline-render substitution.
- **Stale-first policy:** on first observe, emit cached rows immediately, then trigger a
  network refresh; a refresh timestamp in DataStore (`emoji_catalog_refreshed_at`) gates
  refresh frequency (e.g., max once / 6 h unless forced).
- **GIF search** is **not** persisted and (CORRECTED) **not** cursor-paginated — the backend
  returns a single bounded array (limit ≤ 50), so neither a `RemoteMediator` nor a
  cursor-based `PagingSource` is warranted; an in-memory single-page list per query is enough
  (results are ephemeral provider data).
- **Optimistic rows:** GIF/sticker optimistic messages reuse AND-124's local message table
  with `status` (`SENDING|SENT|FAILED`) and a client-only `localId`. CORRECTED:
  reconciliation matches the optimistic `localId` row to the `MessageOut` body returned
  synchronously by the POST and swaps in `message_id` + `created_at`; there is no `client_id`
  on the wire to match against (any stream-pushed copy is de-duped by `message_id`).
- **UiState:** `ConversationUiState` already drives the screen; `MediaPickerState` is nested
  inside it (or a sibling `StateFlow`) and exposed via the existing `StateFlow<UiState>`
  contract. No `LiveData`.

## 7. Error Handling & Resilience

- **Unreliable dev host:** apply the 20 s OkHttp timeout. Only the idempotent GETs
  (`/ui/stickers/gifs/search`, `/ui/stickers/gifs/trending`, `/ui/stickers/collections`,
  `/ui/emojis/custom`, `/ui/emojis/custom/resolve`) use bounded exponential backoff (≤3
  attempts, jittered). The two POST sends are **never** auto-retried (duplicate-message
  risk); failures become `FAILED` bubbles with a manual "Tap to retry". CORRECTED: the retry
  CANNOT pass a `client_id`/idempotency key for server-side dedup — the send endpoints accept
  none (OQ-4), so a retry that actually reached the server before failing can produce a
  duplicate message until the backend gains an idempotency mechanism.
- **GIF search errors:** Paging surfaces `LoadState.Error`; the grid shows an inline retry
  footer. Empty results show an empty-state, not an error.
- **Catalog fetch failure:** if the network refresh fails but cache exists, the UI stays on
  stale data silently (log only). If no cache and fetch fails, the Emoji/Sticker tab shows a
  retry empty-state; inbound `:shortcode:` tokens render as literal text (graceful).
- **401:** handled transparently by the shared interceptor (single-flight
  `POST /ui/session/refresh` then retry once); no per-call handling here.
- **Unknown shortcode / broken image URL:** Coil error fallback → literal text for emoji,
  a neutral placeholder box for GIF/sticker; never crash the list.

## 8. Security & Privacy

- No new credential surface; auth is the existing session. CORRECTED/CLARIFIED: the web
  client (`src/api/client.ts`) sends `X-CSRF-Token` (from the `ui_csrf` cookie) on every
  request AND a `Authorization: Bearer <accessToken>` header; the OpenAPI lists `authorization`
  + `X-SESSION-ID` params on the send endpoints. The Android port reuses `core-network`'s
  shared auth; whether it uses Bearer + cookie or cookie-only is OQ-5. The two POST sends
  require CSRF; GETs include it harmlessly.
- The dev backend is plaintext HTTP; production must be HTTPS. Image URLs returned by the
  GIF provider proxy and sticker/emoji catalog may be third-party (e.g., Tenor CDN). Load
  them through Coil over the app's OkHttp client; do **not** forward session cookies to
  third-party image hosts (Coil uses a separate image-request client without the cookie
  jar). Confirm the `ImageLoader` `OkHttpClient` does not attach the auth cookie jar.
- Custom-emoji/sticker URLs are workspace-scoped content; treat catalog data as
  authenticated content and clear the Room cache on logout (hook into the existing
  session-clear path).
- No PII is logged; `client_id` is a random UUID, not user-identifying.

## 9. Accessibility & i18n

- All picker controls expose `contentDescription`/`semantics`: GIF cells
  ("GIF, <gif_alt_text>"), stickers ("Sticker, <sticker_alt_text>" — CORRECTED: there is no
  sticker `name` field; use `alt_text`), custom emoji (":<shortcode>:"). Sent GIF/sticker
  bubbles carry a `contentDescription` sourced from `gif_alt_text` / `sticker_alt_text`.
- Inline custom emoji in `EmojiText` set `InlineTextContent` alt text so screen readers
  announce `:shortcode:` rather than skipping the glyph.
- Tabs are reachable and labeled; picker is dismissible via back gesture and TalkBack.
- Respect reduced-motion: when the system animator/transition scale is 0, render GIFs as a
  static first frame (do not auto-animate). CORRECTED: there is no `preview_url` on the wire,
  so the static frame must be derived from `gif_url` itself (Coil: load without starting the
  animation / freeze on first frame). Touch targets ≥ 48dp.
- All user-facing strings (`composer_add_media`, tab labels, empty/error/retry states) live
  in `strings.xml`; no hardcoded text. Grids are RTL-aware via Compose defaults.

## 10. Telemetry & Logging

- Analytics events (via the app's existing analytics abstraction): `media_picker_opened`
  `{tab}`, `gif_searched` `{query_len, result_count}`, `gif_sent` `{provider}`,
  `sticker_sent` `{collection_id}` (CORRECTED from `pack_id`), `custom_emoji_inserted` `{shortcode}`, and
  `media_send_failed` `{type, error_code}`. Do not log raw GIF search queries' full text
  (privacy) — log length only.
- Logging: `Timber` (or the project logger) at DEBUG for catalog refresh outcomes and
  optimistic reconciliation; WARN for catalog stale-fallback; ERROR for send failures with
  the mapped `detail` code. No image bytes or URLs with tokens logged.

## 11. Testing Strategy

- **Unit (core-data / feature-chat):**
  - `MediaMessageRepository.sendGif/sendSticker` optimistic-insert → reconciliation against
    the POST's `MessageOut` body (CORRECTED: match by `localId`→`message_id`, not by
    `client_id`) and failure → `FAILED` paths, using fake `MediaMessageApi`.
  - Manual retry re-POSTs (CORRECTED: no `client_id`/idempotency key available — assert the
    duplicate-risk behavior and any client-side guard).
  - Stale-first catalog: emits cache then refreshed values; refresh-failure keeps cache.
  - GIF search single-page load + empty/error mapping (CORRECTED: no cursor paging).
  - `ApiResult` mapping of FastAPI `detail` (all three shapes) for the new calls.
- **ViewModel:** picker state transitions (open/close/tab/query debounce), `onGifSelected`
  triggers send + closes sheet, `onCustomEmojiSelected` inserts `:shortcode:` at caret.
  Use `core-testing` `MainDispatcherRule` + Turbine on `StateFlow`.
- **Inline-emoji unit:** the `:([a-z0-9_]{2,32}):` substitution helper (CORRECTED regex,
  matching `src/utils/emoji.ts`) — known→inline image, unknown→literal, mixed text, adjacent
  tokens, malformed colons, and a single-char/over-32-char token that must NOT match.
- **Compose UI tests:** picker opens with three tabs; selecting a GIF/sticker fires the
  callback; GIF/sticker bubbles render; semantics/contentDescriptions present.
- **Acceptance (instrumented, against a stubbed `MediaMessageApi`):** send + render each of
  the three types end-to-end, asserting optimistic bubble then reconciled state.

## 12. Dependencies & Sequencing

- **Hard dep: AND-124** (composer + optimistic send + reconciliation). This ticket extends
  that pipeline; it must not start before AND-124's `MessageRepository`/`OutgoingMessage`
  abstractions are merged.
- Transitively depends on the conversation-screen/message-list scaffold (E18) for
  `MessageItem` rendering branches and on `core-network` (cookie jar, CSRF, `ApiResult`
  adapter, retry policy) and Coil setup in `core-ui`.
- Blocks: none recorded in the backlog. Emoji *reactions* (E20) may later reuse the
  custom-emoji catalog, but no current ticket is gated on this one.
- Sequencing within the ticket: (1) Moshi models + Retrofit service verified against
  `/openapi.json`; (2) repository + Room caching; (3) ViewModel + picker UI; (4) message
  rendering branches; (5) tests.

## 13. Risks & Open Questions

- **OQ-1:** RESOLVED. Discriminator is `kind` (not `type`/`content_type`); id is
  `message_id`; `created_at` is an integer epoch; GIF/sticker fields are flat on `MessageOut`.
  §5 shapes are now verified against `/openapi.json` (see §16). No remaining ambiguity for the
  fields this ticket uses.
- **OQ-2:** RESOLVED (mostly). GIF search IS a first-party backend proxy at
  `GET /ui/stickers/gifs/search` (description: "Search GIFs via the configured (mock)
  provider") + `…/trending`; no client-side provider key is needed. Open sub-question: the
  dev provider is a **mock**; production provider identity / attribution requirements are
  unverified (see §16 Open assumptions).
- **OQ-3:** Custom-emoji transport — built-in Unicode shortcodes are replaced client-side
  before send and only *custom* `:shortcode:` tokens travel in the text body (verified in
  `src/utils/emoji.ts`); there is no structured custom-emoji content type. So
  `onCustomEmojiSelected` edits text (does not send). Inbound resolution can use either the
  cached `/ui/emojis/custom` catalog or `GET /ui/emojis/custom/resolve` (web uses resolve).
- **OQ-4:** RESOLVED (negatively). The POST send bodies accept NO `client_id`/idempotency key
  and `MessageOut` echoes none, so safe manual retry via server-side dedup is **not possible**
  today. Recommend a backend follow-up to add an idempotency key; until then a retry can
  duplicate. (See §16 Corrections.)
- **OQ-5 (NEW):** Auth transport — the web client sends BOTH a session cookie/CSRF and an
  `Authorization: Bearer` token; the OpenAPI send endpoints list `authorization` + `X-SESSION-ID`
  params. Confirm which scheme the Android `core-network` adopts (Bearer + cookie vs
  cookie-only) so these calls authenticate identically to AND-124.
- **Risk:** Animated GIF/WebP memory pressure on minSdk 24 (`GifDecoder` path) in long
  lists — mitigate by pausing off-screen animations and capping decoded size.
- **Risk:** Third-party image hosts over plaintext HTTP / cookie leakage — mitigated in §8
  (separate image OkHttp client).

## 14. Acceptance Criteria

- AC-1: From the composer, a media picker opens with GIF, Stickers, and Emoji tabs; state
  survives rotation.
- AC-2: **Send + render GIF** — selecting a GIF sends via
  `POST /messaging/conversations/{conversation_id}/messages/gif` (CORRECTED path), shows an
  optimistic bubble, reconciles against the returned `MessageOut`, and renders as an animated
  image (static first frame under reduced-motion). (Backlog acceptance: "Send + render each
  type.")
- AC-3: **Send + render sticker** — selecting a sticker sends via
  `POST /messaging/conversations/{conversation_id}/messages/sticker` (CORRECTED path) with
  `sticker_id` + `sticker_collection_id`, optimistic → reconciled, renders at ≤128dp
  (verified: web fixes the sticker bubble at 128×128).
- AC-4: **Send + render custom emoji** — selecting a custom emoji inserts `:shortcode:` into
  the composer; the sent text message renders that shortcode as an inline image; unknown
  shortcodes render as literal text.
- AC-5: A failed GIF or sticker send shows a `FAILED` bubble with a working manual retry.
  (CORRECTED: the backend has no `client_id`/idempotency key, so retry re-POSTs without dedup;
  acceptance is "retry succeeds and the failed bubble reconciles," with the duplicate-risk
  caveat tracked in OQ-4.)
- AC-6: Custom-emoji and sticker-pack catalogs load stale-first from Room and refresh in the
  background; inbound shortcodes render even if the picker was never opened.
- AC-7: GIF search loads results (single bounded page — CORRECTED: the backend is not
  cursor-paginated) and shows empty/error/retry states; empty query shows trending; no full
  query text is logged.

## 15. Definition of Done

- Code merged to `android-port` under `android/`, package base `com.testlogon.android`,
  building on JDK 17 / AGP 8.7.3 / Gradle 8.9, compileSdk 35, minSdk 24.
- New Retrofit service, Moshi models, Room entities/DAOs, repository, ViewModel additions,
  picker UI, and message-rendering branches implemented and wired via Hilt (KSP).
- All §11 unit, ViewModel, inline-emoji, and Compose tests pass in CI; instrumented
  acceptance test for "send + render each type" green.
- `ktlint`/`detekt` clean; no new lint baseline suppressions; strings externalized;
  accessibility semantics verified with TalkBack on at least one device/emulator.
- Field names reconciled against `/openapi.json` (OQ-1) and OQ-2/OQ-3/OQ-4 resolved or
  explicitly deferred with a follow-up ticket.
- Catalog caches cleared on logout; image loader confirmed not to forward session cookies to
  third-party hosts.
- Spec reviewer sign-off; no P0/P1 defects open against the feature.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **GIF send endpoint is `POST /messaging/conversations/{conversation_id}/messages/gif`.**
   VERDICT: Corrected (draft said `POST /messages/gif`).
   SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/gif` (op
   `send_gif_message_…`, req `SendGifMessageIn`, resp `201:MessageOut`);
   `src/api/endpoints/messaging.ts: sendGifMessage`.
2. **`SendGifMessageIn` is flat: required `gif_url`, optional `gif_alt_text`, `gif_width`,
   `gif_height`, `reply_to_message_id`; no `conversation_id`/`client_id`/nested `gif`/
   `preview_url`/`provider`/`provider_id`.** VERDICT: Corrected.
   SOURCE: OpenAPI schema `SendGifMessageIn`; `src/api/endpoints/messaging.ts: sendGifMessage`
   (`{ gif_url, gif_alt_text?, gif_width?, gif_height?, reply_to_message_id? }`).
3. **Sticker send endpoint is `POST /messaging/conversations/{conversation_id}/messages/sticker`
   with body `{ sticker_id, sticker_collection_id, reply_to_message_id? }` (both ids required).**
   VERDICT: Corrected (draft said `POST /messages/sticker` with `pack_id`).
   SOURCE: OpenAPI `POST /…/messages/sticker` (req `SendStickerMessageIn`);
   `src/api/endpoints/messaging.ts: sendStickerMessage`.
4. **`MessageOut` uses a `kind` enum discriminator (values incl. `text`,`gif`,`sticker`), id
   is `message_id`, `created_at` is an integer epoch; GIF/sticker fields are flat
   (`gif_url`,`gif_alt_text`,`gif_width`,`gif_height`,`gif_provider`,`sticker_url`,
   `sticker_id`,`sticker_collection_id`,`sticker_alt_text`); there is no `content` object and
   no `client_id`.** VERDICT: Corrected (draft used `type`, `id`, ISO `created_at`, nested
   `content`, `client_id`). SOURCE: OpenAPI schema `MessageOut`;
   `src/pages/messages/MessageBubble.tsx` (`message.kind === "gif" && message.gif_url`,
   `message.kind === "sticker" && message.sticker_url`).
5. **GIF search is `GET /ui/stickers/gifs/search?q=&limit=` (limit max 50), trending is a
   separate `GET /ui/stickers/gifs/trending?limit=`; both return a BARE array of
   `GifSearchResult` `{id,url,alt_text,width,height}` — no `cursor`/`next_cursor`/`results`
   wrapper, no `preview_url`, no `provider`.** VERDICT: Corrected (draft said
   `GET /messages/gif/search` with `cursor`/`next_cursor`/`results`/`provider`/`preview_url`).
   SOURCE: OpenAPI `GET /ui/stickers/gifs/search` (params `q,limit`; resp `200: array of
   GifSearchResult`) and `…/trending`; `src/api/endpoints/stickers.ts: searchGifs /
   getTrendingGifs`; `src/components/shared/GifPicker.tsx` (debounced; trending when empty).
6. **Sticker collections are `GET /ui/stickers/collections` → `{ collections: [...] }`; a
   collection has `collection_id`,`name`,`thumbnail_url`,`description`,`sticker_count`,
   `stickers[]`; per-collection stickers also at
   `GET /ui/stickers/collections/{collection_id}/stickers`.** VERDICT: Corrected (draft said
   `GET /messages/sticker/packs` with `packs[]`/`pack_id`/`cover_url`).
   SOURCE: OpenAPI `GET /ui/stickers/collections` (`StickerCollectionListOut` →
   `StickerCollectionOut`); `src/api/endpoints/stickers.ts: listStickerCollections /
   getCollectionStickers`.
7. **`StickerOut` fields are `sticker_id`,`image_url`,`alt_text`,`width`,`height`,`sort_order`
   — no `name`, no `url`.** VERDICT: Corrected (draft had sticker `name` and `url`).
   SOURCE: OpenAPI schema `StickerOut`; `src/api/endpoints/stickers.ts: Sticker`.
8. **Custom-emoji catalog is `GET /ui/emojis/custom` → `{ emojis: [...], global_count,
   personal_count }`; `CustomEmojiOut` has `emoji_id`,`shortcode`,`name`,`image_url`,
   `content_type`,`owner_scope`,`created_by`,`alt_text`,`category` — no `animated` boolean and
   image field is `image_url` not `url`.** VERDICT: Corrected (draft said
   `GET /messages/emoji/custom` → `{ emoji: [...] }` with `url`+`animated`).
   SOURCE: OpenAPI `GET /ui/emojis/custom` (`CustomEmojiListOut` → `CustomEmojiOut`);
   `src/api/endpoints/customEmojis.ts: listMyCustomEmojis`.
9. **Inbound shortcode resolution endpoint `GET /ui/emojis/custom/resolve?codes=a,b` →
   `{ resolved: { shortcode: image_url } }`.** VERDICT: Verified (new info; not in draft).
   SOURCE: OpenAPI `GET /ui/emojis/custom/resolve` (`ResolveShortcodesOut`);
   `src/api/endpoints/customEmojis.ts: resolveCustomShortcodes`; `src/hooks/useCustomEmojiMap.ts`.
10. **Custom emoji travels as inline `:shortcode:` in the text body; built-in Unicode
    shortcodes are replaced client-side before send, only custom shortcodes survive; the
    shortcode regex is `:([a-z0-9_]{2,32}):` (case-insensitive), NOT `:([a-z0-9_+-]+):`.**
    VERDICT: Corrected (regex) / Verified (transport).
    SOURCE: `src/utils/emoji.ts` (`CUSTOM_SHORTCODE_RE = /:([a-z0-9_]{2,32}):/g`,
    `replaceShortcodes`, `extractCustomShortcodes`, `splitCustomEmojiText`).
11. **Sticker bubble renders at 128×128 (≤128dp).** VERDICT: Verified.
    SOURCE: `src/pages/messages/MessageBubble.tsx` (`<div className="h-32 w-32">` around the
    `sticker_url` `<img>`; `h-32`/`w-32` = 128px).
12. **GIF bubble renders `gif_url` with `gif_width`/`gif_height` aspect ratio and `gif_alt_text`
    alt; web uses a plain `<img>` (no explicit animation toggle).** VERDICT: Verified (Android
    adds reduced-motion handling as an enhancement). SOURCE:
    `src/pages/messages/MessageBubble.tsx` (`message.kind === "gif" && message.gif_url`).
13. **Auth: CSRF token from the `ui_csrf` cookie sent as `X-CSRF-Token`; 401 triggers a
    single-flight `POST /ui/session/refresh` then one retry.** VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `X-CSRF-Token`; `refreshSession()`
    POSTs `/ui/session/refresh`; `refreshPromise` single-flight).
14. **Auth additionally uses an `Authorization: Bearer <accessToken>` header (not cookie-only).**
    VERDICT: Corrected (draft implied cookie-session-only). SOURCE: `src/api/client.ts`
    (`headers.set("Authorization", \`Bearer ${accessToken}\`)`); OpenAPI send endpoints list
    `authorization` + `X-SESSION-ID` params.
15. **No `client_id`/idempotency key on the GIF/sticker POSTs (so retry has no server dedup).**
    VERDICT: Corrected (draft's reconcile/retry-by-`client_id` is not implementable).
    SOURCE: OpenAPI schemas `SendGifMessageIn`/`SendStickerMessageIn` (no such field) and
    `MessageOut` (no echo); `src/api/endpoints/messaging.ts` (sends pass no idempotency key).
16. **FastAPI error envelope `detail` may be a string, an array of `{msg}`, or an object with
    a `code`; validation failures are `422: HTTPValidationError`.** VERDICT: Verified.
    SOURCE: `src/api/client.ts: normalizeErrorDetail` (handles string / array-of-`{msg}` /
    `{code}`); OpenAPI `422: HTTPValidationError` on all five endpoints.
17. **Coil animated-decoder choice: `ImageDecoderDecoder` on API 28+, `GifDecoder` on API
    24–27.** VERDICT: Unverified-assumption (framework choice, not in the backend/web sources).
    SOURCE: framework ref — Coil image-loaders docs
    (https://coil-kt.github.io/coil/gifs/).

### Corrections made
- GIF/sticker send paths → conversation-scoped `/messaging/conversations/{id}/messages/{gif|sticker}` (§1, §2, §5.1–5.2, §5.6, §14).
- Request bodies flattened; removed `conversation_id`/`client_id`/nested `gif`/`preview_url`/`provider`/`provider_id`; sticker `pack_id` → `sticker_collection_id` (§4.2–4.4, §5.1–5.2).
- `MessageOut`: `type`→`kind`, `id`→`message_id`, ISO→integer-epoch `created_at`, flat fields, no nested `content`, no `client_id` (§4.2, §5.1–5.2).
- GIF search path → `/ui/stickers/gifs/search` (+ `/trending`); removed cursor pagination / `next_cursor`; response is a bare array; dropped Paging-3 cursor design (§4.4–4.6, §5.3, §6, §11, §14 AC-7).
- Sticker catalog path → `/ui/stickers/collections`; `packs`→`collections`, `cover_url`→`thumbnail_url`, sticker `url`→`image_url`, removed sticker `name` (§4.2, §5.4, §6, §9).
- Custom-emoji path → `/ui/emojis/custom`; `emoji`→`emojis`, `url`→`image_url`, removed `animated` boolean (animation from `content_type`); documented `/resolve` (§4.2, §5.5, §6).
- Shortcode regex `:([a-z0-9_+-]+):` → `:([a-z0-9_]{2,32}):` (§4.6, §11).
- Reconciliation/retry redesigned off `client_id` onto `localId`→`message_id` from the POST body; flagged duplicate-on-retry risk (§4.3–4.4, §6, §7, §11, §14 AC-5, OQ-4).
- Auth clarified: Bearer + CSRF cookie (not cookie-only); added OQ-5 (§2, §8, §13).
- OQ-1/OQ-2 marked resolved; OQ-3 confirmed; OQ-4 resolved-negatively; OQ-5 added (§13).

### Open assumptions
- **Production GIF provider identity / attribution.** The dev `…/gifs/search` is described as a
  "configured (mock) provider"; whether production is Tenor/Giphy and what attribution it
  requires is not in the sources. (Why: OpenAPI description says "mock"; no provider field
  returned.)
- **Server-side idempotency for sends.** No key exists today; whether the backend will add one
  is a product/backend decision, not derivable from current sources. (OQ-4.)
- **Android auth transport (Bearer + cookie vs cookie-only).** Depends on AND-124/`core-network`
  decisions not captured in these sources. (OQ-5.)
- **Coil animated-decoder selection by API level.** Framework guidance only; not a backend
  contract. (Claim 17.)
- **Reduced-motion static-frame for GIFs.** No `preview_url` exists, so freezing on the first
  frame via Coil is an assumed, untested approach.

## 17. Test Plan

Targets: JVM = JVM/Robolectric local; MWS = MockWebServer contract; EMU = headless AVD
`test35` (x86_64, API 35); DEV = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a).
Compose-UI/instrumented cases run on EMU unless a row says it MUST run on DEV.

- **TC-AND-135-01 — Happy path: send + render GIF (contract).**
  Type: contract/MockWebServer (JVM+MWS).
  Target: `MediaMessageApi.sendGif` + `MediaMessageRepository.sendGif`.
  Preconditions: MWS enqueues `201` with a `MessageOut` (`kind:"gif"`, `message_id`,
  `gif_url`, `gif_width/height`, integer `created_at`).
  Steps: call `sendGif(cid, payload)`; capture the recorded request.
  Expected: request line is `POST /messaging/conversations/{cid}/messages/gif`; JSON body has
  `gif_url` (+ optional `gif_alt_text/gif_width/gif_height`) and NO `conversation_id`/
  `client_id`/nested `gif`; parsed result exposes `message_id` and `kind=gif`; optimistic row
  reconciles `localId`→`message_id`.
  Traces: AC-2.
- **TC-AND-135-02 — Happy path: send + render sticker (contract).**
  Type: contract/MockWebServer (JVM+MWS).
  Target: `MediaMessageApi.sendSticker`.
  Preconditions: MWS enqueues `201` `MessageOut` (`kind:"sticker"`, `sticker_url`,
  `sticker_collection_id`).
  Steps: call `sendSticker(cid, collectionId, stickerId)`; inspect request.
  Expected: `POST /messaging/conversations/{cid}/messages/sticker`; body has `sticker_id` +
  `sticker_collection_id` (NOT `pack_id`), no `conversation_id`/`client_id`; result parses
  `sticker_url`/`sticker_alt_text`.
  Traces: AC-3.
- **TC-AND-135-03 — MessageOut deserialization across kinds (unit).**
  Type: unit (JVM).
  Target: Moshi `MessageDto` adapter.
  Preconditions: fixture JSON for `kind` ∈ {text, gif, sticker} with flat fields + integer
  `created_at`.
  Steps: parse each fixture.
  Expected: discriminates on `kind`; maps `message_id`/`created_at` (epoch int); gif→`gif_url`,
  sticker→`sticker_url`; unknown future `kind` degrades safely (no crash).
  Traces: AC-2, AC-3.
- **TC-AND-135-04 — GIF search + trending, bare array, no cursor (contract).**
  Type: contract/MockWebServer (JVM+MWS).
  Target: `MediaMessageApi.searchGifs` / `trendingGifs` + repo.
  Preconditions: MWS returns a bare JSON array of `GifSearchResult`.
  Steps: call with `q="cat"`, then with empty `q`.
  Expected: non-empty `q` hits `GET /ui/stickers/gifs/search?q=cat&limit=20` and parses the
  array directly (no `results`/`next_cursor` wrapper); empty `q` hits
  `GET /ui/stickers/gifs/trending?limit=20`; `limit` is clamped ≤ 50; each item exposes
  `id,url,alt_text,width,height` (no `preview_url`/`provider`).
  Traces: AC-7.
- **TC-AND-135-05 — Sticker collections + emoji catalog stale-first (integration).**
  Type: integration (Robolectric + Room + MWS) (JVM/EMU).
  Target: `MediaMessageRepository.stickerCollections` / `customEmoji` / `refreshCustomEmoji`.
  Preconditions: Room seeded with stale rows; MWS returns `{collections:[...]}` and
  `{emojis:[...], global_count, personal_count}`.
  Steps: observe the `Flow`s; trigger refresh.
  Expected: cached rows emit first, then refreshed; collection maps `collection_id`/
  `thumbnail_url`, sticker maps `image_url`; emoji maps `image_url` + derives `animated` from
  `content_type`; inbound shortcodes render even though the picker was never opened.
  Traces: AC-6.
- **TC-AND-135-06 — Inline custom-emoji substitution helper (unit).**
  Type: unit (JVM).
  Target: `EmojiText` shortcode splitter (regex `:([a-z0-9_]{2,32}):`).
  Preconditions: catalog map `{partyparrot→url}`.
  Steps: feed `"hi :partyparrot: :unknown: :x: :"`+`"a".repeat(40)`+`":"` and adjacent
  `":partyparrot::partyparrot:"`.
  Expected: known→inline image; unknown→literal; 1-char (`:x:`) and >32-char tokens do NOT
  match (left literal); adjacent tokens both resolve; malformed colons untouched.
  Traces: AC-4.
- **TC-AND-135-07 — Optimistic send failure → FAILED → manual retry (unit).**
  Type: unit (JVM).
  Target: `MediaMessageRepository.sendGif` failure/retry path with fake API.
  Preconditions: fake API returns network error, then `201 MessageOut` on retry.
  Steps: send (fails) → row `FAILED`; invoke retry.
  Expected: optimistic row goes `SENDING`→`FAILED`; retry re-POSTs (same payload, NO
  `client_id`/idempotency key — assert absence) → reconciles to `SENT` with `message_id`.
  Documents duplicate-risk caveat (OQ-4).
  Traces: AC-5.
- **TC-AND-135-08 — Error-envelope mapping (422 / 401 / 403) (contract).**
  Type: contract/MockWebServer (JVM+MWS).
  Target: `core-network` `ApiResult` adapter for the new calls.
  Preconditions: MWS returns `422 HTTPValidationError` (`detail:[{msg}]`), a `detail` string,
  and a `{code}` object; plus a `401`.
  Steps: invoke send/search against each.
  Expected: all three `detail` shapes map to a user message; `401` triggers a single-flight
  `POST /ui/session/refresh` then one retry; non-2xx surfaces a typed error, never a crash.
  Traces: AC-5, AC-7.
- **TC-AND-135-09 — ViewModel picker state + actions (unit).**
  Type: unit (JVM, MainDispatcherRule + Turbine).
  Target: `ConversationViewModel` media-picker state.
  Preconditions: fake repo.
  Steps: open picker; switch tabs; type a query (assert ~300ms debounce, trending on empty);
  `onGifSelected`; `onCustomEmojiSelected("partyparrot")`.
  Expected: state survives (tab/query retained); `onGifSelected` sends + closes the sheet;
  `onCustomEmojiSelected` inserts `:partyparrot:` at the caret WITHOUT sending.
  Traces: AC-1, AC-4.
- **TC-AND-135-10 — Picker UI + rotation state retention (Compose-UI).**
  Type: Compose-UI / instrumented (EMU).
  Target: `MediaPickerSheet`, `GifGrid`, `StickerPane`, `EmojiGrid`.
  Preconditions: stubbed repo with sample data.
  Steps: open picker; assert GIF/Stickers/Emoji tabs; type a query; rotate device.
  Expected: three tabs present; selecting a GIF/sticker fires the callback once; active tab +
  query survive recreation; empty/error/retry states show for GIF search.
  Traces: AC-1, AC-7.
- **TC-AND-135-11 — Bubble rendering + accessibility semantics (Compose-UI).**
  Type: Compose-UI / instrumented (EMU).
  Target: `GifBubble`, `StickerBubble`, `EmojiText` in `MessageItem`.
  Preconditions: messages with `kind` gif/sticker and a text msg containing a known + unknown
  shortcode.
  Steps: render the list; query semantics.
  Expected: GIF bubble uses `gif_url` + aspect ratio + contentDescription from `gif_alt_text`;
  sticker bubble ≤128dp with contentDescription from `sticker_alt_text` (NOT a `name`); inline
  emoji has alt text `:shortcode:`; unknown shortcode shows as literal text.
  Traces: AC-2, AC-3, AC-4.
- **TC-AND-135-12 — Animated GIF/WebP decode on real hardware across ABI/API (instrumented).**
  Type: instrumented/e2e (DEV — MUST run on the physical Galaxy A15, arm64-v8a/API 34).
  Target: Coil animated decoders + reduced-motion path.
  Preconditions: device with animated GIF + animated-WebP custom emoji fixtures; toggle
  Settings → Developer options → animation scale = off.
  Steps: open a conversation rendering an animated GIF and an animated-WebP emoji; scroll; then
  enable reduced-motion and re-open.
  Expected: animates on arm64/API 34 (validates the non-emulator decoder path vs EMU API 35);
  under reduced-motion the GIF shows a static first frame; no OOM/jank in a long list
  (off-screen animations paused). MUST be on DEV because animated-image decoding and
  ABI/API-level behavior differ from the x86_64/API-35 emulator.
  Traces: AC-2, AC-4.
- **TC-AND-135-13 — Flaky-host / offline resilience (integration).**
  Type: integration (Robolectric + MWS fault injection) (JVM/EMU).
  Target: retry policy + stale-first fallback + timeouts.
  Preconditions: MWS configured for delays/timeouts/`503` on the idempotent GETs, then a
  disconnected radio for a send.
  Steps: load GIF search/collections/catalog under fault; attempt a GIF send while offline.
  Expected: idempotent GETs apply bounded jittered backoff (≤3) within the 20s timeout;
  catalog falls back to stale Room cache silently; the offline send becomes a `FAILED` bubble
  (never auto-retried) with a working manual retry; no crash.
  Traces: AC-5, AC-6, AC-7.
- **TC-AND-135-14 — CSRF/auth + no-cookie-to-third-party-host + logout cache clear (manual+contract).**
  Type: manual + contract/MockWebServer (DEV for the real CDN check; JVM+MWS for headers).
  Target: send/catalog request headers; Coil image `OkHttpClient`; logout hook.
  Preconditions: a `ui_csrf` cookie + access token present; a sticker/emoji `image_url` on a
  separate host.
  Steps: (contract) inspect outgoing send/catalog requests; (DEV) load a third-party image
  URL through Coil and inspect that no auth cookie/Authorization is attached; log out.
  Expected: POST sends carry `X-CSRF-Token` (+ Bearer per §8); image requests to third-party
  hosts carry NO session cookie/Authorization (separate image client); on logout the
  `custom_emoji`/`sticker_collection`/`sticker` Room caches are cleared.
  Traces: AC-5, AC-6.

### Coverage matrix
- AC-1 → TC-09, TC-10
- AC-2 → TC-01, TC-03, TC-11, TC-12
- AC-3 → TC-02, TC-03, TC-11
- AC-4 → TC-06, TC-09, TC-11, TC-12
- AC-5 → TC-07, TC-08, TC-13, TC-14
- AC-6 → TC-05, TC-13, TC-14
- AC-7 → TC-04, TC-08, TC-10, TC-13
