---
id: AND-135
title: GIFs, stickers, custom emoji
milestone: M3
epic: E19
priority: P2
size: M
status: draft
depends_on:
  - AND-124
blocks: []
---

# AND-135 — GIFs, stickers, custom emoji

## 1. Overview & Goal

Extend the message composer delivered in AND-124 ("Send text message") so users can
compose, send, and render three new rich message content types: animated **GIFs**,
**stickers** (server-hosted sticker-pack images), and **custom emoji** (workspace-scoped
named images rendered inline). The ticket covers the picker UI surfaced from the composer,
the wire format for the two new send endpoints (`/messages/gif`, `/messages/sticker`), the
custom-emoji catalog fetch + inline substitution path, and rendering of all three types in
the message list.

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
- Web reference: `frontend/src/api/endpoints/messages.ts` (GIF/sticker send), the
  custom-emoji catalog endpoint, and `frontend/src/api/types.ts` for `MessageContent`
  discriminated-union shapes. Confirm exact field names against `/openapi.json` before
  freezing the Moshi models.
- Auth/transport: all calls ride the cookie session + `X-CSRF-Token` header established in
  the auth epic; the persistent cookie jar and single-flight `POST /ui/session/refresh` on
  401 are provided by `core-network` and apply transparently here.
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
```kotlin
sealed interface MessageContent {
    data class Text(val body: String) : MessageContent          // existing (AND-124)
    data class Gif(val url: String, val previewUrl: String?,
                   val width: Int, val height: Int,
                   val provider: String, val providerId: String) : MessageContent
    data class Sticker(val stickerId: String, val packId: String,
                       val url: String, val name: String) : MessageContent
}

data class CustomEmoji(
    val shortcode: String,   // without surrounding colons
    val url: String,
    val animated: Boolean,
)

data class StickerPack(
    val packId: String,
    val name: String,
    val coverUrl: String,
    val stickers: List<Sticker>,
)
```
`Text` rendering is unchanged on the wire; custom emoji travels inside the text body as
`:shortcode:` and is resolved client-side from the catalog.

### 4.3 Outgoing message types (feature-chat / core-data)
Extend AND-124's `OutgoingMessage`:
```kotlin
sealed interface OutgoingMessage {
    val localId: String        // client UUID for optimistic reconciliation
    data class Text(...) : OutgoingMessage
    data class Gif(override val localId: String, val conversationId: String,
                   val gif: GifSendPayload) : OutgoingMessage
    data class Sticker(override val localId: String, val conversationId: String,
                       val stickerId: String, val packId: String) : OutgoingMessage
}
```

### 4.4 Repository (core-data)
```kotlin
interface MediaMessageRepository {
    suspend fun sendGif(conversationId: String, gif: GifSendPayload): ApiResult<Message>
    suspend fun sendSticker(conversationId: String, packId: String,
                            stickerId: String): ApiResult<Message>

    fun gifSearch(query: String): Flow<PagingData<GifResult>>     // Paging 3
    suspend fun stickerPacks(): ApiResult<List<StickerPack>>      // stale-first
    fun customEmoji(): Flow<List<CustomEmoji>>                    // Room-backed, stale-first
    suspend fun refreshCustomEmoji(): ApiResult<Unit>
}
```
`sendGif`/`sendSticker` perform optimistic insert via the shared `MessageRepository` (insert
local row, status `SENDING`), POST, then reconcile by `localId`. They are **not** retried
automatically (non-idempotent POST); failure surfaces a manual retry.

### 4.5 ViewModel (feature-chat)
The existing `ConversationViewModel` exposes `StateFlow<ConversationUiState>`. Add a nested
picker state plus actions:
```kotlin
data class MediaPickerState(
    val visible: Boolean = false,
    val tab: MediaTab = MediaTab.GIF,
    val gifQuery: String = "",
    val selectedPackId: String? = null,
    val packs: Loadable<List<StickerPack>> = Loadable.Idle,
    val emoji: List<CustomEmoji> = emptyList(),
)
enum class MediaTab { GIF, STICKERS, EMOJI }

fun openMediaPicker(); fun closeMediaPicker(); fun selectTab(tab: MediaTab)
fun onGifQueryChange(q: String); fun onGifSelected(gif: GifResult)
fun onStickerSelected(packId: String, stickerId: String)
fun onCustomEmojiSelected(shortcode: String)   // inserts ":$shortcode:" at caret
val gifResults: Flow<PagingData<GifResult>>     // flatMapLatest on debounced query
```
GIF search debounces the query (~300 ms) and `flatMapLatest` into `gifSearch`. The Paging
flow is `cachedIn(viewModelScope)`.

### 4.6 Compose UI (feature-chat)
- `MediaPickerSheet(state, onAction)` — `ModalBottomSheet` hosting a `TabRow` + per-tab pane.
- `GifGrid(items: LazyPagingItems<GifResult>, onSelect)` — `LazyVerticalStaggeredGrid`,
  Coil `AsyncImage` with the GIF decoder, append/loading/error footer states.
- `StickerPane(packs, selectedPackId, onPackSelect, onSelect)`.
- `EmojiGrid(emoji, query, onSelect)` — `LazyVerticalGrid`, fixed cell size.
- Message rendering additions in `MessageItem`: `GifBubble`, `StickerBubble`, and
  `EmojiText` (an `InlineTextContent`-based composable that substitutes `:shortcode:` →
  inline image via a precompiled regex `:([a-z0-9_+-]+):` and the cached catalog).

### 4.7 Image loading
Register Coil decoders in the application `ImageLoader` (core-ui): `ImageDecoderDecoder`
(API 28+) / `GifDecoder` (API 24–27) for animated GIFs and animated WebP custom emoji.
Stickers and static emoji use the default decoder. Inline emoji are loaded into
`InlineTextContent` slots sized to font line height.

## 5. API Contract

All paths are relative to the dev base `http://18.222.237.167:8000`. Field names below are
provisional — **verify against `/openapi.json` and `frontend/src/api/types.ts` before
freezing Moshi adapters.** All requests carry the session cookies and `X-CSRF-Token`.

### 5.1 Send GIF — `POST /messages/gif`
Request:
```json
{
  "conversation_id": "conv_123",
  "client_id": "9f1c…",
  "gif": { "url": "https://media…/x.gif", "preview_url": "https://…/x_s.gif",
           "width": 480, "height": 270, "provider": "tenor", "provider_id": "abc123" }
}
```
Response `201`:
```json
{ "id": "msg_789", "conversation_id": "conv_123", "client_id": "9f1c…",
  "type": "gif", "content": { "url": "…", "preview_url": "…",
  "width": 480, "height": 270 }, "created_at": "2026-06-05T12:00:00Z" }
```

### 5.2 Send sticker — `POST /messages/sticker`
Request: `{ "conversation_id": "conv_123", "client_id": "…", "pack_id": "pk_1", "sticker_id": "st_42" }`
Response `201`: `{ "id": "msg_790", "type": "sticker",
  "content": { "sticker_id": "st_42", "pack_id": "pk_1", "url": "…", "name": "wave" }, … }`

### 5.3 GIF search (provider proxy) — `GET /messages/gif/search?q={q}&cursor={c}&limit=30`
Response: `{ "results": [ { "id": "abc123", "url": "…", "preview_url": "…",
  "width": 480, "height": 270, "provider": "tenor" } ], "next_cursor": "eyJ…" }`
Empty `q` returns a trending feed. This is the only **idempotent GET** here and is eligible
for the bounded backoff retry policy; it backs the Paging 3 `PagingSource`.

### 5.4 Sticker packs — `GET /messages/sticker/packs`
Response: `{ "packs": [ { "pack_id": "pk_1", "name": "Animals", "cover_url": "…",
  "stickers": [ { "sticker_id": "st_42", "name": "wave", "url": "…" } ] } ] }`

### 5.5 Custom-emoji catalog — `GET /messages/emoji/custom`
Response: `{ "emoji": [ { "shortcode": "partyparrot", "url": "…", "animated": true } ] }`

### 5.6 Retrofit service (core-network)
```kotlin
interface MediaMessageApi {
    @POST("messages/gif")     suspend fun sendGif(@Body b: SendGifRequest): Response<MessageDto>
    @POST("messages/sticker") suspend fun sendSticker(@Body b: SendStickerRequest): Response<MessageDto>
    @GET("messages/gif/search") suspend fun searchGifs(
        @Query("q") q: String, @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 30): Response<GifSearchResponse>
    @GET("messages/sticker/packs") suspend fun stickerPacks(): Response<StickerPacksResponse>
    @GET("messages/emoji/custom")  suspend fun customEmoji(): Response<CustomEmojiResponse>
}
```
Responses are wrapped into `ApiResult<T>` by the shared `core-network` call adapter, which
also maps the FastAPI `detail` field (string | `[{msg}]` | `{code,…}`).

## 6. Data & State Management

- **Room (core-data):** `custom_emoji` table (`shortcode` PK, `url`, `animated`,
  `fetched_at`) and `sticker_pack` / `sticker` tables (composite keys, `fetched_at`).
  DAOs expose `Flow` reads; repository writes via upsert + a `deleteStale` pass after a
  successful refresh. The custom-emoji `Flow` is the single source of truth for both the
  picker grid and inline-render substitution.
- **Stale-first policy:** on first observe, emit cached rows immediately, then trigger a
  network refresh; a refresh timestamp in DataStore (`emoji_catalog_refreshed_at`) gates
  refresh frequency (e.g., max once / 6 h unless forced).
- **GIF search** is **not** persisted — Paging 3 `RemoteMediator` is unnecessary; a plain
  cursor-based `PagingSource` over `searchGifs` with `cachedIn(viewModelScope)` is enough
  (results are ephemeral provider data).
- **Optimistic rows:** GIF/sticker optimistic messages reuse AND-124's local message table
  with `status` (`SENDING|SENT|FAILED`) and `client_id`/`localId`. Reconciliation matches
  the ack's `client_id` to swap in the server `id` and `created_at`.
- **UiState:** `ConversationUiState` already drives the screen; `MediaPickerState` is nested
  inside it (or a sibling `StateFlow`) and exposed via the existing `StateFlow<UiState>`
  contract. No `LiveData`.

## 7. Error Handling & Resilience

- **Unreliable dev host:** apply the 20 s OkHttp timeout. Only the idempotent GETs
  (`gif/search`, `sticker/packs`, `emoji/custom`) use bounded exponential backoff (≤3
  attempts, jittered). The two POST sends are **never** auto-retried (duplicate-message
  risk); failures become `FAILED` bubbles with a manual "Tap to retry" that re-POSTs with
  the **same** `client_id` for idempotent server-side dedup.
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

- No new credential surface; auth is the existing cookie + CSRF session. All five calls send
  `X-CSRF-Token` (state-changing POSTs require it; GETs include it harmlessly).
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
  ("GIF, <alt/provider tag>"), stickers ("Sticker, <name>"), custom emoji
  (":<shortcode>:"). Sent GIF/sticker bubbles carry a `contentDescription`.
- Inline custom emoji in `EmojiText` set `InlineTextContent` alt text so screen readers
  announce `:shortcode:` rather than skipping the glyph.
- Tabs are reachable and labeled; picker is dismissible via back gesture and TalkBack.
- Respect reduced-motion: when the system animator/transition scale is 0, render GIFs as the
  static `preview_url`/first frame (do not auto-animate). Touch targets ≥ 48dp.
- All user-facing strings (`composer_add_media`, tab labels, empty/error/retry states) live
  in `strings.xml`; no hardcoded text. Grids are RTL-aware via Compose defaults.

## 10. Telemetry & Logging

- Analytics events (via the app's existing analytics abstraction): `media_picker_opened`
  `{tab}`, `gif_searched` `{query_len, result_count}`, `gif_sent` `{provider}`,
  `sticker_sent` `{pack_id}`, `custom_emoji_inserted` `{shortcode}`, and
  `media_send_failed` `{type, error_code}`. Do not log raw GIF search queries' full text
  (privacy) — log length only.
- Logging: `Timber` (or the project logger) at DEBUG for catalog refresh outcomes and
  optimistic reconciliation; WARN for catalog stale-fallback; ERROR for send failures with
  the mapped `detail` code. No image bytes or URLs with tokens logged.

## 11. Testing Strategy

- **Unit (core-data / feature-chat):**
  - `MediaMessageRepository.sendGif/sendSticker` optimistic-insert → ack reconciliation
    (match by `client_id`) and failure → `FAILED` paths, using fake `MediaMessageApi`.
  - Manual retry re-POSTs with the same `client_id`.
  - Stale-first catalog: emits cache then refreshed values; refresh-failure keeps cache.
  - GIF `PagingSource` cursor paging + `LoadState.Error` mapping.
  - `ApiResult` mapping of FastAPI `detail` (all three shapes) for the new calls.
- **ViewModel:** picker state transitions (open/close/tab/query debounce), `onGifSelected`
  triggers send + closes sheet, `onCustomEmojiSelected` inserts `:shortcode:` at caret.
  Use `core-testing` `MainDispatcherRule` + Turbine on `StateFlow`.
- **Inline-emoji unit:** the `:([a-z0-9_+-]+):` substitution helper — known→inline image,
  unknown→literal, mixed text, adjacent tokens, malformed colons.
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

- **OQ-1:** Exact backend field names and the discriminator key for `type` on `MessageDto`
  (`type` vs `content_type`) — confirm in `/openapi.json`. Provisional shapes in §5 must be
  validated before freezing adapters.
- **OQ-2:** Is GIF search a first-party proxy (`/messages/gif/search`) or does the client
  call a provider (Tenor/Giphy) SDK directly with a key? Spec assumes a backend proxy; if
  not, an API key and provider attribution requirements are added scope.
- **OQ-3:** Custom-emoji transport — confirmed as inline `:shortcode:` in text body (assumed)
  vs a structured content type. Affects whether `onCustomEmojiSelected` sends or just edits
  text.
- **OQ-4:** Server-side idempotency on `client_id` for the POST sends — required for safe
  manual retry; confirm the backend dedups, else retry can duplicate messages.
- **Risk:** Animated GIF/WebP memory pressure on minSdk 24 (`GifDecoder` path) in long
  lists — mitigate by pausing off-screen animations and capping decoded size.
- **Risk:** Third-party image hosts over plaintext HTTP / cookie leakage — mitigated in §8
  (separate image OkHttp client).

## 14. Acceptance Criteria

- AC-1: From the composer, a media picker opens with GIF, Stickers, and Emoji tabs; state
  survives rotation.
- AC-2: **Send + render GIF** — selecting a GIF sends via `POST /messages/gif`, shows an
  optimistic bubble, reconciles on ack, and renders as an animated image (static preview
  under reduced-motion). (Backlog acceptance: "Send + render each type.")
- AC-3: **Send + render sticker** — selecting a sticker sends via `POST /messages/sticker`,
  optimistic → reconciled, renders at ≤128dp.
- AC-4: **Send + render custom emoji** — selecting a custom emoji inserts `:shortcode:` into
  the composer; the sent text message renders that shortcode as an inline image; unknown
  shortcodes render as literal text.
- AC-5: A failed GIF or sticker send shows a `FAILED` bubble with a working retry that reuses
  the same `client_id`.
- AC-6: Custom-emoji and sticker-pack catalogs load stale-first from Room and refresh in the
  background; inbound shortcodes render even if the picker was never opened.
- AC-7: GIF search paginates and shows empty/error/retry states; no full query text is
  logged.

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
