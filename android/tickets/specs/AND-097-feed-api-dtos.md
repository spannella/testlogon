---
id: AND-097
title: Feed API + DTOs
milestone: M2
epic: E14
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-097 — Feed API + DTOs

## 1. Overview & Goal

This ticket delivers the network and data-mapping foundation for the TestLogon newsfeed on
the native Android port: a Retrofit `FeedApi`, the Moshi DTOs that mirror the backend feed
contract (`src/api/endpoints/newsfeed.ts` → `getFeed` on `GET /feed`, and the `FeedPost`
shape in `src/api/types.ts`), the
domain models in `core-model`, and a `FeedRepository` that exposes a typed
`ApiResult<FeedPage>`. It is a non-UI, contract-level slice: no Compose screen, no Paging
wiring, and no list rendering are in scope here. Those are owned downstream (see §12).

The explicit goal is that a single page of the feed — including **paywall / locked**
metadata and media descriptors — round-trips from the dev backend through Retrofit/Moshi
into stable `core-model` types, with deterministic, unit-tested mapping that correctly
distinguishes purchasable/locked posts from fully visible posts. "Tested" in the acceptance
bullet is interpreted as: MockWebServer-backed API tests plus pure mapper unit tests that
assert locked/paywall fields are preserved and defaulted safely.

## 2. Context & References

- Backend: FastAPI + DynamoDB, OpenAPI at `http://18.222.237.167:8000/openapi.json`
  (plaintext HTTP, unreliable dev host). The main feed read route is `GET /feed`
  (`operationId=view_feed_feed_get`, OpenAPI tag `newsfeed`). **Review correction:** the
  `/ui/newsfeed/*` paths in OpenAPI are creator-delegation/admin operations (drafts,
  analytics, settings), NOT the consumer feed read; do not target them for `getFeed`.
- Web reference: `src/api/endpoints/newsfeed.ts` (endpoint signatures, query params — the
  feed fetch is `getFeed` calling `GET /feed`), `src/api/types.ts` (the `FeedPost`
  interface and the `{ items: FeedPost[]; next_cursor?: string }` envelope). These are the
  authoritative shapes the DTOs must mirror. **NOTE (review correction):** there is no
  `Post`/`MediaItem`/`Paywall` named type; the real type is `FeedPost` with *flat* lock
  fields (not a nested `paywall` object), `body` (not `text`), `author_id` (no nested
  `author`), and `image_urls: string[]` + a single `video` object (no `media: MediaItem[]`).
  See §5 and §16 for the corrected contract.
- Auth/session: AND-027 supplies `AuthApi` and the session machinery; the same
  authenticated OkHttp client built in AND-026/AND-027 is reused. **Review correction:** the
  web client is NOT purely cookie-gated. `src/api/client.ts` sends, on every request: a
  cookie session (`credentials: include`), an `Authorization: Bearer <accessToken>` header
  from the auth store, and an `X-CSRF-Token` header sourced from the `ui_csrf` cookie. It
  may also send `X-IMPERSONATION-TOKEN`. The `/feed` endpoint additionally accepts optional
  `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` / `user_sub` per OpenAPI. The Android client must
  reproduce the bearer-token + CSRF-header + cookie combination, not cookies alone.
- Module layering: `core-network` (Retrofit interface, DTOs, error mapping) →
  `core-model` (domain types) → `core-data` (repository). `feature-feed` consumes this in a
  later ticket but is **not** modified here.
- Stack: Kotlin 2.0.21, Retrofit 2.11, OkHttp 4.12, Moshi 1.15 (codegen via KSP),
  Coroutines/Flow, Hilt. Namespace base `com.testlogon.android`.

## 3. Functional Requirements

FR-1. Provide a suspend `FeedApi.getFeed(...)` call that fetches one cursor/offset page of
feed posts for the authenticated user, accepting pagination and optional filter params.

FR-2. Deserialize the backend response into DTOs that capture, for each post: id, author
summary, created timestamp, caption/body text, media list, like/comment counts, and the
paywall block (locked flag, price, currency, purchased flag, unlock/teaser metadata).

FR-3. Map DTOs to `core-model` domain types via a pure, side-effect-free mapper. Locked
posts must map to a domain representation where protected fields (full media URLs, full
body) are explicitly absent/null when the backend withholds them, and a `locked`/`paywall`
state is always present and unambiguous.

FR-4. Expose `FeedRepository.getFeedPage(cursor, limit, filter): ApiResult<FeedPage>`
returning a typed success (`FeedPage` with items + next-cursor) or a typed error
(`ApiError`) mapped from the FastAPI `detail` shape and transport failures.

FR-5. Distinguish three media access states per media item: fully accessible (URL present),
locked-with-teaser (blurred/preview URL or dimensions only), and locked-no-preview. The
mapper must derive a single `MediaAccess` enum so the UI need not re-interpret raw flags.

FR-6. Tolerate unknown JSON fields and unknown enum values without throwing (forward
compatibility against the evolving dev backend).

## 4. Technical Design

Package roots (module → package):

- `core-network` → `com.testlogon.android.core.network.feed`
- `core-model`   → `com.testlogon.android.core.model.feed`
- `core-data`    → `com.testlogon.android.core.data.feed`

### Retrofit interface (`core-network`)

```kotlin
package com.testlogon.android.core.network.feed

interface FeedApi {
    // Review correction: path is `feed` (GET /feed), NOT `ui/newsfeed`.
    // Review correction: there is no `filter` param. Real optional filters per OpenAPI /
    // newsfeed.ts are author_id, q (search), from, to (ISO date range), has_media. `limit`
    // exists in OpenAPI (default 20, min 1, max 50) though the web getFeed omits it.
    @GET("feed")
    suspend fun getFeed(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = DEFAULT_PAGE_SIZE,
        @Query("author_id") authorId: String? = null,
        @Query("q") q: String? = null,
        @Query("from") from: String? = null,
        @Query("to") to: String? = null,
        @Query("has_media") hasMedia: Boolean? = null,
    ): FeedPageDto

    companion object { const val DEFAULT_PAGE_SIZE = 20 }
}
```

The path is `feed` (`GET /feed`), confirmed against both `/openapi.json`
(`view_feed_feed_get`) and `newsfeed.ts` (`getFeed`); the contract in §5 is authoritative.
The `FeedApi` is provided via Hilt from the existing authenticated Retrofit instance
(`@Named("authenticated")` Retrofit from AND-026), so cookies, CSRF header, and 401→refresh
are inherited automatically.

### DTOs (`core-network`, Moshi `@JsonClass(generateAdapter = true)`)

```kotlin
// Review correction: the real envelope is { items, next_cursor }. There is NO `has_more`
// field (web `getFeed` types it as `{ items: FeedPost[]; next_cursor?: string }`).
// End-of-feed is signalled by `next_cursor` being absent/null.
@JsonClass(generateAdapter = true)
data class FeedPageDto(
    @Json(name = "items") val items: List<PostDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

// Review correction: PostDto mirrors `FeedPost` in src/api/types.ts. Lock metadata is FLAT
// (no nested `paywall`), id is `post_id`, author is `author_id` (no nested author object),
// the text field is `body`, and media is `image_urls` + a single `video` (no `media[]`).
@JsonClass(generateAdapter = true)
data class PostDto(
    @Json(name = "post_id") val postId: String,
    @Json(name = "author_id") val authorId: String,
    @Json(name = "created_at") val createdAt: String,   // ISO-8601 string
    @Json(name = "body") val body: String? = null,
    @Json(name = "image_urls") val imageUrls: List<String>? = null,
    @Json(name = "video") val video: VideoDto? = null,
    @Json(name = "like_count") val likeCount: Int = 0,
    @Json(name = "comment_count") val commentCount: Int = 0,
    @Json(name = "liked_by_me") val likedByMe: Boolean = false,
    // --- flat lock / paywall fields (mirror FeedPost) ---
    @Json(name = "locked") val locked: Boolean = false,        // runtime flag used by web PostCard
    @Json(name = "unlocked") val unlocked: Boolean = false,    // viewer has purchased/unlocked
    @Json(name = "lock_type") val lockType: String? = null,    // "fixed_price" | "tip_lottery"
    @Json(name = "unlock_price_cents") val unlockPriceCents: Int? = null,
    @Json(name = "unlock_limit") val unlockLimit: Int? = null,
    @Json(name = "unlock_count") val unlockCount: Int? = null,
    @Json(name = "unlock_limit_reached") val unlockLimitReached: Boolean? = null,
    @Json(name = "lock_expired") val lockExpired: Boolean? = null,
)

// Note: there is no `author` object on the feed item — only `author_id`. Author
// display-name/avatar resolution is a separate profile lookup, out of scope for this slice.

@JsonClass(generateAdapter = true)
data class VideoDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Long? = null,
    @Json(name = "hls_manifest_url") val hlsManifestUrl: String? = null,
)
```

> **Removed (review):** the earlier `AuthorDto`, `MediaDto`, and `PaywallDto` types do not
> correspond to anything the backend returns (`currency`, `teaser_text`, `preview_url`,
> `purchased`, `price_cents`, `media[]` are all fabricated). Currency is not modelled — the
> web UI hardcodes `USD` (`$…USD`); price is `unlock_price_cents` only.

### Domain models (`core-model`)

```kotlin
// Review correction: no `hasMore`; end-of-feed == nextCursor == null.
data class FeedPage(val posts: List<FeedPost>, val nextCursor: String?)

data class FeedPost(
    val id: String,                 // from post_id
    val authorId: String,           // only author_id is provided by the feed
    val createdAt: Instant,
    val body: String?,
    val media: List<Media>,         // synthesized from image_urls + video
    val likeCount: Int,
    val commentCount: Int,
    val likedByMe: Boolean,
    val paywall: Paywall,           // never null at domain level (derived from flat fields)
)

enum class MediaType { IMAGE, VIDEO, UNKNOWN }
// Review correction: backend does not provide a per-item preview/blur URL, so there is no
// "teaser preview URL" media state. Locked media is the SAME url/thumbnail that the web UI
// blurs client-side. Access is binary per item, driven by the post-level lock state.
enum class MediaAccess { ACCESSIBLE, LOCKED }

data class Media(
    val id: String,                 // image url or video_id used as stable key
    val type: MediaType,
    val url: String?,               // image url, or video thumbnail/hls (nulled when LOCKED)
    val access: MediaAccess,
)

// Review correction: there is no server `currency` (USD-only in UI) and no `teaser_text`.
// Lock state is derived from flat fields: locked, unlocked, lock_type, unlock_price_cents,
// unlock_limit(_reached), unlock_count, lock_expired.
sealed interface Paywall {
    /** Visible: not locked, or already unlocked/purchased by the viewer. */
    data object Unlocked : Paywall
    data class Locked(
        val lockType: LockType,
        val priceCents: Int?,       // unlock_price_cents (cents, USD assumed by UI)
        val unlockCount: Int?,
        val unlockLimit: Int?,
        val unlockLimitReached: Boolean,
        val lockExpired: Boolean,
    ) : Paywall
}

enum class LockType { FIXED_PRICE, TIP_LOTTERY, UNKNOWN }
```

### Mapper (`core-network` → `core-model`, pure functions)

```kotlin
object FeedMapper {
    fun FeedPageDto.toDomain(): FeedPage
    fun PostDto.toDomain(): FeedPost
    fun PostDto.toPaywall(): Paywall            // derived from flat lock fields
    fun PostDto.toMedia(isLocked: Boolean): List<Media>  // from image_urls + video
}
```

Mapping rules (corrected to the real flat contract — see §16):
- `PostDto.toPaywall()`: the post is *effectively locked* when `locked == true &&
  !unlocked`. If not effectively locked → `Paywall.Unlocked` (covers the unlocked,
  already-purchased, and never-locked cases — matches web `isLocked = !!post.locked &&
  !post.unlocked`). If effectively locked → `Paywall.Locked(lockType, unlockPriceCents,
  unlockCount, unlockLimit, unlockLimitReached ?: false, lockExpired ?: false)`.
- `lock_type` mapping: `"fixed_price"` → `FIXED_PRICE`, `"tip_lottery"` → `TIP_LOTTERY`,
  null/unknown → `UNKNOWN`. (Web treats a non-lottery post with `unlock_price_cents>0` as a
  fixed-price lock, so the mapper defaults `UNKNOWN`+price → `FIXED_PRICE`.)
- `PostDto.toMedia(isLocked)`: build `Media` entries from `image_urls` (type `IMAGE`) and,
  if `video != null`, one `VIDEO` entry keyed on `video_id` (url = `hls_manifest_url ?:
  thumbnail_url`). `access = LOCKED` when the post is effectively locked, else `ACCESSIBLE`.
  When `access == LOCKED`, the `url` is forced to `null` so this layer can never hand a paid
  media URL to the UI — note this is *stricter* than the web client, which keeps the URL and
  blurs it via CSS; on Android we redact instead (defense in depth, see §8).
- `createdAt`: parse ISO-8601; on parse failure fall back to `Instant.EPOCH` and log (no
  throw), so one bad timestamp does not drop a whole page.

### Repository (`core-data`)

```kotlin
class FeedRepository @Inject constructor(
    private val api: FeedApi,
    private val errorMapper: ApiErrorMapper,   // from AND-027 shared infra
) {
    suspend fun getFeedPage(
        cursor: String? = null,
        limit: Int = FeedApi.DEFAULT_PAGE_SIZE,
        filter: String? = null,
    ): ApiResult<FeedPage> = runCatchingApi(errorMapper) {
        with(FeedMapper) { api.getFeed(cursor, limit, filter).toDomain() }
    }
}
```

`runCatchingApi` / `ApiResult` / `ApiErrorMapper` are the shared primitives established by
AND-027; this ticket reuses, not redefines, them. No Room caching and no Paging
`PagingSource` are added here (see §12).

## 5. API Contract

`GET /feed?cursor=<opaque>&limit=20[&author_id=&q=&from=&to=&has_media=]` — authenticated
(cookie session + `Authorization: Bearer` + `X-CSRF-Token`). Idempotent GET → eligible for
bounded backoff retry per §7. (Path/params verified: OpenAPI `view_feed_feed_get` and
`newsfeed.ts:getFeed`. `limit` is OpenAPI-only with default 20 / min 1 / max 50; the web
client omits it. There is NO `filter` param.)

Example 200 response (shape mirrors `FeedPost` in `src/api/types.ts`; the 200 schema is
untyped `{}` in OpenAPI, so `types.ts` is authoritative). An unlocked post and a
fixed-price-locked, not-yet-unlocked post:

```json
{
  "items": [
    {
      "post_id": "post_01HZ...",
      "author_id": "u_42",
      "created_at": "2026-06-04T18:22:10Z",
      "body": "Full post body",
      "image_urls": ["http://18.222.237.167:8000/media/m1.jpg"],
      "like_count": 12, "comment_count": 3, "liked_by_me": true,
      "locked": false, "unlocked": false
    },
    {
      "post_id": "post_01J0...",
      "author_id": "u_99",
      "created_at": "2026-06-04T17:00:00Z",
      "body": "Teaser body",
      "video": { "video_id": "v_2", "title": "Premium clip",
                 "thumbnail_url": "http://18.222.237.167:8000/media/v2_thumb.jpg",
                 "duration_seconds": 45 },
      "like_count": 88, "comment_count": 20, "liked_by_me": false,
      "locked": true, "unlocked": false,
      "lock_type": "fixed_price", "unlock_price_cents": 499,
      "unlock_limit": 500, "unlock_count": 230, "unlock_limit_reached": false,
      "lock_expired": false
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ=="
}
```

Note: there is no `has_more`; absence/null of `next_cursor` is end-of-feed. There is no
nested `author`/`media`/`paywall`/`currency`/`teaser_text`/`preview_url`.

Error responses: the only per-endpoint documented error is `422` (`HTTPValidationError`,
whose `detail` is an array of `ValidationError` objects `{ loc, msg, type }`). `401`/`403`
are not declared per-endpoint but are handled centrally by the shared client (see
`src/api/client.ts`): on `401` the web client calls `POST /ui/session/refresh` once then
retries (AND-027 authenticator mirrors this); `403` detail may be a string or an object
(e.g. `{ "code": "geo_blocked", ... }` / `{ "code": "role_required", ... }`). The
`ApiErrorMapper` must therefore accept `detail` as string, array-of-objects, OR object.
Relevant statuses to map: `401`, `403`, `422`, `5xx`/timeout (transient).

## 6. Data & State Management

This ticket introduces **no** persistent state (no Room, no DataStore writes) and **no**
`StateFlow<UiState>`; those belong to the repository-cache and ViewModel tickets in §12.
The unit of state produced is the in-memory `FeedPage` carrying `posts` and `nextCursor`
(review correction: no `hasMore` — the backend does not return it), which is the seam a
later `PagingSource` will key on (`LoadResult.Page(data, prevKey=null, nextKey=nextCursor)`).

Paging contract this slice must satisfy so downstream Paging 3 work is trivial:
`nextCursor == null` ⇒ end of pagination. `limit` defaults to 20 (OpenAPI max 50) and is
passed through unchanged. Cursors are treated as opaque strings (never parsed client-side).

Identity & dedup: `FeedPost.id` (from `post_id`) is the stable key for later list diffing;
the mapper guarantees ids pass through verbatim. No client-side sorting is applied — server
order is preserved.

## 7. Error Handling & Resilience

- Transport: OkHttp call/connect/read timeouts ~20s (inherited from the shared client built
  for the unreliable dev host). On `IOException`/timeout, `getFeedPage` returns
  `ApiResult.Error(ApiError.Network)`.
- Retry: `getFeed` is an idempotent GET, so it participates in the shared bounded backoff
  retry policy (max 2–3 attempts, jittered exponential) for transient failures (timeouts,
  `5xx`). Non-idempotent calls do not exist in this ticket.
- 401: a single `POST /ui/session/refresh` then one retry is performed by the AND-027
  authenticator/interceptor; the repository sees either the retried success or a terminal
  `ApiError.Unauthorized`.
- Parse robustness: Moshi adapters use defaulted fields; unknown JSON keys are ignored;
  unknown `lock_type` strings degrade to `LockType.UNKNOWN`; a malformed `created_at`
  degrades to `Instant.EPOCH` rather than failing the page. A `JsonDataException` on a
  structurally invalid body maps to `ApiError.Parse` (surfaced as "couldn't load feed").
- Locked-content safety net: any locked media has its `url` nulled by the mapper, so a
  backend leak cannot cause paid content to be fetched/rendered (defense in depth with §8).

## 8. Security & Privacy

- All feed access is over the authenticated session reused from AND-027 — cookie jar +
  `Authorization: Bearer` + `X-CSRF-Token` (review correction: the web client sends all
  three; not cookies alone). No new token handling is added here.
- Paywall enforcement is server-authoritative; the client trusts the server's `locked` /
  `unlocked` flags and additionally refuses to expose media URLs for non-`ACCESSIBLE` media
  (mapper-level redaction — stricter than the web client, which only CSS-blurs).
- Logs must never include media URLs or post `body` at info level; only ids, counts, and
  access/paywall enums (see §10). (There is no `teaser_text` field to leak.)
- Dev backend is plaintext HTTP; this is a known dev-only condition. The release build's
  network security config (owned by the build/security tickets) must continue to forbid
  cleartext for production hosts; this ticket adds no new cleartext exemption.
- No PII is persisted by this slice (no caching introduced).

## 9. Accessibility & i18n

No UI is rendered in this ticket, so there are no Compose semantics, focus order, or
contrast concerns here — those are owned by the feed UI ticket (§12). Two data-shaping
obligations support downstream a11y/i18n:

- `priceCents` is preserved as a raw integer (no client-side formatting), so the UI layer
  can localize via `NumberFormat.getCurrencyInstance(locale)`. **Review correction:** the
  backend supplies no `currency` code; the web UI assumes USD. The Android UI ticket should
  default to USD until/unless a currency field is added server-side (tracked as an open
  assumption in §16).
- Timestamps are exposed as `Instant` (timezone-neutral), enabling locale/timezone-aware
  relative-time formatting downstream. No user-facing strings are introduced by this ticket.

## 10. Telemetry & Logging

- Structured debug log on each `getFeedPage`: `feed.fetch { cursor, limit, filter }` and on
  result `feed.fetch.result { count, hasMore, nextCursorPresent, lockedCount, durationMs }`.
- Error log on failure: `feed.fetch.error { errorType, httpStatus }` — no response bodies.
- Mapper degradations (unknown media type, bad timestamp) emit a single warn with the
  offending field name and post id, throttled, never the value.
- Telemetry uses the project's existing logging abstraction (Timber/`Logger` wrapper); no
  new analytics SDK is added. Metric names use the `feed.` namespace for later dashboards.

## 11. Testing Strategy

Module: tests live in `core-network` and `core-data` test source sets, using `core-testing`
fixtures. Required tests (all must pass for acceptance):

1. **MockWebServer API tests** (`FeedApiTest`): enqueue the §5 sample body; assert
   `getFeed` issues `GET` to the correct path with `cursor`/`limit`/`filter` query params,
   and that headers from the authenticated client are present.
2. **Mapper unit tests** (`FeedMapperTest`, pure, no network):
   - Unlocked post (`locked=false`) → `Paywall.Unlocked`, media `access = ACCESSIBLE`, url
     preserved.
   - Locked, not-yet-unlocked post (`locked=true, unlocked=false`) →
     `Paywall.Locked(lockType=FIXED_PRICE, priceCents=499, unlockCount=230, unlockLimit=500,
     unlockLimitReached=false, lockExpired=false)`, media `access = LOCKED`, `url == null`.
     **(core acceptance: locked/paywall metadata mapped and tested.)**
   - Locked but already unlocked/purchased (`locked=true, unlocked=true`) →
     `Paywall.Unlocked`, media `access = ACCESSIBLE`, url preserved.
   - `tip_lottery` lock → `Paywall.Locked(lockType=TIP_LOTTERY, ...)`.
   - `unlock_limit_reached=true` (or `lock_expired=true`) carried through on `Paywall.Locked`.
   - Unknown `lock_type` string with a price → `LockType.FIXED_PRICE`; without price →
     `UNKNOWN`.
   - Malformed `created_at` → `Instant.EPOCH`; a video with only `thumbnail_url` →
     `MediaType.VIDEO` keyed on `video_id`.
   - Unknown extra JSON field is ignored without error.
3. **Pagination tests**: `next_cursor` absent/null ⇒ `FeedPage.nextCursor == null` (end of
   feed); present ⇒ propagated verbatim.
4. **Repository tests** (`FeedRepositoryTest`): success → `ApiResult.Success<FeedPage>`;
   `401`/`403`/`422`/`5xx`/`IOException` → correct `ApiError` variant via the shared
   `ApiErrorMapper`; FastAPI `detail` forms all map — string (e.g. 403), array of
   `{loc,msg,type}` (422 `HTTPValidationError`), and object (e.g.
   `{"code":"geo_blocked"}` / `{"code":"role_required"}` on 403).

Coverage target: 100% of `FeedMapper` branches; MockWebServer covers `FeedApi` and
`FeedRepository` error paths. No instrumented (device) tests required for this ticket.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi + session endpoints): supplies the authenticated Retrofit
  client, cookie jar, CSRF interceptor, 401→refresh authenticator, `ApiResult`,
  `ApiErrorMapper`, and `runCatchingApi`. This ticket must not duplicate that infra.
- **Blocks** (downstream consumers, not modified here): the feed Paging `PagingSource` /
  repository-cache ticket, the `FeedViewModel` (`StateFlow<FeedUiState>`) ticket, and the
  `feature-feed` Compose screen ticket within epic E14. Hand-off seam is `FeedRepository`
  + `core-model` types defined above.
- Sequencing: land DTOs + mapper + tests first, then the Retrofit interface wiring, then the
  repository; all within this single PR on branch `android-port`.

## 13. Risks & Open Questions

- **Exact feed path & params** — RESOLVED in review: path is `GET /feed` (not
  `ui/newsfeed`); pagination is cursor-based (`cursor` in, `next_cursor` out, no `has_more`).
  Mitigation retained: keep the path/param surface in one Retrofit interface.
- **Paywall field naming** — RESOLVED in review: there is no nested `paywall`/`entitlement`
  object and no `currency`. Lock state is flat: `locked`, `unlocked`, `lock_type`,
  `unlock_price_cents`, `unlock_limit`, `unlock_count`, `unlock_limit_reached`,
  `lock_expired`. Price is cents-only; USD is assumed by the web UI (no ISO code from server).
- **Locked-media URL semantics** — PARTIALLY RESOLVED: the web client does NOT receive a
  separate blurred/preview URL; it keeps the real `image_urls`/`thumbnail_url` and blurs via
  CSS. Open question: does the backend actually withhold the URL for not-yet-unlocked posts,
  or rely entirely on client-side blurring? The Android mapper redacts (`url=null` on
  `LOCKED`) regardless, so this is safe either way — but a captured real sample of a locked
  post is still needed to confirm whether real URLs are leaked to non-purchasers.
- **Unreliable dev host**: timeouts during test capture; use recorded fixtures so tests are
  deterministic and host-independent.
- `liked_by_me` — confirmed present as an optional field on `FeedPost`; defaults to `false`.

## 14. Acceptance Criteria

AC-1. `FeedApi.getFeed(...)` exists and, under MockWebServer, issues a `GET` to `/feed` with
`cursor` and `limit` (and any supplied `author_id`/`q`/`from`/`to`/`has_media`) query params
correctly serialized. (No `filter` param.)
AC-2. A full feed page deserializes into `FeedPage`/`FeedPost`/`Media` with `nextCursor`
populated from `next_cursor` (and `null` when absent — there is no `has_more`).
AC-3. Locked/paywall metadata maps correctly and is unit-tested: locked & not-unlocked →
`Paywall.Locked` carrying `lockType`, `unlock_price_cents`, `unlock_count`, `unlock_limit`,
`unlock_limit_reached`, `lock_expired`; locked & `unlocked=true` → `Paywall.Unlocked`;
`locked=false`/absent → `Paywall.Unlocked`. (Directly satisfies the source acceptance
bullet.)
AC-4. Media of a locked (not-unlocked) post yields `MediaAccess.LOCKED` with `url == null`;
media of an accessible post yields `ACCESSIBLE` with `url` preserved.
AC-5. `FeedRepository.getFeedPage(...)` returns `ApiResult.Success<FeedPage>` on 200 and the
correct `ApiError` variant for 401/403/422/5xx/network/parse failures.
AC-6. Mapping tolerates unknown JSON fields, unknown `lock_type` values, and malformed
timestamps without throwing; all `FeedMapper` branches are covered.

## 15. Definition of Done

- DTOs, `core-model` types, `FeedMapper`, `FeedApi`, and `FeedRepository` implemented in the
  correct modules under `com.testlogon.android.*`, provided via Hilt from the authenticated
  Retrofit instance.
- All §11 tests written and green in CI; `FeedMapper` branch coverage at 100%.
- No new cleartext network exemptions; no PII or media URLs/post body logged at info level.
- No UI, Paging, or caching code introduced (correctly deferred to the §12 downstream
  tickets) and the repository seam documented for them.
- Builds clean with KSP Moshi codegen on JDK 17 / Gradle 8.9 / AGP 8.7.3; merged to
  `android-port` with the §5 contract reconciled against `/openapi.json`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: OpenAPI =
`reference/openapi.index.txt` / `reference/openapi.pretty.json`; FE = `reference/src/...`.

1. **Feed read endpoint is `GET /feed`.** VERIFIED. OpenAPI `GET /feed`
   (`op=view_feed_feed_get`, tag `newsfeed`); FE `src/api/endpoints/newsfeed.ts: getFeed`
   calls `api.get("/feed", ...)`.
2. **It is NOT `/ui/newsfeed`.** CORRECTED (spec previously said `ui/newsfeed`). OpenAPI:
   all `/ui/newsfeed/*` ops are `delegate`/analytics/drafts/settings, not a consumer feed
   read (e.g. `GET /ui/newsfeed/delegate/{creator_id}/posts`).
3. **Query params are `cursor`, `limit`, `author_id`, `q`, `from`, `to`, `has_media`.**
   VERIFIED. OpenAPI `GET /feed` parameters; FE `FeedQueryParams` in `newsfeed.ts`.
4. **There is no `filter` param.** CORRECTED (spec invented `filter=subscribed|all`).
   Absent from both OpenAPI `GET /feed` params and FE `FeedQueryParams`.
5. **`limit` default 20, min 1, max 50.** VERIFIED. OpenAPI `GET /feed` `limit` schema
   (`default:20, minimum:1, maximum:50`). Note the FE `getFeed` does not send `limit`.
6. **Response envelope is `{ items: FeedPost[]; next_cursor?: string }`; no `has_more`.**
   CORRECTED (spec had `has_more`). FE `newsfeed.ts: getFeed` return type
   `{ items: FeedPost[]; next_cursor?: string }`. OpenAPI 200 schema is untyped `{}`, so FE
   is authoritative.
7. **Post id field is `post_id` (not `id`).** CORRECTED. FE `src/api/types.ts: FeedPost.post_id`.
8. **Author is `author_id` only — no nested `author` object.** CORRECTED. FE
   `src/api/types.ts: FeedPost.author_id`; no `author` member on `FeedPost`.
9. **Body text field is `body` (not `text`).** CORRECTED. FE `src/api/types.ts: FeedPost.body`.
10. **Media is `image_urls: string[]` + a single `video` object — no `media: MediaItem[]`,
    no per-item `preview_url`/`width`/`height`/`duration_ms`.** CORRECTED. FE
    `src/api/types.ts: FeedPost.image_urls` and `FeedPost.video`. Confirmed in UI use:
    `src/pages/feed/PostCard.tsx` (`post.image_urls`, `post.video.thumbnail_url`).
11. **Paywall is FLAT fields, not a nested `paywall` object: `locked`, `unlocked`,
    `lock_type` (`fixed_price`|`tip_lottery`), `unlock_price_cents`, `unlock_limit`,
    `unlock_count`, `unlock_limit_reached`, `lock_expired`.** CORRECTED (spec had nested
    `PaywallDto`/`price_cents`/`currency`/`teaser_text`/`purchased`). FE
    `src/api/types.ts: FeedPost` (these exact members) and `src/pages/feed/PostCard.tsx`
    (reads `post.lock_type`, `post.unlock_price_cents`, `post.unlock_limit`,
    `post.unlock_count`, `post.unlock_limit_reached`, `post.lock_expired`).
12. **Effective-locked predicate is `locked && !unlocked`.** VERIFIED. FE
    `src/pages/feed/PostCard.tsx`: `const isLocked = !!post.locked && !post.unlocked;`.
13. **No server `currency` field; UI assumes USD.** CORRECTED (spec modelled `currency`).
    FE `src/pages/feed/PostCard.tsx` hardcodes `"$… USD"` for the unlock price; no
    `currency` member on `FeedPost`.
14. **No server `teaser_text`.** CORRECTED. Absent from `src/api/types.ts: FeedPost`.
15. **`liked_by_me`, `like_count`, `comment_count` exist on the feed item.** VERIFIED. FE
    `src/api/types.ts: FeedPost.liked_by_me?` (optional), `.like_count`, `.comment_count`.
16. **Auth = cookie session + `Authorization: Bearer` + `X-CSRF-Token`, not cookies
    alone.** CORRECTED (spec said "cookie-gated"). FE `src/api/client.ts`: sets
    `Authorization: Bearer <accessToken>` from auth store, `X-CSRF-Token` from the `ui_csrf`
    cookie, and `credentials: "include"`. OpenAPI `GET /feed` also lists optional headers
    `X-SESSION-ID`, `X-IMPERSONATION-TOKEN` and query `user_sub`.
17. **401 → single `POST /ui/session/refresh` then one retry.** VERIFIED. FE
    `src/api/client.ts: refreshSession()` posts `/ui/session/refresh`, then retries the
    original request once.
18. **422 body is `HTTPValidationError` with `detail: ValidationError[]` (`{loc,msg,type}`);
    403/401 `detail` may be a string or an object (`{code: ...}`).** VERIFIED. OpenAPI
    `components.schemas.HTTPValidationError` / `ValidationError`; FE
    `src/api/client.ts: normalizeErrorDetail` handles string, array-of-`{msg}`, and object
    (`mapAuthorizationError` reads `detail.code` e.g. `geo_blocked`, `role_required`).
19. **Unlock error codes (for downstream, not this slice):** `unlock_limit_reached`,
    `post_lock_expired`, `unlock_attempt_throttled`. VERIFIED. FE
    `src/pages/feed/PostCard.tsx: unlockMutation.onError`.
20. **Stack/framework choices (Retrofit 2.11, OkHttp 4.12, Moshi 1.15 + KSP, Hilt,
    Coroutines).** UNVERIFIED-assumption (not derivable from backend/FE sources; standard
    Android networking stack). framework ref: Moshi codegen
    https://github.com/square/moshi#codegen ; Retrofit https://square.github.io/retrofit/ .
21. **Mapper redaction: null the media `url` for locked posts (stricter than web).**
    UNVERIFIED-assumption (a design choice for this port). Web instead keeps the URL and
    CSS-blurs it (FE `src/pages/feed/PostCard.tsx` uses `blur-sm`/`blur-lg`). Safe because
    redaction is a superset of hiding.

### Corrections made

- Endpoint path `ui/newsfeed` → `GET /feed` (§1, §2, §4, §5). [claims 1–2]
- Removed fabricated `filter` param; added the real `author_id`/`q`/`from`/`to`/`has_media`
  optional filters; documented `limit` (OpenAPI-only) (§4, §5, AC-1). [claims 3–5]
- Envelope: removed `has_more`; end-of-feed is `next_cursor == null` (§4, §5, §6, AC-2).
  [claim 6]
- Rewrote `PostDto`/domain `FeedPost`: `post_id`, `author_id` (no nested author), `body`
  (not `text`), `image_urls` + `video` (no `media[]`/`preview_url`/dimensions) (§4). [7–10]
- Replaced nested `PaywallDto`/`Paywall.Purchased`/`currency`/`teaser_text` with the real
  flat lock fields and a derived `Paywall.{Unlocked,Locked}` + `LockType` enum; collapsed
  `MediaAccess` from 3 states to `{ACCESSIBLE, LOCKED}` (no preview/teaser state exists)
  (§4, §7, §8, §9, §11, §13, AC-3/AC-4/AC-6). [11–14]
- Auth description: cookie + Bearer + CSRF (not cookie-only) (§2, §8). [16]
- Error-mapping note: 422 array vs 403 string/object detail forms (§5, §11). [18]

### Open assumptions

- **Whether the backend withholds media URLs for not-yet-unlocked posts**, or relies on the
  client to blur. Cannot be confirmed from sources: OpenAPI's `GET /feed` 200 schema is
  untyped `{}`, and the dev host is unreliable for live capture. Mapper redacts regardless,
  so behaviour is safe either way; a captured real locked-post sample is the follow-up.
- **`currency`**: no server field; USD assumed (web does the same). If the backend later
  emits a currency, add it to the DTO — single change point.
- **Networking-stack versions/libraries** (claim 20): a port-level decision, not validated
  against backend/FE; standard choices, flagged for tech-lead confirmation.
- **`liked_by_me` is optional** in the FE type; safe default `false` assumed when absent.

## 17. Test Plan

Acceptance traces refer to §14 (AC-1…AC-6). Targets: JVM = JVM/Robolectric unit (no
device); MWS = MockWebServer contract test (JVM); emulator = AVD `test35` (API 35 x86_64);
device = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This slice is
non-UI/non-device by nature; almost all cases run on the JVM/MWS. Device/emulator cases are
included only where ABI/cleartext/real-host behaviour genuinely differs.

- **TC-AND-097-01** — Type: contract/MockWebServer. Target: MWS (JVM). Preconditions:
  `FeedApi` wired to a MockWebServer base URL. Steps: enqueue the §5 200 body; call
  `getFeed(cursor="c1", limit=20)`. Expected: exactly one request, method `GET`, path
  `/feed`, query contains `cursor=c1` and `limit=20`; deserializes to a `FeedPageDto` with 2
  items. Traces: AC-1, AC-2.
- **TC-AND-097-02** — Type: contract/MockWebServer. Target: MWS. Preconditions: authenticated
  OkHttp client (Bearer + CSRF interceptors from AND-027) pointed at MWS. Steps: enqueue any
  200; call `getFeed()`. Expected: outgoing request carries `Authorization: Bearer …` and
  `X-CSRF-Token` headers (and no `filter` query param is ever sent). Traces: AC-1.
- **TC-AND-097-03** — Type: unit (mapper). Target: JVM. Preconditions: none. Steps: map an
  unlocked post (`locked=false`, `image_urls=["…/m1.jpg"]`). Expected: `Paywall.Unlocked`;
  one `Media(type=IMAGE, access=ACCESSIBLE, url="…/m1.jpg")`; `id` from `post_id`. Traces:
  AC-3, AC-4.
- **TC-AND-097-04** — Type: unit (mapper). Target: JVM. Preconditions: none. Steps: map a
  locked, not-unlocked post (`locked=true, unlocked=false, lock_type="fixed_price",
  unlock_price_cents=499, unlock_limit=500, unlock_count=230, unlock_limit_reached=false,
  lock_expired=false`, with a `video`). Expected:
  `Paywall.Locked(lockType=FIXED_PRICE, priceCents=499, unlockCount=230, unlockLimit=500,
  unlockLimitReached=false, lockExpired=false)`; media `access=LOCKED`, `url==null`. Traces:
  AC-3, AC-4 (core acceptance bullet).
- **TC-AND-097-05** — Type: unit (mapper). Target: JVM. Steps: map a locked-but-`unlocked=true`
  post. Expected: `Paywall.Unlocked`; media `access=ACCESSIBLE`, url preserved. Traces:
  AC-3, AC-4.
- **TC-AND-097-06** — Type: unit (mapper). Target: JVM. Steps: map `lock_type="tip_lottery"`
  (locked) and a locked post with unknown `lock_type` but `unlock_price_cents>0`. Expected:
  former → `LockType.TIP_LOTTERY`; latter → `LockType.FIXED_PRICE` (price-implies-fixed
  fallback). Traces: AC-3, AC-6.
- **TC-AND-097-07** — Type: unit (mapper). Target: JVM. Steps: map a body with an unknown
  extra JSON key, an unknown `lock_type` string with no price, and a malformed `created_at`.
  Expected: no exception; unknown key ignored; `lockType=UNKNOWN`; `createdAt=Instant.EPOCH`.
  Traces: AC-6.
- **TC-AND-097-08** — Type: unit (mapper/pagination). Target: JVM. Steps: map an envelope
  with `next_cursor` present, then one with it absent. Expected: `FeedPage.nextCursor`
  equals the value, then `null` (end of feed); no `has_more` is read. Traces: AC-2.
- **TC-AND-097-09** — Type: contract/MockWebServer + integration. Target: MWS. Preconditions:
  `FeedRepository` + shared `ApiErrorMapper`. Steps: for each enqueued response — 200 body,
  `422` `HTTPValidationError` (`detail:[{loc,msg,type}]`), `403` string `detail`, `403`
  object `detail` `{"code":"geo_blocked"}`, `500`, and a simulated `IOException`/timeout —
  call `getFeedPage()`. Expected: `Success<FeedPage>` for 200; `ApiError.Validation` /
  `Forbidden` / `Forbidden` / `Server` / `Network` respectively, each preserving the parsed
  detail. Traces: AC-5.
- **TC-AND-097-10** — Type: contract/MockWebServer. Target: MWS. Preconditions: structurally
  invalid JSON enqueued (e.g. `items` is a number). Steps: call `getFeedPage()`. Expected:
  `ApiError.Parse` (mapped from `JsonDataException`), not a crash. Traces: AC-5, AC-6.
- **TC-AND-097-11** — Type: integration (offline/flaky-host). Target: JVM (MWS with throttle/
  disconnect). Preconditions: MWS configured to drop the socket / delay beyond the ~20s
  timeout for the first 2 attempts then succeed. Steps: call `getFeedPage()` with the shared
  bounded-backoff retry policy. Expected: transient failures are retried (≤3 attempts) and
  the eventual 200 yields `Success`; if all attempts fail, terminal `ApiError.Network`. (No
  partial/locked data is emitted on failure.) Traces: AC-5.
- **TC-AND-097-12** — Type: unit (security/redaction). Target: JVM. Preconditions: a locked,
  not-unlocked post whose JSON still contains real `image_urls`/`video.thumbnail_url` (a
  simulated backend "leak"). Steps: map it. Expected: every resulting `Media.url == null`
  and `access == LOCKED`; the raw paid URL never appears on any domain object. Traces:
  AC-4 (defense-in-depth, §8).
- **TC-AND-097-13** — Type: unit (security/logging). Target: JVM. Preconditions: a fake
  `Logger`. Steps: run `getFeedPage()` success + error paths and capture emitted logs.
  Expected: no media URL and no post `body` at info level; only ids, counts, and
  access/paywall enums; error log has `errorType`/`httpStatus` but no response body. Traces:
  AC-5 (§8/§10).
- **TC-AND-097-14** — Type: instrumented/e2e (smoke). Target: PHYSICAL DEVICE (SM-A156U,
  arm64-v8a, API 34) — MUST run on device, not the x86_64 emulator, to validate the real
  arm64 ABI build, Moshi-KSP-generated adapters at runtime, and that the release/dev network
  config permits the cleartext dev host. Preconditions: app built for arm64-v8a, signed-in
  session, reachable dev backend (or an on-device MWS). Steps: invoke `FeedRepository
  .getFeedPage()` from an instrumented harness; observe one real network round-trip.
  Expected: a non-empty `FeedPage` deserializes with paywall/access correctly derived on the
  device runtime; no `NoClassDefFound`/codegen-adapter failures specific to arm64. (Run the
  same case on emulator `test35` to catch API-34-vs-35 / x86-vs-arm differences.) Traces:
  AC-2, AC-3.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-02 |
| AC-2 | TC-01, TC-08, TC-14 |
| AC-3 | TC-03, TC-04, TC-05, TC-06, TC-14 |
| AC-4 | TC-03, TC-04, TC-05, TC-12 |
| AC-5 | TC-09, TC-10, TC-11, TC-13 |
| AC-6 | TC-06, TC-07, TC-10 |
