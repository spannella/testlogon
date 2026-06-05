---
id: AND-097
title: Feed API + DTOs
milestone: M2
epic: E14
priority: P0
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-097 — Feed API + DTOs

## 1. Overview & Goal

This ticket delivers the network and data-mapping foundation for the TestLogon newsfeed on
the native Android port: a Retrofit `FeedApi`, the Moshi DTOs that mirror the backend feed
contract (`frontend/src/api/endpoints/newsfeed.ts` and `frontend/src/api/types.ts`), the
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
  (plaintext HTTP, unreliable dev host). The feed routes live under the newsfeed router.
- Web reference: `frontend/src/api/endpoints/newsfeed.ts` (endpoint signatures, query
  params), `frontend/src/api/types.ts` (`Post`, `MediaItem`, `Paywall`, pagination
  envelope). These are the authoritative shapes the DTOs must mirror.
- Auth/session: AND-027 supplies `AuthApi` and the cookie + `X-CSRF-Token` machinery; the
  same authenticated OkHttp client (persistent cookie jar, CSRF interceptor, 401→refresh)
  built in AND-026/AND-027 is reused. The feed is an authenticated, cookie-gated resource.
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
    @GET("ui/newsfeed")
    suspend fun getFeed(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = DEFAULT_PAGE_SIZE,
        @Query("filter") filter: String? = null, // e.g. "subscribed", "all"
    ): FeedPageDto

    companion object { const val DEFAULT_PAGE_SIZE = 20 }
}
```

The exact path (`ui/newsfeed` vs `newsfeed`) is resolved against `/openapi.json` and
`newsfeed.ts` at implementation time; the contract in §5 is authoritative if they diverge.
The `FeedApi` is provided via Hilt from the existing authenticated Retrofit instance
(`@Named("authenticated")` Retrofit from AND-026), so cookies, CSRF header, and 401→refresh
are inherited automatically.

### DTOs (`core-network`, Moshi `@JsonClass(generateAdapter = true)`)

```kotlin
@JsonClass(generateAdapter = true)
data class FeedPageDto(
    @Json(name = "items") val items: List<PostDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "has_more") val hasMore: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class PostDto(
    @Json(name = "id") val id: String,
    @Json(name = "author") val author: AuthorDto,
    @Json(name = "created_at") val createdAt: String, // ISO-8601
    @Json(name = "text") val text: String? = null,
    @Json(name = "media") val media: List<MediaDto> = emptyList(),
    @Json(name = "like_count") val likeCount: Int = 0,
    @Json(name = "comment_count") val commentCount: Int = 0,
    @Json(name = "liked_by_me") val likedByMe: Boolean = false,
    @Json(name = "paywall") val paywall: PaywallDto? = null,
)

@JsonClass(generateAdapter = true)
data class AuthorDto(
    @Json(name = "id") val id: String,
    @Json(name = "username") val username: String,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
)

@JsonClass(generateAdapter = true)
data class MediaDto(
    @Json(name = "id") val id: String,
    @Json(name = "type") val type: String? = null,     // "image" | "video"
    @Json(name = "url") val url: String? = null,        // null when withheld
    @Json(name = "preview_url") val previewUrl: String? = null,
    @Json(name = "width") val width: Int? = null,
    @Json(name = "height") val height: Int? = null,
    @Json(name = "duration_ms") val durationMs: Long? = null,
    @Json(name = "locked") val locked: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class PaywallDto(
    @Json(name = "locked") val locked: Boolean = false,
    @Json(name = "purchased") val purchased: Boolean = false,
    @Json(name = "price_cents") val priceCents: Int? = null,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "teaser_text") val teaserText: String? = null,
    @Json(name = "unlock_count") val unlockCount: Int? = null,
)
```

### Domain models (`core-model`)

```kotlin
data class FeedPage(val posts: List<FeedPost>, val nextCursor: String?, val hasMore: Boolean)

data class FeedPost(
    val id: String,
    val author: Author,
    val createdAt: Instant,
    val text: String?,
    val media: List<Media>,
    val likeCount: Int,
    val commentCount: Int,
    val likedByMe: Boolean,
    val paywall: Paywall,           // never null at domain level
)

data class Author(
    val id: String, val username: String,
    val displayName: String?, val avatarUrl: String?,
)

enum class MediaType { IMAGE, VIDEO, UNKNOWN }
enum class MediaAccess { ACCESSIBLE, LOCKED_TEASER, LOCKED }

data class Media(
    val id: String,
    val type: MediaType,
    val url: String?,
    val previewUrl: String?,
    val width: Int?, val height: Int?, val durationMs: Long?,
    val access: MediaAccess,
)

sealed interface Paywall {
    data object Unlocked : Paywall
    data class Locked(
        val priceCents: Int?, val currency: String?,
        val teaserText: String?, val unlockCount: Int?,
    ) : Paywall
    data class Purchased(val priceCents: Int?, val currency: String?) : Paywall
}
```

### Mapper (`core-network` → `core-model`, pure functions)

```kotlin
object FeedMapper {
    fun FeedPageDto.toDomain(): FeedPage
    fun PostDto.toDomain(): FeedPost
    fun MediaDto.toDomain(postLocked: Boolean): Media
    fun PaywallDto?.toDomain(): Paywall
}
```

Mapping rules:
- `PaywallDto?.toDomain()`: `null` or `locked=false` → `Unlocked`; `locked=true &&
  purchased=true` → `Purchased`; `locked=true && purchased=false` → `Locked(...)`.
- `MediaDto.toDomain(postLocked)`: `access = ACCESSIBLE` when `url != null && !locked &&
  !postLocked`; `LOCKED_TEASER` when locked but `previewUrl != null` (or width/height
  present); else `LOCKED`. When access != ACCESSIBLE the full `url` is forced to `null` even
  if the backend leaked one, so locked content can never be rendered from this layer.
- `type` unknown string → `MediaType.UNKNOWN`.
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

`GET /ui/newsfeed?cursor=<opaque>&limit=20&filter=all` — authenticated (cookie session +
`X-CSRF-Token`). Idempotent GET → eligible for bounded backoff retry per §7.

Example 200 response:

```json
{
  "items": [
    {
      "id": "post_01HZ...",
      "author": { "id": "u_42", "username": "creator", "display_name": "Creator",
                  "avatar_url": "http://18.222.237.167:8000/media/av_42.jpg" },
      "created_at": "2026-06-04T18:22:10Z",
      "text": "Full post body",
      "media": [
        { "id": "m1", "type": "image", "url": "http://.../m1.jpg",
          "width": 1080, "height": 1350, "locked": false }
      ],
      "like_count": 12, "comment_count": 3, "liked_by_me": true,
      "paywall": { "locked": false }
    },
    {
      "id": "post_01J0...",
      "author": { "id": "u_99", "username": "premium" },
      "created_at": "2026-06-04T17:00:00Z",
      "text": null,
      "media": [
        { "id": "m2", "type": "video", "url": null, "preview_url": "http://.../m2_blur.jpg",
          "width": 720, "height": 1280, "duration_ms": 45000, "locked": true }
      ],
      "like_count": 88, "comment_count": 20, "liked_by_me": false,
      "paywall": { "locked": true, "purchased": false, "price_cents": 499,
                   "currency": "USD", "teaser_text": "Unlock to view", "unlock_count": 230 }
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ==",
  "has_more": true
}
```

Error responses use the FastAPI `detail` shape and are mapped centrally:
`detail` may be a `string`, `[{ "msg": "...", "type": "..." }]`, or `{ "code": "...", ... }`.
Relevant statuses: `401` (session expired → client triggers single `POST /ui/session/refresh`
then retry, handled by the AND-027 interceptor), `403` (not entitled), `422` (bad
cursor/params), `5xx`/timeout (transient). The exact path and param names are reconciled
with `/openapi.json` and `newsfeed.ts`; if a discrepancy is found, the OpenAPI schema wins
and this section is updated in the same PR.

## 6. Data & State Management

This ticket introduces **no** persistent state (no Room, no DataStore writes) and **no**
`StateFlow<UiState>`; those belong to the repository-cache and ViewModel tickets in §12.
The unit of state produced is the in-memory `FeedPage` carrying `posts`, `nextCursor`, and
`hasMore`, which is the seam a later `PagingSource` will key on (`LoadResult.Page(data,
prevKey=null, nextKey=nextCursor)`).

Paging contract this slice must satisfy so downstream Paging 3 work is trivial:
`nextCursor == null || !hasMore` ⇒ end of pagination. `limit` defaults to 20 and is passed
through unchanged. Cursors are treated as opaque strings (never parsed client-side).

Identity & dedup: `FeedPost.id` is the stable key for later list diffing; the mapper
guarantees ids pass through verbatim. No client-side sorting is applied — server order is
preserved.

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
  unknown `type` strings degrade to `MediaType.UNKNOWN`; a malformed `created_at` degrades
  to `Instant.EPOCH` rather than failing the page. A `JsonDataException` on a structurally
  invalid body maps to `ApiError.Parse` (surfaced as a "couldn't load feed" state upstream).
- Locked-content safety net: any locked media has its `url` nulled by the mapper, so a
  backend leak cannot cause paid content to be fetched/rendered (defense in depth with §8).

## 8. Security & Privacy

- All feed access is over the authenticated cookie session; the persistent cookie jar and
  `X-CSRF-Token` echo are reused from AND-027 — no token handling is added here.
- Paywall enforcement is server-authoritative; the client trusts the server's `paywall` and
  `locked` flags and additionally refuses to expose full media URLs for non-`ACCESSIBLE`
  media (mapper-level redaction).
- Logs must never include full media URLs, `teaser_text`, or post body at info level; only
  ids, counts, and access enums (see §10).
- Dev backend is plaintext HTTP; this is a known dev-only condition. The release build's
  network security config (owned by the build/security tickets) must continue to forbid
  cleartext for production hosts; this ticket adds no new cleartext exemption.
- No PII is persisted by this slice (no caching introduced).

## 9. Accessibility & i18n

No UI is rendered in this ticket, so there are no Compose semantics, focus order, or
contrast concerns here — those are owned by the feed UI ticket (§12). Two data-shaping
obligations support downstream a11y/i18n:

- `priceCents` + `currency` are preserved as raw numeric + ISO-4217 code (no client-side
  formatting), so the UI layer can localize via `NumberFormat.getCurrencyInstance(locale)`.
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
   - Unlocked post → `Paywall.Unlocked`, media `access = ACCESSIBLE`, url preserved.
   - Locked unpurchased post → `Paywall.Locked(priceCents=499,currency="USD",...)`, media
     `access = LOCKED_TEASER`, `url == null`, `previewUrl` preserved. **(core acceptance:
     locked/paywall metadata mapped and tested.)**
   - Locked purchased post → `Paywall.Purchased`.
   - `paywall == null` → `Unlocked`.
   - Locked media with no preview → `access = LOCKED`, `url == null`.
   - Unknown `type` → `MediaType.UNKNOWN`; malformed `created_at` → `Instant.EPOCH`.
   - Unknown extra JSON field is ignored without error.
3. **Pagination tests**: `hasMore=false` and/or `next_cursor=null` ⇒ `FeedPage.nextCursor`
   reflects end-of-feed.
4. **Repository tests** (`FeedRepositoryTest`): success → `ApiResult.Success<FeedPage>`;
   `401`/`403`/`422`/`5xx`/`IOException` → correct `ApiError` variant via the shared
   `ApiErrorMapper`; FastAPI `detail` string/array/object forms all map.

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

- **Exact feed path & params**: `ui/newsfeed` vs `newsfeed`, and whether pagination is
  cursor- or offset-based, must be confirmed against `/openapi.json` and `newsfeed.ts`.
  Mitigation: keep the path/param surface in one Retrofit interface; reconcile in-PR.
- **Paywall field naming**: backend may use `price`/`amount` instead of `price_cents`, or a
  nested `entitlement` object. Mitigation: DTO `@Json` names are the single change point;
  mapper insulates the domain.
- **Locked-media URL semantics**: does the backend return `url=null` or a redacted/blurred
  URL for locked media? Mapper handles both; needs a captured real sample to confirm.
- **Unreliable dev host**: timeouts during test capture; use recorded fixtures so tests are
  deterministic and host-independent.
- Open question: is `liked_by_me` present on the feed endpoint or only on post-detail? If
  absent it safely defaults to `false`.

## 14. Acceptance Criteria

AC-1. `FeedApi.getFeed(cursor, limit, filter)` exists and, under MockWebServer, issues a
`GET` to the contracted path with the three query params correctly serialized.
AC-2. A full feed page deserializes into `FeedPage`/`FeedPost`/`Media`/`Author` with
`nextCursor` and `hasMore` populated.
AC-3. Locked/paywall metadata maps correctly and is unit-tested: locked-unpurchased →
`Paywall.Locked` with price/currency/teaser/unlock_count; purchased → `Paywall.Purchased`;
absent/false → `Paywall.Unlocked`. (Directly satisfies the source acceptance bullet.)
AC-4. Locked media yields `MediaAccess.LOCKED`/`LOCKED_TEASER` with `url == null`; accessible
media yields `ACCESSIBLE` with `url` preserved.
AC-5. `FeedRepository.getFeedPage(...)` returns `ApiResult.Success<FeedPage>` on 200 and the
correct `ApiError` variant for 401/403/422/5xx/network/parse failures.
AC-6. Mapping tolerates unknown JSON fields, unknown media types, and malformed timestamps
without throwing; all `FeedMapper` branches are covered.

## 15. Definition of Done

- DTOs, `core-model` types, `FeedMapper`, `FeedApi`, and `FeedRepository` implemented in the
  correct modules under `com.testlogon.android.*`, provided via Hilt from the authenticated
  Retrofit instance.
- All §11 tests written and green in CI; `FeedMapper` branch coverage at 100%.
- No new cleartext network exemptions; no PII or media URLs/body/teaser logged at info level.
- No UI, Paging, or caching code introduced (correctly deferred to the §12 downstream
  tickets) and the repository seam documented for them.
- Builds clean with KSP Moshi codegen on JDK 17 / Gradle 8.9 / AGP 8.7.3; merged to
  `android-port` with the §5 contract reconciled against `/openapi.json`.
