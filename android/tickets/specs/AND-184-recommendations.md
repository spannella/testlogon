---
id: AND-184
title: Recommendations
milestone: M4
epic: E25
priority: P2
size: M
depends_on: [AND-182]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-184 — Recommendations

## 1. Overview & Goal

Add personalized **Recommendations** rows to the Discover surface of the TestLogon
native Android app. The web reference app exposes a `recommendations.ts` API module.
**CORRECTION (verified against `recommendations.ts` + OpenAPI):** the primary
recommendations surface is **not** a set of nested titled "rows". The web `ForYouTab`
calls `GET /ui/videos/gallery/for-you` and renders a **single flat, cursor-paginated
grid** of `RecommendedVideo` items (`ForYouResponse { videos[], next_cursor?, source }`).
"Similar Videos" and "Creator Suggestions" are *separate* single-section calls
(`/ui/videos/{id}/similar`, `/ui/discover/creators`), each rendered as one titled block —
again, not a server-driven list of rows. The "rows / carousels" framing throughout this
spec is a **planning abstraction**, not a backend contract: the Android implementation
may compose For-You / Similar / Creators as up to three client-defined sections, but the
backend returns flat per-feed lists, and each section maps to a distinct endpoint. This
ticket ports that capability: fetch the For-You feed (and optionally the Similar/Creators
feeds) from the backend, model them in `core-model`, expose them through a Repository +
ViewModel in the `feature-discover` module, and render them above/within the existing
Discover grid built in **AND-182**. Wherever this spec says "row(s)" below, read it as
"client-composed recommendation section(s)" unless a server field is explicitly named.

The goal is a working, testable Recommendations experience: when the user opens
Discover, their recommended rows render with title, poster art, and tap-through
navigation to detail. The scope is intentionally narrow — *rows render* — and
explicitly excludes the curated/discover grid itself (owned by AND-182), the detail
screen, and any "because you watched" explainability beyond a row title string.

Success = recommended items render in correctly titled rows, are scrollable, navigate
on tap, and degrade gracefully (skeleton → content, empty, offline/stale, error)
without blocking the rest of the Discover screen.

## 2. Context & References

- **Web reference:** `src/api/endpoints/recommendations.ts` is the authoritative
  request/response source. **CORRECTION (verified):** the DTO types live *inside*
  `recommendations.ts` itself (`RecommendedVideo`, `ForYouResponse`,
  `SimilarVideosResponse`, `CreatorSuggestionsResponse`) — there is **no**
  `RecommendationRow`/`MediaItem` type in `src/api/types.ts`. The consuming screens are
  `src/pages/videos/ForYouTab.tsx`, `SimilarVideos.tsx`, and `CreatorSuggestions.tsx`.
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json`. **CORRECTION (verified):** there
  is **no** `GET /ui/recommendations` endpoint. The recommendation feed the web app calls
  is `GET /ui/videos/gallery/for-you` (`op=for_you_endpoint…`, `resp=200:ForYouResponse`).
  Related endpoints: `GET /ui/videos/{video_id}/similar` (`SimilarVideosResponse`),
  `GET /ui/discover/creators` (`CreatorSuggestionsResponse`),
  `POST /ui/recommendations/engagement` (`req=EngagementIn`), and the internal
  `POST /internal/recommendations/refresh`. The `detail` error envelope is the standard
  FastAPI `HTTPValidationError` (422) shape — see §16.
- **Depends on AND-182 (Discover screen):** provides `feature-discover`, the Discover
  `Screen`/`ViewModel`/route, the reusable `MediaCard` composable, image loading via
  Coil, and the navigation contract to the media detail route. AND-184 *adds* rows to
  the already-rendering Discover scaffold; it must not fork or duplicate that scaffold.
- **AND-027 / AND-103** (transitive, via AND-182): core-network `ApiResult<T>` plumbing,
  cookie jar + CSRF interceptor, and the shared media card / image pipeline. Reused as-is.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Coil, Paging 3 (not used
  here — see §6), minSdk 24 / targetSdk 35, JDK 17.
- **Namespace:** `com.testlogon.android` everywhere.

## 3. Functional Requirements

FR-1. On entering Discover, the app requests recommendation rows for the authenticated
user and renders each non-empty row as a labeled horizontal carousel.

FR-2. Each row displays its server-provided `title` and a horizontally scrollable
`LazyRow` of media cards (poster image + title), reusing `MediaCard` from AND-182.

FR-3. Rows render in the server-provided order. Within a row, items render in
server-provided order. An empty row (zero items) is dropped, not rendered as a blank label.

FR-4. Tapping a card navigates to the media detail route via the navigation contract
established in AND-182, passing the item's `video_id`. **NOTE (unverified):** the exact
Android route name (`media/{mediaId}` as written, vs. the web route `/gallery/{video_id}`)
is owned by AND-182 and could not be confirmed from the reference (no `media/` route exists
in the web app; the web uses `/gallery/{video_id}`). Use whatever route AND-182 actually
exposes; AND-184 only emits the navigation event with the `video_id` and does not own the
detail screen.

FR-5. Recommendations load **independently** of the Discover grid. A failure or slow
response in recommendations must not block the grid, and vice versa. The two compose
into one scrollable Discover screen.

FR-6. Loading state shows shimmer/skeleton card placeholders (a fixed count, e.g. 6 per
row, 1–2 rows) until data or terminal state arrives.

FR-7. Empty state: if the user has *zero* recommendation rows, the Recommendations
section renders nothing (collapses) — Discover still shows its grid.

FR-8. Stale/offline: if a cached snapshot exists and the network fetch fails, render the
cached rows with a non-blocking "Showing saved recommendations" stale indicator.

FR-9. Error (no cache, fetch failed): render a compact inline retry affordance scoped to
the Recommendations section only — never a full-screen error that hides the grid.

FR-10. Pull-to-refresh on Discover (provided by AND-182) re-triggers recommendation fetch.

## 4. Technical Design

All new code lives in `com.testlogon.android.feature.discover.recommendations`
(feature-discover module) plus models in `core-model` and a DTO/service in `core-network`.

### 4.1 Module placement
- `core-model`: domain models `RecommendationRow`, `RecommendationItem`.
- `core-network`: `RecommendationsService` (Retrofit), `RecommendationRowDto`,
  `RecommendationItemDto`, mappers.
- `core-data`: `RecommendationsRepository` (+ impl), optional Room cache entity/DAO.
- `feature-discover`: `RecommendationsViewModel`, `RecommendationsSection` composable,
  `RecommendationRowUi` / `RecommendationItemUi` UI models, `RecommendationsUiState`.

### 4.2 Domain models (`core-model`)
```kotlin
data class RecommendationRow(
    val id: String,
    val title: String,
    val items: List<RecommendationItem>,
)

data class RecommendationItem(
    val id: String,            // == server `video_id`; used for navigation
    val title: String,
    val posterUrl: String?,    // == server `thumbnail_url`; nullable -> placeholder art
    val reason: String?,       // == server `recommendation_reason` (CORRECTED: this field
                               // exists; resolves OQ1). Optional subtitle.
)
```
**CORRECTION:** the earlier `kind: MediaKind` field is removed — the backend
`RecommendedVideoItem` has **no** `kind` field (verified). All recommended items are
videos; navigation uses `video_id`. Drop the OQ2 assumption about a `kind` enum.

### 4.3 Repository (`core-data`)
```kotlin
interface RecommendationsRepository {
    /** Cold flow: emits cached rows immediately (if any), then network result. */
    fun recommendations(forceRefresh: Boolean = false): Flow<ApiResult<List<RecommendationRow>>>
}

class RecommendationsRepositoryImpl @Inject constructor(
    private val service: RecommendationsService,
    private val cache: RecommendationsCacheDao,   // Room; see §6
    @IoDispatcher private val io: CoroutineDispatcher,
) : RecommendationsRepository
```
The repo emits a `ApiResult.Loading`/cached `Success(stale=true)` first, then performs
the network call, maps DTO→domain, writes-through to cache, and emits the fresh result.

### 4.4 ViewModel (`feature-discover`)
```kotlin
@HiltViewModel
class RecommendationsViewModel @Inject constructor(
    private val repo: RecommendationsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<RecommendationsUiState>(RecommendationsUiState.Loading)
    val state: StateFlow<RecommendationsUiState> = _state.asStateFlow()

    private val refreshTrigger = MutableSharedFlow<Boolean>(replay = 1)

    init { refresh(force = false) }

    fun refresh(force: Boolean) { refreshTrigger.tryEmit(force) }

    // refreshTrigger.flatMapLatest { repo.recommendations(it) } collected -> _state
}
```
`RecommendationsViewModel` is a *sibling* of the AND-182 `DiscoverViewModel`, scoped to
the same Discover nav entry; this keeps recommendation failures isolated from grid state.

### 4.5 UI state
```kotlin
sealed interface RecommendationsUiState {
    data object Loading : RecommendationsUiState
    data class Content(
        val rows: List<RecommendationRowUi>,
        val isStale: Boolean = false,
    ) : RecommendationsUiState
    data object Empty : RecommendationsUiState              // 0 rows, success
    data class Error(val message: String) : RecommendationsUiState  // no cache + failure
}
```

### 4.6 Composables (`feature-discover`)
```kotlin
@Composable
fun RecommendationsSection(
    state: RecommendationsUiState,
    onItemClick: (mediaId: String) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
)

@Composable
private fun RecommendationRowView(
    row: RecommendationRowUi,
    onItemClick: (String) -> Unit,
)   // Text(title) + LazyRow { items(row.items) { MediaCard(...) } }
```
`RecommendationsSection` is inserted into the AND-182 Discover `LazyColumn` as a leading
item (or items), so the whole screen scrolls vertically while rows scroll horizontally.
`MediaCard` and Coil `AsyncImage` config are imported from AND-182 / core-ui — no new
card component is introduced.

## 5. API Contract

**Primary endpoint (CORRECTED — verified against OpenAPI + `recommendations.ts`):**
`GET /ui/videos/gallery/for-you` (op `for_you_endpoint_ui_videos_gallery_for_you_get`,
`resp=200:ForYouResponse;422:HTTPValidationError`). The previously-assumed
`GET /ui/recommendations` **does not exist** and has been removed.

Optional secondary endpoints (only if this ticket also surfaces those sections):
- `GET /ui/videos/{video_id}/similar` → `SimilarVideosResponse` (params `video_id`, `limit`).
- `GET /ui/discover/creators` → `CreatorSuggestionsResponse` (param `limit`).

Auth (CORRECTED — verified in `src/api/client.ts`): the web client sends **both** the
session cookie jar **and** an `Authorization: Bearer <accessToken>` header **and**
`X-CSRF-Token` echoed from the `ui_csrf` cookie (plus `X-IMPERSONATION-TOKEN` when
impersonating). The original "cookie-authenticated only" claim was incomplete. The Android
core-network layer must attach the Bearer token (from AND-027 auth store) in addition to
cookies + CSRF. This is an idempotent GET, eligible for the bounded-backoff retry
policy (§7).

**Query params (CORRECTED):** `limit` (max items) and `cursor` (opaque pagination cursor).
There is **no** `row_limit` param — that was an unverified assumption and is removed.
Web `ForYouTab` calls with `limit=24`.

**Retrofit service (`core-network`):**
```kotlin
interface RecommendationsService {
    @GET("ui/videos/gallery/for-you")
    suspend fun getForYou(
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): Response<ForYouResponseDto>

    // Optional, if Similar / Creators sections are in scope:
    @GET("ui/videos/{videoId}/similar")
    suspend fun getSimilar(
        @Path("videoId") videoId: String,
        @Query("limit") limit: Int? = null,
    ): Response<SimilarVideosResponseDto>
}
```

**Response (200) — actual JSON shape** (verified: schema `ForYouResponse`, items
`RecommendedVideoItem`; only `videos` is required, `source` defaults to `"for_you"`):
```json
{
  "videos": [
    {
      "video_id": "med_8sd9",
      "title": "Sample Title",
      "description": "optional",
      "thumbnail_url": "http://18.222.237.167:8000/media/med_8sd9/thumb.jpg",
      "duration_seconds": 212.0,
      "creator_id": "usr_123",
      "creator_name": "Jane",
      "view_count": 4210,
      "like_count": 88,
      "category": "tech",
      "created_at": 1717000000,
      "recommendation_reason": "Because you watched …"
    }
  ],
  "next_cursor": null,
  "source": "for_you"
}
```
Note `source` can be `"trending_fallback"` for new/cold-start users (web shows a
"Showing trending videos…" notice — this answers R3, see §13). `recommendation_reason`
**does** exist on the item (answers OQ1). There is **no** `kind`, `id`, or `poster_url`
field — the item id is `video_id` and the image field is `thumbnail_url`.

**DTOs + mapper (`core-network`) — CORRECTED to the real field names:**
```kotlin
@JsonClass(generateAdapter = true)
data class ForYouResponseDto(
    val videos: List<RecommendedVideoDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    val source: String = "for_you",
)

@JsonClass(generateAdapter = true)
data class RecommendedVideoDto(
    @Json(name = "video_id") val videoId: String,          // only required field
    val title: String = "",
    val description: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "creator_id") val creatorId: String = "",
    @Json(name = "creator_name") val creatorName: String = "",
    @Json(name = "view_count") val viewCount: Long = 0,
    @Json(name = "like_count") val likeCount: Long = 0,
    val category: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "recommendation_reason") val recommendationReason: String? = null,
)

fun RecommendedVideoDto.toDomain() = RecommendationItem(
    id = videoId,                  // video_id is the nav id
    title = title,
    posterUrl = thumbnailUrl,      // server field is thumbnail_url
    reason = recommendationReason,
)
```
(There is no nested-row DTO because the backend returns a flat `videos` list per feed; the
"row" grouping, if any, is composed client-side per endpoint — see §1/§4 corrections.)

**Error envelope (FastAPI):** the 422 response is `HTTPValidationError`
(`{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }`). The shared
`ApiResult` error mapper from AND-027 already normalizes `detail` (string |
`[{loc,msg,type}]` | `{...}`). A `401` triggers the single `POST /ui/session/refresh`
(verified: `op=ui_session_refresh…`, POST, no request body) + retry path owned by the auth
interceptor; AND-184 does not implement refresh itself.

## 6. Data & State Management

- **StateFlow:** `RecommendationsViewModel.state: StateFlow<RecommendationsUiState>` is
  the single source of truth for the section; Compose collects via
  `collectAsStateWithLifecycle()`.
- **Caching (Room, `core-data`):** a small write-through cache enables FR-8 (offline/stale).
  ```kotlin
  @Entity(tableName = "recommendation_rows")
  data class RecommendationRowEntity(
      @PrimaryKey val id: String,
      val title: String,
      val position: Int,
      val itemsJson: String,        // Moshi-serialized List<RecommendedVideoDto>
      val fetchedAtEpochMs: Long,
  )

  @Dao interface RecommendationsCacheDao {
      @Query("SELECT * FROM recommendation_rows ORDER BY position")
      fun observe(): Flow<List<RecommendationRowEntity>>
      @Transaction suspend fun replaceAll(rows: List<RecommendationRowEntity>)
  }
  ```
  Cache TTL: treat rows older than **6 h** as stale-on-load (still shown, flagged
  `isStale`); always background-refresh on screen entry. `replaceAll` clears + inserts in
  one transaction to avoid mixed-version rows.
- **DataStore:** not required; no user prefs introduced by this ticket.
- **Paging 3:** **not used.** Recommendation rows are small, bounded, server-curated lists
  (typically ≤ ~30 items/row); a `LazyRow` over an in-memory list is correct. Paging is N/A.
- **State transitions:** `Loading → Content(stale=true)` (cache hit) → `Content(stale=false)`
  (network) ; or `Loading → Content` (fresh) ; or `Loading → Empty` (0 rows) ; or
  `Loading → Error` (no cache + failure). Empty rows are filtered before state emission.
- **Recomposition:** UI models (`RecommendationRowUi`) are immutable `data class`es marked
  `@Immutable`; lists keyed by `row.id` and `item.id` in `items(key = ...)` for stable
  diffing and scroll-position retention.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the shared OkHttp client (~20 s call timeout per project policy);
  no per-call override.
- **Retry:** GET is idempotent → eligible for the shared bounded-backoff retry interceptor
  (e.g. up to 2 retries, jittered, for transient 5xx / IO errors). No retry on 4xx.
- **401:** handled upstream by the auth interceptor (single `session/refresh` + retry). If
  refresh fails, the repo surfaces an auth error → section shows `Error` with retry.
- **Failure isolation (FR-5):** the Recommendations `ApiResult` failure maps to the
  section-local `Error`/stale state; the Discover grid (AND-182) has its own independent
  state. One can succeed while the other fails.
- **Offline / unreliable dev host:** the dev backend is plaintext HTTP and flaky — design
  for it. On `IOException`/timeout with a cache present → `Content(isStale=true)` + banner.
  With no cache → `Error("Couldn't load recommendations")` + inline Retry that calls
  `viewModel.refresh(force = true)`.
- **Malformed/partial data:** Moshi parse failure for a row/item → drop that row/item
  (defensive `try`/`filter`) rather than failing the whole section; null `posterUrl` →
  Coil placeholder. If *all* rows fail to parse → `Empty`.

## 8. Security & Privacy

- **Transport:** dev backend is HTTP; production must be HTTPS. Cleartext is permitted only
  for the dev host via the existing `network_security_config.xml` (owned by core-network);
  AND-184 adds no new cleartext domains.
- **Auth:** requests carry the persistent cookie jar + `X-CSRF-Token`; no tokens or
  credentials are introduced, logged, or persisted by this ticket.
- **PII:** recommendation rows are personalized — treat row/item payloads as user data.
  Do not log full payloads (see §10); the Room cache lives in app-private storage only and
  is cleared on logout (hook into the existing logout/cache-clear path from core-data).
- **Deep links:** navigation passes only an opaque `mediaId`; no sensitive data crosses the
  nav boundary.

## 9. Accessibility & i18n

- All visible strings (`row.title` is server-supplied; static strings like "Retry",
  "Showing saved recommendations", "Couldn't load recommendations") are in
  `strings.xml` (`feature-discover`) and localizable.
- Each `MediaCard` exposes a `contentDescription` of the item title; decorative shimmer
  placeholders are marked `Modifier.semantics { /* hidden */ }`.
- Row carousels are keyboard/D-pad and TalkBack traversable; the row title is a
  `heading()` semantics node so screen-reader users can navigate row-by-row.
- Touch targets ≥ 48 dp; text honors Dynamic Type / font scaling; layout reflows in RTL
  (LazyRow respects layout direction).
- Contrast: titles over poster art use the core-ui scrim/overlay token to meet WCAG AA.

## 10. Telemetry & Logging

Reuse the shared analytics abstraction (from core-ui/core-data); no new SDK.
- `rec_section_view` — emitted once per Discover entry when rows render
  (props: `row_count`, `is_stale`).
- `rec_row_impression` — per visible row (props: `row_id`, `item_count`).
- `rec_item_click` — on tap (props: `row_id`, `item_id`, `position_in_row`).
- `rec_load_error` — on terminal error (props: `error_kind` = timeout|http|parse|auth).
- **Logging:** `Timber` tags `Recommendations`; log counts and error kinds only — never
  full item payloads or poster URLs. Debug-build verbose; release strips per existing
  Timber config.

## 11. Testing Strategy

**Unit (core-testing + JUnit/Turbine/MockWebServer):**
- `RecommendationRowDto.toDomain()` mapping incl. null `posterUrl`, empty items, bad `kind`.
- `RecommendationsRepositoryImpl`: emits cached-then-fresh; on network failure with cache →
  stale Success; without cache → Error; write-through `replaceAll` invoked once on success.
- `RecommendationsViewModel`: `Loading → Content`, `→ Empty` (0 rows after filter),
  `→ Error`; `refresh(force=true)` re-triggers fetch; empty rows filtered out.
- MockWebServer: 200 happy path, 401-then-refresh-then-200, 500 (retry), malformed JSON
  (row dropped), timeout (stale/error branch).

**Compose UI (androidx.compose.ui.test):**
- `RecommendationsSection` renders N titled rows; shows shimmer in `Loading`; collapses in
  `Empty`; shows stale banner when `isStale`; shows inline Retry in `Error` and invokes
  `onRetry`.
- Tapping a card invokes `onItemClick(mediaId)` with the correct id.
- Section failure does not remove/hide the Discover grid (integration test with AND-182).

**Acceptance harness:** verify against dev host `http://18.222.237.167:8000` that real
rows render and tap navigates.

Target: ≥ 80% line coverage on new repo/VM/mapper code.

## 12. Dependencies & Sequencing

- **Blocked by AND-182 (Discover screen):** requires the Discover module scaffold, the
  `MediaCard` composable, the Coil image pipeline, the navigation contract to
  `media/{mediaId}`, and pull-to-refresh. AND-184 cannot merge before AND-182.
- **Transitive:** AND-027 (`ApiResult`/network core), AND-103 (media card / image pipeline)
  — consumed via AND-182; no direct new work.
- **Blocks:** none currently.
- **Sequencing within AND-184:** (1) core-model + DTOs + mapper, (2) `RecommendationsService`
  + repo + Room cache, (3) ViewModel + UI state, (4) `RecommendationsSection` composable
  wired into the AND-182 Discover screen, (5) tests + telemetry.

## 13. Risks & Open Questions

- **R1 — API shape (RESOLVED in review):** path and fields are now confirmed —
  `GET /ui/videos/gallery/for-you` returning `ForYouResponse { videos[], next_cursor,
  source }`, items `RecommendedVideoItem` with `video_id`/`thumbnail_url`/
  `recommendation_reason` (no `rows`/`poster_url`/`kind`). DTOs in §5 reflect this. Residual
  risk is low; keep the DTO/service isolation so server changes stay contained.
- **R2 — Unreliable dev host:** flaky/plaintext backend makes manual acceptance noisy.
  Mitigation: Room stale cache + MockWebServer-driven CI tests as the source of truth.
- **R3 — Empty personalization for new users (PARTIALLY RESOLVED):** verified — the backend
  **already** handles cold-start server-side by returning `source: "trending_fallback"`
  with a populated `videos` list (the web shows a "Showing trending videos…" notice). So a
  truly empty (0-item) response is rare. Android should: (a) when `source ==
  "trending_fallback"`, show an equivalent non-blocking notice; (b) only when `videos` is
  empty, collapse the section per FR-7. The "generic/popular fallback" question is therefore
  largely answered by the backend; no extra client fallback needed.
- **OQ1 (RESOLVED):** Yes — the item payload includes `recommendation_reason` (verified in
  `RecommendedVideoItem` / `recommendations.ts`). Surface it as an optional per-item
  subtitle (mapped to `RecommendationItem.reason`).
- **OQ2 (RESOLVED):** There is **no** `kind` field on the item — all recommended items are
  videos. The `MediaKind` enum is not needed here; navigation uses `video_id`.

## 14. Acceptance Criteria

AC-1. (Source) **Recommended items render.** On Discover, recommendation items fetched from
`GET /ui/videos/gallery/for-you` (CORRECTED from `GET /ui/recommendations`) render as
media cards (thumbnail + title) in server order, grouped into the client-composed
recommendation section(s) (For-You, and optionally Similar/Creators).
AC-2. Tapping a recommended item navigates to the AND-182 media detail route, passing the
item's `video_id` (CORRECTED from the unverified `media/{mediaId}` literal — route name is
owned by AND-182).
AC-3. Loading shows skeleton placeholders; success replaces them with content.
AC-4. Zero rows → the Recommendations section renders nothing; the Discover grid still shows.
AC-5. Network failure **with** cache → cached rows render with a stale indicator; **without**
cache → inline section-scoped error with a working Retry; in both cases the Discover grid is
unaffected.
AC-6. Empty/malformed rows or items are filtered out, not rendered as blanks; null poster →
placeholder image.
AC-7. Pull-to-refresh re-fetches recommendations.
AC-8. Unit + Compose tests for mapper, repo, ViewModel, and section cover happy/empty/
stale/error/parse-failure paths and pass in CI.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android` with models in core-model,
  service/DTOs/mappers in core-network, repo + Room cache in core-data, and ViewModel +
  `RecommendationsSection` in feature-discover, wired into the AND-182 Discover screen.
- All AC-1…AC-8 demonstrably met against the dev backend and via tests.
- Unit + Compose UI tests added and green in CI; new code ≥ 80% coverage.
- Telemetry events (`rec_*`) emitted; no payload/PII in logs.
- Strings externalized + localizable; TalkBack/D-pad traversal and ≥ 48 dp targets verified.
- `./gradlew :feature-discover:lint :feature-discover:testDebugUnitTest` and detekt/ktlint
  pass with no new warnings.
- API path/field names verified against `/openapi.json` and `recommendations.ts`; any
  divergence reflected only in the DTO/service layer.
- Failure isolation confirmed: a recommendations failure never blocks or hides the Discover
  grid.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Recommendations endpoint is `GET /ui/recommendations`.** VERDICT: **Corrected** — no
   such endpoint exists. The real feed endpoint is `GET /ui/videos/gallery/for-you`.
   SOURCE: OpenAPI `GET /ui/videos/gallery/for-you`
   (`op=for_you_endpoint_ui_videos_gallery_for_you_get`, `resp=200:ForYouResponse`);
   `src/api/endpoints/recommendations.ts: getForYou` (`api.get("/ui/videos/gallery/for-you")`).
2. **Response is `{ rows: [{ id, title, items[] }] }`.** VERDICT: **Corrected** — the
   response is a flat `ForYouResponse { videos: RecommendedVideoItem[], next_cursor?, source }`;
   there is no nested "rows" concept. SOURCE: OpenAPI schema `components.schemas.ForYouResponse`
   (required: `videos`; `source` default `"for_you"`); `src/api/endpoints/recommendations.ts: ForYouResponse`.
3. **Item fields are `id`, `title`, `poster_url`, `kind`.** VERDICT: **Corrected** — the item
   schema `RecommendedVideoItem` has `video_id` (only required), `title`, `description`,
   `thumbnail_url`, `duration_seconds`, `creator_id`, `creator_name`, `view_count`,
   `like_count`, `category`, `created_at`, `recommendation_reason`. No `id`, `poster_url`, or
   `kind`. SOURCE: OpenAPI schema `components.schemas.RecommendedVideoItem`;
   `src/api/endpoints/recommendations.ts: RecommendedVideo`.
4. **Query params `limit` and `row_limit`.** VERDICT: **Corrected** — params are `limit` and
   `cursor`; there is no `row_limit`. Web calls with `limit=24`. SOURCE: OpenAPI
   `GET /ui/videos/gallery/for-you | params=limit,cursor,…`;
   `src/api/endpoints/recommendations.ts: getForYou`; `src/pages/videos/ForYouTab.tsx` (`limit: 24`).
5. **HTTP method is GET (idempotent, retry-eligible).** VERDICT: **Verified.** SOURCE: OpenAPI
   `GET /ui/videos/gallery/for-you`.
6. **Auth is cookie-only (session cookies + `X-CSRF-Token` from `ui_csrf`).** VERDICT:
   **Corrected (incomplete)** — CSRF claim is right, but the web client also sends
   `Authorization: Bearer <accessToken>` and (when impersonating) `X-IMPERSONATION-TOKEN`.
   SOURCE: `src/api/client.ts` (lines ~157–171: `Authorization: Bearer`, `X-IMPERSONATION-TOKEN`,
   `X-CSRF-Token` from `getCookie("ui_csrf")`; `credentials: "include"`).
7. **`X-CSRF-Token` is echoed from the `ui_csrf` cookie.** VERDICT: **Verified.** SOURCE:
   `src/api/client.ts: getCookie("ui_csrf") -> headers.set("X-CSRF-Token", csrf)`.
8. **401 triggers a single `POST /ui/session/refresh` + retry, owned by the interceptor.**
   VERDICT: **Verified.** SOURCE: `src/api/client.ts: refreshSession()` (POST
   `/ui/session/refresh`, single-flight via `refreshPromise`, one retry then `logout`);
   OpenAPI `POST /ui/session/refresh` (`op=ui_session_refresh…`, no request body).
9. **Error envelope is FastAPI `detail` (string | `[{msg}]` | `{code,…}`).** VERDICT:
   **Verified (refined)** — the 422 schema is `HTTPValidationError` with
   `detail: [{loc, msg, type}]`. SOURCE: OpenAPI `resp=…;422:HTTPValidationError` on the feed
   endpoint; `components.schemas.HTTPValidationError`; `src/api/client.ts: normalizeErrorDetail`.
10. **Item payload contains an explanation/reason string (OQ1).** VERDICT: **Verified (present)** —
    field `recommendation_reason`. SOURCE: OpenAPI `RecommendedVideoItem.recommendation_reason`;
    `src/api/endpoints/recommendations.ts: RecommendedVideo.recommendation_reason`.
11. **Item `kind` enum matching AND-182 `MediaKind` (OQ2).** VERDICT: **Corrected** — no `kind`
    field exists; all items are videos. SOURCE: OpenAPI `RecommendedVideoItem` (no `kind`).
12. **Image field on the item.** VERDICT: **Corrected** — it is `thumbnail_url`, not
    `poster_url`. SOURCE: OpenAPI `RecommendedVideoItem.thumbnail_url`;
    `src/pages/videos/SimilarVideos.tsx` (renders `v.thumbnail_url`, fallback "No thumbnail").
13. **Navigation route is `media/{mediaId}`.** VERDICT: **Unverified-assumption / likely wrong** —
    no `media/` route exists in the reference; the web detail route is `/gallery/{video_id}`.
    The Android route name is owned by AND-182 and not present in these sources; pass `video_id`.
    SOURCE: `src/pages/gallery/GalleryVideoCard.tsx` (`to={/gallery/${video.video_id}}`);
    `src/pages/videos/SimilarVideos.tsx` (`to={/gallery/${v.video_id}}`); grep for `media/` route → no match.
14. **Empty state behavior (0 items → collapse / "No recommendations yet").** VERDICT:
    **Verified.** SOURCE: `src/pages/videos/ForYouTab.tsx` (videos.length === 0 → "No
    recommendations yet" empty block).
15. **Cold-start fallback exists server-side.** VERDICT: **Verified** — `source ==
    "trending_fallback"` drives a "Showing trending videos…" notice with populated videos.
    SOURCE: `src/pages/videos/ForYouTab.tsx` (`source === "trending_fallback"` branch);
    OpenAPI `ForYouResponse.source` (default `"for_you"`).
16. **Engagement signal endpoint (telemetry-adjacent).** VERDICT: **Verified** —
    `POST /ui/recommendations/engagement` with body `EngagementIn { video_id (req), watch_pct?
    (0–100 int), liked? }`. SOURCE: OpenAPI `POST /ui/recommendations/engagement`
    (`req=EngagementIn`); `components.schemas.EngagementIn`; `src/api/endpoints/recommendations.ts: recordEngagement`.
17. **Web client list rendering is a flat grid, not server-driven titled rows.** VERDICT:
    **Verified.** SOURCE: `src/pages/videos/ForYouTab.tsx` (single `grid` of `GalleryVideoCard`);
    `SimilarVideos.tsx` / `CreatorSuggestions.tsx` are separate single-section components.
18. **`react-query` caches the feed with a `staleTime` (informs the Android cache-TTL design).**
    VERDICT: **Verified (web behavior).** SOURCE: `src/pages/videos/ForYouTab.tsx`
    (`staleTime: 5 * 60_000`); `SimilarVideos.tsx` (`staleTime: 10 * 60_000`). NOTE: the Android
    spec's 6-hour Room TTL (§6) is an Android-side design choice, not derived from the web value.
19. **Compose `collectAsStateWithLifecycle`, Hilt/KSP, Coil, Paging-not-used.** VERDICT:
    **Unverified-assumption (framework choices)** — reasonable Android stack decisions; not
    verifiable from backend/frontend sources. SOURCE: framework ref —
    https://developer.android.com/jetpack/compose/state and
    https://developer.android.com/develop/ui/compose/libraries (lifecycle/Hilt). Cursor pagination
    *is* supported by the API (`next_cursor`/`cursor`), so "Paging N/A" is a scope decision, not a
    contract limit.

### Corrections made
- Endpoint `GET /ui/recommendations` → `GET /ui/videos/gallery/for-you` (and named the real
  secondary endpoints) in §1, §2, §5, §13, AC-1.
- Response model `{rows:[{id,title,items}]}` → flat `ForYouResponse {videos[], next_cursor,
  source}`; rewrote DTOs/mapper in §5 and the entity comment in §6.
- Item fields: `id`→`video_id`, `poster_url`→`thumbnail_url`, removed `kind`, added
  `recommendation_reason` (§4.2, §5).
- Query params: removed non-existent `row_limit`; added `cursor` (§5).
- Auth: noted the additional `Authorization: Bearer` (+ `X-IMPERSONATION-TOKEN`) headers
  beyond cookies/CSRF (§5).
- Navigation: flagged `media/{mediaId}` as unverified (web uses `/gallery/{video_id}`); pass
  `video_id` (§FR-4, AC-2).
- Resolved OQ1 (reason present), OQ2 (no kind), and refined R1/R3 with verified facts.

### Open assumptions
- **Android detail route name** (`media/{mediaId}` vs other): owned by AND-182; not present in
  these sources. Must be confirmed against the AND-182 implementation when wiring navigation.
- **6-hour Room cache TTL** (§6): an Android design choice; the backend/web give no TTL contract
  (web uses react-query `staleTime` of 5–10 min, a different layer). Tunable.
- **Telemetry event names (`rec_*`)** (§10): internal to the Android analytics layer; not
  derivable from the reference. The only server-facing signal is `POST
  /ui/recommendations/engagement` (claim 16).
- **Whether AND-184 surfaces Similar/Creators sections at all**: ticket scope says "rows render";
  the For-You feed alone satisfies AC-1. Similar/Creators are optional and gated on product
  decision; DTOs/endpoints are documented for that case.
- **Framework stack choices** (Compose/Hilt/Coil/dispatcher injection): standard Android
  practice; framework refs only (see claim 19).

## 17. Test Plan

Test-case IDs `TC-AND-184-NN`. Targets: JVM/Robolectric (local), emulator AVD `test35`
(API 35 x86_64), or the physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34
arm64). Recommendations is a network-list + Compose feature with no camera/biometrics/WebRTC,
so most cases run JVM or on the emulator; the physical device is reserved for real-flaky-network
and arm64/API-34 verification.

- **TC-AND-184-01 — Happy path mapping (For-You).** Type: unit (JVM). Target: JVM unit.
  Preconditions: a captured `ForYouResponse` JSON fixture (videos with `video_id`,
  `thumbnail_url`, `recommendation_reason`). Steps: deserialize with Moshi → call
  `RecommendedVideoDto.toDomain()`. Expected: `RecommendationItem(id=video_id,
  posterUrl=thumbnail_url, reason=recommendation_reason)`; required-only payload (just
  `video_id`) maps with safe defaults. Traces: AC-1, AC-6.
- **TC-AND-184-02 — Contract: 200 happy path over MockWebServer.** Type: contract/MockWebServer.
  Target: JVM unit. Preconditions: MockWebServer returns 200 `ForYouResponse` (3 videos),
  `source:"for_you"`. Steps: `RecommendationsService.getForYou(limit=24)`; assert request path
  `/ui/videos/gallery/for-you?limit=24`, then map. Expected: 3 items in server order; verify the
  request carried cookie + `X-CSRF-Token` + `Authorization: Bearer` headers. Traces: AC-1.
- **TC-AND-184-03 — Trending fallback notice.** Type: unit + Compose-UI. Target: emulator
  `test35`. Preconditions: response `source:"trending_fallback"` with videos. Steps: drive
  `RecommendationsViewModel`→`Content`; render `RecommendationsSection`. Expected: items render
  AND a non-blocking "Showing trending videos…"-style notice appears; section does not collapse.
  Traces: AC-1, AC-3.
- **TC-AND-184-04 — Empty feed collapses.** Type: Compose-UI. Target: emulator `test35`.
  Preconditions: 200 with `videos: []`. Steps: render section in resulting `Empty` state inside a
  host that also renders a stub Discover grid. Expected: Recommendations section renders nothing
  (collapses); the stub grid remains visible. Traces: AC-4.
- **TC-AND-184-05 — Validation/error response (422).** Type: contract/MockWebServer. Target: JVM
  unit. Preconditions: MockWebServer returns 422 `HTTPValidationError`
  (`detail:[{loc,msg,type}]`). Steps: call service; run through AND-027 `ApiResult` mapper; no
  cache present. Expected: maps to `ApiResult` error → ViewModel `Error("Couldn't load
  recommendations")`; `detail` array normalized to a message; no crash. Traces: AC-5, AC-8.
- **TC-AND-184-06 — Malformed/partial JSON is defensively dropped.** Type: unit
  (Moshi/MockWebServer). Target: JVM unit. Preconditions: response where one video object is
  malformed/missing `video_id` and another is valid. Steps: parse + map with the defensive
  filter. Expected: bad item dropped, valid item retained; if all fail → `Empty`, not a thrown
  error. Traces: AC-6, AC-8.
- **TC-AND-184-07 — Null thumbnail → placeholder.** Type: Compose-UI. Target: emulator `test35`.
  Preconditions: item with `thumbnail_url: null`. Steps: render `MediaCard` via the section.
  Expected: Coil placeholder shown; no crash; `contentDescription` still set to the title.
  Traces: AC-6, AC-9 (a11y).
- **TC-AND-184-08 — Cached-then-fresh emission.** Type: unit (Turbine). Target: JVM/Robolectric.
  Preconditions: Room cache pre-populated; MockWebServer returns fresh 200. Steps: collect
  `repo.recommendations()`. Expected: emits cached `Content(isStale=true)` first, then network
  `Content(isStale=false)`; `replaceAll` called exactly once on success. Traces: AC-5, AC-8.
- **TC-AND-184-09 — Offline with cache → stale banner.** Type: integration (Robolectric +
  MockWebServer). Target: JVM/Robolectric. Preconditions: cache present; network forced to
  `IOException`/timeout (MockWebServer `NO_RESPONSE`/disconnect). Steps: trigger fetch. Expected:
  state stays `Content(isStale=true)`; UI shows "Showing saved recommendations" banner; no
  `Error`. Traces: AC-5.
- **TC-AND-184-10 — Real flaky/offline network on device.** Type: instrumented/e2e. Target:
  **PHYSICAL DEVICE (SM-A156U)** — MUST run on hardware: toggle real Wi-Fi/airplane mode against
  the plaintext dev host `http://18.222.237.167:8000` to exercise genuine DNS/timeout flakiness
  that the emulator's NAT masks. Preconditions: app logged in, cache previously warmed. Steps:
  open Discover online (rows load), enable airplane mode, re-enter Discover / pull-to-refresh.
  Expected: cached rows render with stale banner offline; on reconnect, fresh content replaces
  them; Discover grid never blocked. Traces: AC-5, AC-7.
- **TC-AND-184-11 — 401 → single refresh → retry success.** Type: contract/MockWebServer.
  Target: JVM unit. Preconditions: authenticated; queue 401, then `POST /ui/session/refresh`
  200, then feed 200. Steps: call through the auth interceptor. Expected: exactly one refresh,
  one retry, final success; on refresh failure → auth `Error` with working Retry. Traces: AC-5.
- **TC-AND-184-12 — Tap navigates with correct video_id.** Type: Compose-UI. Target: emulator
  `test35`. Preconditions: section in `Content` with known `video_id`. Steps: tap a card; capture
  `onItemClick`. Expected: `onItemClick(video_id)` invoked with the exact server `video_id`
  (verifies the `video_id`, not `poster_url`/`kind`, drives nav). Traces: AC-2.
- **TC-AND-184-13 — Failure isolation from Discover grid.** Type: integration/Compose-UI. Target:
  emulator `test35`. Preconditions: host renders AND-182 grid (stub Success) + Recommendations in
  `Error`. Steps: render combined Discover. Expected: inline section-scoped error + Retry shown;
  grid fully visible/scrollable; tapping Retry calls `viewModel.refresh(force=true)`. Traces:
  AC-5, AC-7.
- **TC-AND-184-14 — Accessibility: TalkBack traversal & touch targets.** Type: instrumented
  (a11y). Target: **PHYSICAL DEVICE (SM-A156U)** preferred (real TalkBack engine), emulator
  acceptable as fallback. Preconditions: section in `Content`. Steps: enable TalkBack; traverse
  the section. Expected: each card announces its title `contentDescription`; section/row title is
  a `heading()`; shimmer placeholders are not focusable; touch targets ≥ 48 dp. Traces: AC-9-class
  a11y requirements (§9), supports AC-1.
- **TC-AND-184-15 — Security: no PII/payload in logs; cache cleared on logout.** Type:
  instrumented. Target: emulator `test35`. Preconditions: logged-in session with cached rows.
  Steps: capture logcat during fetch; then log out. Expected: Timber logs contain only counts /
  error-kinds (no titles, no `thumbnail_url`, no `video_id` payloads); after logout the
  `recommendation_rows` Room table is empty (app-private storage). Traces: §8 security,
  supports AC-8.

### Coverage matrix
| AC (§14) | Covered by |
| --- | --- |
| AC-1 (items render in order) | TC-01, TC-02, TC-03, TC-14 |
| AC-2 (tap → detail w/ video_id) | TC-12 |
| AC-3 (loading → content) | TC-03 (and Loading state exercised in TC-04/TC-13 setups) |
| AC-4 (zero rows → collapse, grid shows) | TC-04 |
| AC-5 (failure: stale w/ cache, inline error w/o, grid unaffected) | TC-05, TC-08, TC-09, TC-10, TC-11, TC-13 |
| AC-6 (malformed/empty filtered, null poster → placeholder) | TC-01, TC-06, TC-07 |
| AC-7 (pull-to-refresh re-fetches) | TC-10, TC-13 |
| AC-8 (unit+Compose cover happy/empty/stale/error/parse) | TC-01, TC-05, TC-06, TC-08, TC-15 (+ all above) |
