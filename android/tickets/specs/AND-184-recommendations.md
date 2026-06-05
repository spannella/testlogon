---
id: AND-184
title: Recommendations
milestone: M4
epic: E25
priority: P2
size: M
status: draft
depends_on: [AND-182]
blocks: []
---

# AND-184 — Recommendations

## 1. Overview & Goal

Add personalized **Recommendations** rows to the Discover surface of the TestLogon
native Android app. The web reference app exposes a `recommendations.ts` API module
that returns one or more *rows* (named, ordered carousels) of recommended items
tailored to the authenticated user. This ticket ports that capability: fetch the
recommendation rows from the backend, model them in `core-model`, expose them through
a Repository + ViewModel in the `feature-discover` module, and render them as
horizontally scrolling carousels above/within the existing Discover grid built in
**AND-182**.

The goal is a working, testable Recommendations experience: when the user opens
Discover, their recommended rows render with title, poster art, and tap-through
navigation to detail. The scope is intentionally narrow — *rows render* — and
explicitly excludes the curated/discover grid itself (owned by AND-182), the detail
screen, and any "because you watched" explainability beyond a row title string.

Success = recommended items render in correctly titled rows, are scrollable, navigate
on tap, and degrade gracefully (skeleton → content, empty, offline/stale, error)
without blocking the rest of the Discover screen.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/recommendations.ts` (authoritative
  request/response shape), `frontend/src/api/types.ts` (shared `RecommendationRow`,
  `MediaItem` types), and the Discover page that consumes it.
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json` — confirm the live
  `/ui/recommendations` path, query params, and `detail` error envelope before coding.
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

FR-4. Tapping a card navigates to the media detail route
(`media/{mediaId}`) via the navigation contract established in AND-182. AND-184 only
emits the navigation event; it does not own the detail screen.

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
    val id: String,            // mediaId used for navigation
    val title: String,
    val posterUrl: String?,    // nullable -> placeholder art
    val kind: MediaKind,       // VIDEO, SERIES, etc. (reused enum from AND-182)
)
```

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

**Endpoint:** `GET /ui/recommendations`

Cookie-authenticated (session cookies + `X-CSRF-Token` echoed from the `ui_csrf`
cookie). This is an idempotent GET, so it is eligible for the bounded-backoff retry
policy (§7). Verify exact path/params against `/openapi.json` and
`frontend/src/api/endpoints/recommendations.ts` before implementation; if the live path
differs (e.g. `/ui/discover/recommendations`), update `RecommendationsService` only.

**Optional query params:** `limit` (max rows), `row_limit` (max items per row) if exposed
by OpenAPI; otherwise omit and accept server defaults.

**Retrofit service (`core-network`):**
```kotlin
interface RecommendationsService {
    @GET("ui/recommendations")
    suspend fun getRecommendations(
        @Query("limit") limit: Int? = null,
    ): Response<RecommendationsResponseDto>
}
```

**Response (200) — expected JSON shape** (confirm field names against web types):
```json
{
  "rows": [
    {
      "id": "rec_continue",
      "title": "Recommended for you",
      "items": [
        {
          "id": "med_8sd9",
          "title": "Sample Title",
          "poster_url": "http://18.222.237.167:8000/media/med_8sd9/poster.jpg",
          "kind": "video"
        }
      ]
    }
  ]
}
```

**DTOs + mapper (`core-network`):**
```kotlin
@JsonClass(generateAdapter = true)
data class RecommendationsResponseDto(val rows: List<RecommendationRowDto> = emptyList())

@JsonClass(generateAdapter = true)
data class RecommendationRowDto(
    val id: String,
    val title: String,
    val items: List<RecommendationItemDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class RecommendationItemDto(
    val id: String,
    val title: String,
    @Json(name = "poster_url") val posterUrl: String? = null,
    val kind: String? = null,
)

fun RecommendationRowDto.toDomain() = RecommendationRow(
    id = id,
    title = title,
    items = items.map { it.toDomain() }.filter { it.id.isNotBlank() },
)
```

**Error envelope (FastAPI `detail`):** map `detail` per the project-wide convention —
`string` | `[{msg}]` | `{code,...}` — through the shared `ApiResult` error mapper from
AND-027. A `401` triggers the single `POST /ui/session/refresh` + retry path owned by
the auth interceptor; AND-184 does not implement refresh itself.

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
      val itemsJson: String,        // Moshi-serialized List<RecommendationItemDto>
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

- **R1 — API shape uncertainty:** exact path (`/ui/recommendations` vs nested under
  discover) and field names (`rows`/`items`/`poster_url`) must be confirmed from
  `/openapi.json` + `recommendations.ts`. Mitigation: isolate in DTOs + service; adjust in
  one place.
- **R2 — Unreliable dev host:** flaky/plaintext backend makes manual acceptance noisy.
  Mitigation: Room stale cache + MockWebServer-driven CI tests as the source of truth.
- **R3 — Empty personalization for new users:** backend may return 0 rows; handled by FR-7
  `Empty` (section collapses). Open question: should we fall back to a generic/popular row?
  Out of scope for AND-184 — track separately.
- **OQ1:** Does the row payload include an explanation/`reason` string ("Because you
  watched…")? If present, surface as a secondary row subtitle; if absent, omit. Confirm in
  web types.
- **OQ2:** Are item `kind` values an enumerable set matching AND-182's `MediaKind`? Unknown
  values map to a safe default and still navigate.

## 14. Acceptance Criteria

AC-1. (Source) **Recommended items render.** On Discover, recommendation rows fetched from
`GET /ui/recommendations` render as titled horizontal carousels of media cards (poster +
title) in server order.
AC-2. Tapping a recommended item navigates to `media/{mediaId}` for that item.
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
