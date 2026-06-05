---
id: AND-093
title: Achievements
milestone: M2
epic: E13
priority: P2
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-093 — Achievements

## 1. Overview & Goal

Implement the **Achievements** feature: a read-only Compose screen that renders
the authenticated user's achievement catalog split into **earned** and **locked**
states, with per-achievement **progress** (e.g. "7 / 10") for in-flight,
unlocked-but-not-yet-earned items. The screen is sourced from the FastAPI
backend, refreshable, and degrades gracefully on the unreliable plaintext dev
host (offline / stale states, bounded retry on the idempotent GET).

This ticket delivers the **`achievements` API surface** (the Android analogue of
the web reference `achievements.ts`) plus the **achievements screen** wired to a
`StateFlow<AchievementsUiState>` ViewModel. It builds directly on the
authenticated, cookie-based network stack from **AND-027**
(`authapi-session-endpoints`). The success bar from the backlog is narrow and
testable: *achievements render with progress*.

Out of scope: any write/claim action on an achievement, newly-earned
notifications/toasts (notifications epic), social/leaderboard comparison, and the
session lifecycle / refresh-on-401 plumbing (AND-027). The catalog is returned
whole in one response, so Paging 3 is intentionally not used.

## 2. Context & References

- **Module:** new `feature-achievements` module under the standard layering
  `app -> feature-achievements -> core-*` (`core-network`, `core-model`,
  `core-ui`, `core-data`, `core-testing`).
- **Package root:** `com.testlogon.android.feature.achievements`.
- **Web reference:** `frontend/src/api/endpoints/achievements.ts`, shared types in
  `frontend/src/api/types.ts`. The Android `AchievementsApi` mirrors the web
  endpoint path and query params 1:1.
- **OpenAPI:** `GET http://18.222.237.167:8000/openapi.json` — verify the
  `/ui/achievements` path and the `Achievement` schema (field names for progress,
  `earned_at`, thresholds) against this at implementation time; treat the JSON
  shapes below as the working contract and reconcile drift via an Open Question
  (§13).
- **Upstream ticket:**
  - **AND-027** — provides the authenticated `Retrofit`, persistent cookie jar,
    `ui_csrf` -> `X-CSRF-Token` echo, and the `401 -> POST /ui/session/refresh ->
    retry` authenticator. `AchievementsApi` is registered on the same
    authenticated `Retrofit` instance and inherits this behavior transparently.
- **Shared infrastructure consumed (already on `android-port`):** core-network
  `ApiResult<T>` decoder + FastAPI `detail` mapping, ~20s OkHttp timeouts and
  bounded backoff retry for idempotent GETs, core-ui state composables
  (Loading / Empty / Error / Offline), Material 3 theme, and the
  Navigation-Compose host.

## 3. Functional Requirements

FR-1. On entering the Achievements screen the app loads the full achievements
catalog for the authenticated user in a single request and renders it.

FR-2. The catalog is partitioned into two visually distinct sections:
**Earned** (achievements the user has completed) and **Locked / In progress**
(not yet earned). Section order: Earned first, then Locked.

FR-3. Each achievement row renders: an icon/badge, a title, a description, and —
for items that expose progress — a **progress indicator** showing
`current / target` (numeric label) and a determinate progress bar
(`current / target` as a 0..1 fraction). Earned items show an earned badge and
the `earned_at` date instead of a progress bar.

FR-4. Locked items with no progress data (not started) render at 0 progress with
a "locked" affordance and reduced emphasis (dimmed badge), not an error.

FR-5. A header/summary shows the earned count vs total (e.g. "12 of 30
unlocked"); this is derived client-side from the loaded list.

FR-6. Pull-to-refresh (or a refresh action) re-fetches the catalog and replaces
the rendered state, preserving scroll position where possible.

FR-7. Empty catalog (server returns zero achievements) shows a dedicated empty
state, not a spinner or error.

FR-8. Initial-load failure shows a full-screen retryable error. When a Room
snapshot exists, previously cached achievements render under a "stale / offline"
banner with refresh offered (FR honored only on the RemoteMediator-free cache
path described in §6).

FR-9. The screen requires an authenticated session; an unauthenticated/expired
session (post-refresh-retry 401) surfaces an auth-required state and does not
loop.

## 4. Technical Design

### Module & files

```
feature-achievements/
  src/main/kotlin/com/testlogon/android/feature/achievements/
    data/AchievementsApi.kt
    data/AchievementDto.kt
    data/AchievementsMappers.kt
    data/AchievementsRepository.kt
    data/AchievementEntity.kt          // Room cache (single-table snapshot)
    data/AchievementsDao.kt
    model/Achievement.kt               // domain model (may live in core-model)
    ui/AchievementsScreen.kt
    ui/AchievementsViewModel.kt
    ui/AchievementsUiState.kt
    ui/AchievementRow.kt
    ui/AchievementsHeader.kt
    di/AchievementsModule.kt
```

### Repository

The catalog is small and returned whole, so the repository exposes a single
suspend fetch (not a `Pager`). Room is used as a best-effort offline snapshot
(single table), refreshed transactionally on each successful load.

```kotlin
interface AchievementsRepository {
    /** Network fetch; on success writes through to the Room snapshot. */
    suspend fun getAchievements(): ApiResult<AchievementCatalog>

    /** Last cached snapshot for offline/stale render; null if none. */
    suspend fun cachedAchievements(): AchievementCatalog?

    /** Clear cache on logout (hook into AND-027 session teardown). */
    suspend fun clear()
}

class DefaultAchievementsRepository @Inject constructor(
    private val api: AchievementsApi,
    private val dao: AchievementsDao,
) : AchievementsRepository
```

`AchievementCatalog` is the partitioned, count-summarized domain aggregate:

```kotlin
data class AchievementCatalog(
    val earned: List<Achievement>,     // already split + sorted
    val locked: List<Achievement>,
    val earnedCount: Int,
    val total: Int,
)
```

Partitioning and sorting happen in the mapper (§6), so the ViewModel and UI stay
presentation-only.

### ViewModel

```kotlin
@HiltViewModel
class AchievementsViewModel @Inject constructor(
    private val repository: AchievementsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<AchievementsUiState>(AchievementsUiState.Loading)
    val uiState: StateFlow<AchievementsUiState> = _uiState.asStateFlow()

    init { load(trigger = LoadTrigger.INITIAL) }

    fun refresh() = load(trigger = LoadTrigger.PULL_TO_REFRESH)
    fun retry()   = load(trigger = LoadTrigger.RETRY)

    private fun load(trigger: LoadTrigger) { /* see §6/§7 */ }
}
```

`AchievementsUiState` is a sealed hierarchy driving the screen branches:

```kotlin
sealed interface AchievementsUiState {
    data object Loading : AchievementsUiState
    data class Content(
        val catalog: AchievementCatalog,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,        // rendered from cache while offline
    ) : AchievementsUiState
    data object Empty : AchievementsUiState
    data class Error(val message: UiText, val canRetry: Boolean = true) : AchievementsUiState
    data object AuthExpired : AchievementsUiState
}
```

### UI

```kotlin
@Composable
fun AchievementsScreen(viewModel: AchievementsViewModel = hiltViewModel())

@Composable
private fun AchievementsContent(
    catalog: AchievementCatalog,
    isStale: Boolean,
    isRefreshing: Boolean,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
)

@Composable
private fun AchievementRow(item: Achievement, modifier: Modifier = Modifier)

@Composable
private fun AchievementsHeader(earnedCount: Int, total: Int, modifier: Modifier = Modifier)
```

`AchievementsScreen` collects `uiState` via
`collectAsStateWithLifecycle()` and maps each state to a core-ui state composable
(Loading / Empty / Error+retry / Offline banner). `Content` renders a single
`LazyColumn` with two `stickyHeader` section labels (Earned / Locked) and
`AchievementRow` item slots; the header summary (FR-5) is the first item.
Progress uses Material 3 `LinearProgressIndicator(progress = { fraction })`.

Navigation: register the `"achievements"` route in the single-Activity
Navigation-Compose graph (no arguments); reachable from the More/Profile hub
entry per the IA tickets.

## 5. API Contract

`AchievementsApi` is registered on the AND-027 authenticated `Retrofit` (cookie
jar + `X-CSRF-Token` echo applied transparently by the shared OkHttp client).

```kotlin
interface AchievementsApi {
    @GET("ui/achievements")
    suspend fun getAchievements(): AchievementsResponseDto
}
```

**Request:** `GET /ui/achievements`. GET only, no query params (full catalog) —
eligible for the bounded backoff retry on idempotent GETs (§7).

**Response 200 (`AchievementsResponseDto`):**

```json
{
  "items": [
    {
      "id": "ach_first_login",
      "title": "First Steps",
      "description": "Sign in for the first time.",
      "icon": "badge_first_login",
      "earned": true,
      "earned_at": "2026-05-30T08:11:02Z",
      "progress": { "current": 1, "target": 1 }
    },
    {
      "id": "ach_streak_10",
      "title": "On a Roll",
      "description": "Sign in 10 days in a row.",
      "icon": "badge_streak",
      "earned": false,
      "earned_at": null,
      "progress": { "current": 7, "target": 10 }
    },
    {
      "id": "ach_profile_complete",
      "title": "All About You",
      "description": "Complete your profile.",
      "icon": "badge_profile",
      "earned": false,
      "earned_at": null,
      "progress": null
    }
  ]
}
```

Notes on the contract:
- `progress` may be `null` (achievements with no measurable progress — boolean
  unlock). When present, `target >= 1` and `0 <= current <= target` is expected;
  the mapper clamps defensively (§6).
- `earned_at` is `null` for not-yet-earned items.
- `icon` is a server-side key; the client maps it to a local drawable with a
  default fallback for unknown keys.

**Errors:** FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`) via the
shared `ApiResult<T>` decoder from core-network. `401` is handled upstream
(refresh-once-then-retry); a `401` that survives retry maps to
`ApiResult.AuthExpired` -> `AchievementsUiState.AuthExpired`.

DTOs:

```kotlin
@JsonClass(generateAdapter = true)
data class AchievementsResponseDto(
    @Json(name = "items") val items: List<AchievementDto>,
)

@JsonClass(generateAdapter = true)
data class AchievementDto(
    @Json(name = "id") val id: String,
    @Json(name = "title") val title: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "icon") val icon: String? = null,
    @Json(name = "earned") val earned: Boolean = false,
    @Json(name = "earned_at") val earnedAt: String? = null,    // ISO-8601 | null
    @Json(name = "progress") val progress: ProgressDto? = null,
)

@JsonClass(generateAdapter = true)
data class ProgressDto(
    @Json(name = "current") val current: Int,
    @Json(name = "target") val target: Int,
)
```

## 6. Data & State Management

**Domain model** (`core-model` or feature-local):

```kotlin
data class Achievement(
    val id: String,
    val title: String,
    val description: String?,
    val iconKey: String?,           // resolved to drawable in UI with fallback
    val earned: Boolean,
    val earnedAt: Instant?,
    val progress: AchievementProgress?,  // null = no measurable progress
)

data class AchievementProgress(
    val current: Int,
    val target: Int,
) {
    /** 0f..1f, safe for LinearProgressIndicator; 0 when target <= 0. */
    val fraction: Float
        get() = if (target <= 0) 0f else (current.toFloat() / target).coerceIn(0f, 1f)
}
```

**Mapping & partitioning** (`AchievementsMappers`): DTO -> domain, then build
`AchievementCatalog`:
- `earned = items.filter { it.earned }` sorted by `earnedAt` descending
  (nulls last);
- `locked = items.filterNot { it.earned }` sorted by progress fraction
  descending (closest-to-complete first), tie-broken by title;
- `earnedCount = earned.size`, `total = items.size`;
- `progress` clamped: `current.coerceIn(0, target)`, `target.coerceAtLeast(0)`;
  malformed/negative values fall back to `null` rather than throwing;
- malformed `earned_at` -> `null` (logged at WARN, never fatal).

**Room snapshot** (`core-data` conventions): a single `AchievementEntity` table
(PK `id`) storing the flattened achievement plus a `cached_at` epoch-millis
column. `AchievementsDao.replaceAll(list)` runs delete+insert in one
`@Transaction`. `getAll()` returns the snapshot for offline/stale render
(FR-8). Cache is per-user and cleared on logout via `clear()` hooked into the
AND-027 session-teardown path. No paging keys table is needed (non-paginated).

**Load flow** (`AchievementsViewModel.load`):
1. emit `Loading` (initial) or set `isRefreshing = true` (pull-to-refresh,
   keeping current `Content`);
2. call `repository.getAchievements()`;
3. on `Success` with non-empty list -> `Content(catalog, isStale = false)`;
   empty list -> `Empty`;
4. on `Failure(network/io)` -> if `cachedAchievements()` non-null ->
   `Content(cached, isStale = true)`; else -> `Error(canRetry = true)`;
5. on `AuthExpired` -> `AuthExpired`.

**State surfaces:** exactly one `StateFlow<AchievementsUiState>`. No DataStore
usage beyond what core-data provides; no Paging.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the core-network ~20s OkHttp timeout; do not override.
- **Retry (transport):** `GET /ui/achievements` is idempotent -> eligible for
  the shared bounded backoff retry (capped attempts, jittered) in core-network.
- **Retry (user):** `Error` state exposes a retry action -> `viewModel.retry()`.
- **Initial-load failure with cache:** render the cached snapshot under a
  stale/offline banner (FR-8) instead of the error screen.
- **Initial-load failure without cache:** full-screen retryable `Error`.
- **Empty vs error:** a successful 200 with `items == []` is `Empty`, never an
  error; a transport/parse failure is `Error`.
- **Refresh failure:** keep the existing `Content`, drop `isRefreshing`, and
  surface a transient inline message (snackbar) — do not blow away loaded data.
- **401 after refresh-retry:** mapped to `AuthExpired`; the screen shows an
  auth-required state and stops — no refresh/retry loop.
- **Malformed payload:** mapper tolerates null/negative progress and bad dates
  (see §6); a wholesale parse failure surfaces as `Error`.

## 8. Security & Privacy

- All requests ride the existing cookie-based session (AND-027). The persistent
  cookie jar and `X-CSRF-Token` echo are applied by the shared client; this
  ticket adds no new auth code. (The CSRF header is irrelevant to GET but is
  emitted uniformly by the shared client.)
- Dev backend is **plaintext HTTP**; this is a dev-only allowance via the debug
  network-security-config. The release config must NOT cleartext-permit
  production hosts.
- Achievement payloads are low-sensitivity (titles, descriptions, counts) and
  contain no credentials or PII beyond timestamps tied to the signed-in user.
  Still, the Room snapshot lives in app-private storage and is excluded from
  backup per app policy, and is wiped on logout (`clear()`).
- No secrets, tokens, or raw cookies are rendered in the UI or telemetry.

## 9. Accessibility & i18n

- All strings (section headers, summary "X of Y unlocked", progress
  "current / target", empty/error/offline copy, locked/earned labels,
  relative/absolute dates) in `strings.xml`; no hardcoded UI text. Plurals via
  `<plurals>` for counts.
- `AchievementRow` exposes a single merged `contentDescription` combining
  title + earned/locked status + progress (e.g. "On a Roll, locked, 7 of 10")
  for TalkBack; badge icons are decorative (`contentDescription = null`).
- `LinearProgressIndicator` carries an accessible progress semantics
  (`progressBarRangeInfo`) so TalkBack announces the percentage.
- Touch targets >= 48dp; supports dynamic font scaling and dark theme via
  Material 3 tokens from core-ui. List is fully keyboard/D-pad scrollable.
- Earned/locked distinction does not rely on color alone — earned items also
  carry a badge/check glyph and a text label.
- Dates localized via `DateUtils` / a Compose-friendly formatter.

## 10. Telemetry & Logging

- Events via the core telemetry facade: `achievements_viewed`,
  `achievements_refresh{trigger}`,
  `achievements_loaded{earned_count, total}`,
  `achievements_load_error{stage: initial|refresh, reason}`,
  `achievements_empty`. Payloads include only counts and coarse reason codes —
  no per-achievement identifiers beyond aggregate counts, and no timestamps.
- Logging through the core logger at `DEBUG`/`WARN`; never log full response
  bodies. Network-level logging uses the shared OkHttp logging interceptor
  already gated to debug builds (no `BODY` level in release).

## 11. Testing Strategy

- **Unit — mappers:** `AchievementsMappers` DTO->domain + catalog build:
  earned/locked partitioning, sort order (earned by `earned_at` desc, locked by
  fraction desc), `progress == null` passthrough, progress clamping
  (negative/over-target), malformed `earned_at` -> null, unknown `icon` key
  fallback, and `earnedCount`/`total` math.
- **Unit — API (MockWebServer):** assert path `/ui/achievements`, GET verb, no
  query params, and JSON parsing of `AchievementsResponseDto` including
  `progress: null` and `earned_at: null`. Mirrors the AND-027 MockWebServer
  harness from core-testing.
- **Unit — repository:** success writes through to `AchievementsDao`
  (`replaceAll` invoked); network failure with cache returns the snapshot;
  failure without cache propagates `Failure`; `AuthExpired` passthrough;
  `clear()` empties the table.
- **Unit — ViewModel (Turbine on `StateFlow`):** `Loading -> Content`,
  `Loading -> Empty`, `Loading -> Error` (no cache), `Loading -> Content(isStale)`
  (with cache), `Content -> isRefreshing -> Content` on refresh,
  `Loading -> AuthExpired`, and retry re-issues the load.
- **UI (Compose):** renders earned + locked sections with progress bars (FR-1..
  FR-3), header summary (FR-5), empty state (FR-7), full-screen error + retry
  (FR-8), offline/stale banner (FR-8), and auth-required state (FR-9). The
  acceptance check "achievements render with progress" is covered by a Compose
  test that loads a fixture catalog (earned + in-progress + no-progress items)
  and asserts a determinate progress bar with the expected fraction and label.
- **Coverage gate:** mappers + repository + ViewModel >= 80% line coverage.

## 12. Dependencies & Sequencing

- **AND-027 (P0, M1)** — REQUIRED before integration: authenticated `Retrofit`,
  cookie jar, CSRF echo, 401-refresh-retry. `AchievementsApi` cannot be
  exercised against the backend without it.
- **Implicit infra (already on `android-port`):** core-network `ApiResult` +
  `detail` mapping + timeouts/retry, core-ui state composables, Material 3 theme,
  Navigation-Compose host, core-data Room conventions, core-testing MockWebServer
  harness. None of these are new work for this ticket.
- **Blocks:** none recorded in the backlog.
- **Sequencing:** land DTOs + `AchievementsApi` + mappers + MockWebServer/unit
  tests first (only `AchievementsApi` registration depends on AND-027); wire the
  repository/Room snapshot and `AchievementsScreen`/ViewModel next; integrate the
  navigation entry and the authenticated cookie path once AND-027 is available on
  `android-port`.

## 13. Risks & Open Questions

- **R1 — Endpoint shape unverified.** `/ui/achievements` and the `Achievement`
  schema (especially the `progress` object field names and whether `earned` is a
  flag vs derived from `earned_at`) are assumed from the web reference; confirm
  against `/openapi.json` and `achievements.ts`. *Open: exact path and progress
  field names.*
- **R2 — Progress representation.** Assumed `{current, target}` integer pair;
  backend may instead expose a precomputed `percent` float or a list of sub-task
  flags. *Open: confirm before building the progress UI.* Mapper isolates this.
- **R3 — Icon key catalog.** `icon` is a server-side string mapped to local
  drawables; the full key set is unknown. Mitigated by a default-badge fallback,
  but the key->drawable map needs to be kept in sync. *Open: source of truth for
  icon keys.*
- **R4 — Pagination.** Assumed the full catalog is returned in one response. If
  the backend paginates achievements, this screen must adopt the Paging-3
  scaffold (cf. AND-091/AND-098) — a non-trivial rework. *Open: confirm catalog
  size bound / pagination.*
- **R5 — Dev backend instability** (plaintext, flaky). Mitigated by timeouts,
  bounded GET retry, and stale/offline UI; CI tests run against MockWebServer,
  not the live host.

## 14. Acceptance Criteria

AC-1. Navigating to the Achievements screen loads and renders the catalog,
partitioned into Earned and Locked sections (maps source acceptance
"Achievements render").

AC-2. Each achievement that exposes progress renders a determinate progress bar
and a `current / target` label with the correct fraction; earned items render an
earned badge and `earned_at`; no-progress locked items render a locked
affordance at 0 (maps "with progress"). Verified by a Compose test over a mixed
fixture catalog.

AC-3. The header summary shows the correct earned-vs-total count derived from the
loaded list.

AC-4. Pull-to-refresh re-fetches and replaces the rendered state without
discarding the screen on a transient refresh failure.

AC-5. Zero achievements -> empty state; initial failure without cache ->
full-screen retry; initial failure with cache -> cached render under
stale/offline banner.

AC-6. `AchievementsApi` is MockWebServer-tested: path `/ui/achievements`, GET
verb, no query params, and `AchievementsResponseDto` parsing (including
`progress: null` and `earned_at: null`).

AC-7. A surviving 401 (post refresh-retry) yields an auth-required state with no
retry loop.

## 15. Definition of Done

- `feature-achievements` module created under
  `com.testlogon.android.feature.achievements` with the layering in §4; builds on
  `android-port` (Gradle 8.9 / AGP 8.7.3 / JDK 17, Kotlin 2.0.21, KSP).
- `AchievementsApi`, DTOs, mappers, repository, Room snapshot (DAO/entity),
  ViewModel, and `AchievementsScreen`/`AchievementRow`/`AchievementsHeader`
  implemented per §4–§6 and registered via Hilt (`AchievementsModule`) on the
  AND-027 authenticated Retrofit.
- Achievements route added to the Navigation-Compose graph and reachable from the
  hub entry.
- All strings externalized (incl. plurals); TalkBack, progress semantics,
  dynamic font, and dark-theme verified (§9).
- Telemetry events emitted with no sensitive payloads (§10).
- Tests in §11 pass in CI; mappers/repository/ViewModel >= 80% line coverage; no
  cleartext logging of bodies.
- All AC-1..AC-7 demonstrably met against MockWebServer and (smoke) the dev
  backend.
- Code review approved; ktlint/detekt clean; no new lint baseline regressions.
