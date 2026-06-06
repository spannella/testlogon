---
id: AND-093
title: Achievements
milestone: M2
epic: E13
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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

> **CORRECTED (review 2026-06-06):** The backend does NOT expose a single
> "earned + locked + per-item progress" catalog endpoint. Verified against the
> OpenAPI index and the web reference, the achievements view is composed from up
> to **three** authenticated GETs (mirroring the web `achievements.ts`):
> - `GET /ui/achievements` → `{ achievements: UserAchievement[], total_points,
>   achievement_count }` — the user's **earned** badges only (every item returned
>   is unlocked; there is no `earned` flag, no locked rows, no nested progress).
> - `GET /ui/achievements/progress` → `{ progress: AchievementProgress[] }` —
>   per-`metric_key` in-flight progress (`current_value` / `next_threshold`).
> - `GET /ui/achievements/definitions` → `{ definitions: AchievementDefinition[] }`
>   — the full catalog used to derive **locked** items (definitions not present in
>   the earned set) and to resolve a `threshold` (progress target) by `metric_key`.
>
> The combined earned/locked-with-progress UI in this ticket is therefore a
> **client-side composition** of these responses. The single-endpoint `{items:[…]}`
> contract previously asserted in §5 was fictional and has been corrected.

Out of scope: any write/claim action on an achievement (incl. `setDisplayBadges`),
newly-earned notifications/toasts (notifications epic), social/leaderboard
comparison (the separate `/ui/achievements/leaderboard*` endpoints), and the
session lifecycle / refresh-on-401 plumbing (AND-027). Each response is returned
whole (no cursor on the earned/progress/definitions GETs), so Paging 3 is
intentionally not used.

## 2. Context & References

- **Module:** new `feature-achievements` module under the standard layering
  `app -> feature-achievements -> core-*` (`core-network`, `core-model`,
  `core-ui`, `core-data`, `core-testing`).
- **Package root:** `com.testlogon.android.feature.achievements`.
- **Web reference:** `src/api/endpoints/achievements.ts` (functions
  `getMyAchievements`, `getAchievementProgress`, `listDefinitions`), shared DTOs in
  `src/api/types.ts` (`UserAchievement`, `AchievementProgress`,
  `AchievementDefinition`), and the screens `src/pages/achievements/BadgeGrid.tsx`
  and `ProgressTracker.tsx`. The Android `AchievementsApi` mirrors these web
  endpoint paths and query params 1:1. (VERIFIED: paths/params/response shapes
  read directly from these files during review.)
- **OpenAPI:** `GET /openapi.json`. VERIFIED against
  `reference/openapi.index.txt` and `reference/openapi.pretty.json`:
  - `GET /ui/achievements` exists (`op=get_my_achievements_ui_achievements_get`),
    query params `displayed` (bool|null), `category` (string|null),
    `user_sub` (string|null); header params `X-SESSION-ID`,
    `X-IMPERSONATION-TOKEN`; responses `200` (untyped schema — body shape is
    defined by the web `types.ts`) and `422:HTTPValidationError`.
  - `GET /ui/achievements/progress` and `GET /ui/achievements/definitions` exist
    with `200` + `422:HTTPValidationError`.
  - There is **no** `Achievement` schema with `earned`/`earned_at`/nested
    `progress` — those field names were assumed and are corrected throughout (§5).
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

FR-3. Each achievement row renders: an icon/badge (`icon_url`), a title
(`label`), a description, a rarity chip, and — for items that expose progress —
a **progress indicator** showing `current_value / next_threshold` (numeric label)
and a determinate progress bar (`current_value / next_threshold` as a 0..1
fraction). Earned items show an earned badge and the `unlocked_at` date (epoch
seconds → formatted) instead of a progress bar. (CORRECTED: web fields are
`label`/`icon_url`/`unlocked_at`, not `title`/`icon`/`earned_at`; progress comes
from the separate `/ui/achievements/progress` response keyed by `metric_key`,
with the target being `next_threshold` (web `ProgressTracker.tsx`) or the
definition `threshold`.)

FR-4. Locked items with no progress data (not started) render at 0 progress with
a "locked" affordance and reduced emphasis (dimmed badge), not an error.

FR-5. A header/summary shows the earned count and total points (e.g. "12 badges
earned · 340 points"), and — when definitions are loaded — earned-vs-catalog
total ("12 of 30 unlocked"). The earned count and total points come **directly**
from the `/ui/achievements` response (`achievement_count`, `total_points`; web
`BadgeGrid.tsx`); the catalog total is `definitions.size`. (CORRECTED: earned
count is server-provided, not purely client-derived.)

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
suspend fetch (not a `Pager`). **CORRECTED:** that fetch fans out to the three
authenticated GETs (`/ui/achievements`, `/ui/achievements/progress`,
`/ui/achievements/definitions`) concurrently (`coroutineScope { async {…} }`) and
composes the `AchievementCatalog` in the mapper (§6). Earned items come from the
first call; locked items are `definitions − earned` (by `achievement_id`);
progress is joined onto locked items by `metric_key`. The `definitions` and
`progress` calls are best-effort: if either fails but the earned call succeeds,
render earned-only and degrade locked/progress gracefully (see §7). Room is used
as a best-effort offline snapshot (single table), refreshed transactionally on
each successful load.

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

> **CORRECTED (review 2026-06-06):** This section previously described a single
> `GET /ui/achievements` returning `{ items: [{ id, title, icon, earned,
> earned_at, progress:{current,target} }] }`. That contract does not exist. The
> real contract (verified against `src/api/endpoints/achievements.ts`,
> `src/api/types.ts`, and the OpenAPI spec) is below.

`AchievementsApi` is registered on the AND-027 authenticated `Retrofit` (cookie
jar + `X-CSRF-Token` echo applied transparently by the shared OkHttp client).
All three GETs are idempotent → eligible for the bounded backoff retry (§7).

```kotlin
interface AchievementsApi {
    /** Earned badges only. Optional filters mirror the web client. */
    @GET("ui/achievements")
    suspend fun getMyAchievements(
        @Query("displayed") displayed: Boolean? = null,
        @Query("category") category: String? = null,
    ): MyAchievementsResponseDto

    /** In-flight progress, keyed by metric_key. */
    @GET("ui/achievements/progress")
    suspend fun getProgress(): AchievementProgressResponseDto

    /** Full catalog of definitions; used to derive locked items + thresholds. */
    @GET("ui/achievements/definitions")
    suspend fun listDefinitions(
        @Query("active_only") activeOnly: Boolean = true,
    ): AchievementDefinitionsResponseDto
}
```

**Requests:**
- `GET /ui/achievements` — earned badges. Optional query params `displayed`
  (bool) and `category` (string); the screen calls it with no params for the full
  earned set. (VERIFIED: params exist in OpenAPI and web `getMyAchievements`. The
  prior "no query params" claim was wrong.)
- `GET /ui/achievements/progress` — no query params.
- `GET /ui/achievements/definitions` — query `active_only` (bool, web default
  `true`).

**Response 200 — `GET /ui/achievements` (`MyAchievementsResponseDto`):** the
backend declares an untyped 200 in OpenAPI, so the body shape is taken from the
web `getMyAchievements` return type and `UserAchievement` (`src/api/types.ts`):

```json
{
  "achievements": [
    {
      "achievement_id": "first_login",
      "label": "First Steps",
      "description": "Sign in for the first time.",
      "icon_url": "https://cdn.testlogon.dev/badges/first_login.png",
      "rarity": "common",
      "points": 10,
      "unlocked_at": 1748592662,
      "trigger_event": "auth.login",
      "displayed": true
    }
  ],
  "total_points": 10,
  "achievement_count": 1
}
```

Every item in `achievements` is **already earned** — there is no `earned` flag.

**Response 200 — `GET /ui/achievements/progress`
(`AchievementProgressResponseDto`):** from `AchievementProgress`:

```json
{
  "progress": [
    {
      "metric_key": "login_streak_days",
      "current_value": 7,
      "last_updated_at": 1748592662,
      "last_updated_date": "2026-05-30",
      "highest_value": 7,
      "streak_anchor_date": "2026-05-23",
      "next_threshold": 10,
      "next_achievement": {
        "achievement_id": "streak_10",
        "label": "On a Roll",
        "rarity": "uncommon",
        "points": 25
      }
    }
  ]
}
```

`next_threshold` may be `null` (no further tier → treat as complete, web
`ProgressTracker` renders 100%). The progress **target** is `next_threshold`.

**Response 200 — `GET /ui/achievements/definitions`
(`AchievementDefinitionsResponseDto`):** from `AchievementDefinition`:

```json
{
  "definitions": [
    {
      "achievement_id": "streak_10",
      "category": "general",
      "subcategory": "engagement",
      "label": "On a Roll",
      "description": "Sign in 10 days in a row.",
      "icon_url": "https://cdn.testlogon.dev/badges/streak_10.png",
      "rarity": "uncommon",
      "threshold": 10,
      "points": 25,
      "metric_key": "login_streak_days",
      "active": true,
      "sort_order": 20,
      "created_at": 1740000000,
      "updated_at": 1740000000
    }
  ]
}
```

Notes on the contract:
- `icon_url` is a server-side **absolute URL** (loaded via the image pipeline,
  e.g. Coil), not a drawable key. (CORRECTED: prior spec called `icon` a local
  drawable key; provide a default-badge placeholder for null/failed loads.)
- `unlocked_at`, `created_at`, `updated_at`, `last_updated_at` are **epoch
  seconds (numbers)**, not ISO-8601 strings. (CORRECTED.)
- Progress target = `next_threshold` (progress response) or the matching
  definition `threshold`; fraction = `current_value / target`, clamped (§6).
- A locked achievement = a `definition` whose `achievement_id` is not in the
  earned set; its progress (if any) is joined by `metric_key`.

**Errors:** all three return `422 HTTPValidationError` =
`{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }` (VERIFIED:
`components.schemas.HTTPValidationError` / `ValidationError`). The shared
`ApiResult<T>` decoder maps FastAPI `detail` (string | `[{loc,msg,type}]` |
`{code,...}`). `401` is handled upstream (refresh-once-then-retry); a `401` that
survives retry maps to `ApiResult.AuthExpired` -> `AchievementsUiState.AuthExpired`.

DTOs:

```kotlin
@JsonClass(generateAdapter = true)
data class MyAchievementsResponseDto(
    @Json(name = "achievements") val achievements: List<UserAchievementDto>,
    @Json(name = "total_points") val totalPoints: Int = 0,
    @Json(name = "achievement_count") val achievementCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class UserAchievementDto(
    @Json(name = "achievement_id") val achievementId: String,
    @Json(name = "label") val label: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "icon_url") val iconUrl: String? = null,
    @Json(name = "rarity") val rarity: String? = null,
    @Json(name = "points") val points: Int = 0,
    @Json(name = "unlocked_at") val unlockedAt: Long? = null,   // epoch seconds
    @Json(name = "trigger_event") val triggerEvent: String? = null,
    @Json(name = "displayed") val displayed: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class AchievementProgressResponseDto(
    @Json(name = "progress") val progress: List<AchievementProgressDto>,
)

@JsonClass(generateAdapter = true)
data class AchievementProgressDto(
    @Json(name = "metric_key") val metricKey: String,
    @Json(name = "current_value") val currentValue: Int = 0,
    @Json(name = "highest_value") val highestValue: Int = 0,
    @Json(name = "next_threshold") val nextThreshold: Int? = null,
    @Json(name = "streak_anchor_date") val streakAnchorDate: String? = null,
    @Json(name = "next_achievement") val nextAchievement: NextAchievementDto? = null,
)

@JsonClass(generateAdapter = true)
data class NextAchievementDto(
    @Json(name = "achievement_id") val achievementId: String,
    @Json(name = "label") val label: String,
    @Json(name = "rarity") val rarity: String? = null,
    @Json(name = "points") val points: Int = 0,
)

@JsonClass(generateAdapter = true)
data class AchievementDefinitionsResponseDto(
    @Json(name = "definitions") val definitions: List<AchievementDefinitionDto>,
)

@JsonClass(generateAdapter = true)
data class AchievementDefinitionDto(
    @Json(name = "achievement_id") val achievementId: String,
    @Json(name = "category") val category: String? = null,
    @Json(name = "label") val label: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "icon_url") val iconUrl: String? = null,
    @Json(name = "rarity") val rarity: String? = null,
    @Json(name = "threshold") val threshold: Int? = null,
    @Json(name = "points") val points: Int = 0,
    @Json(name = "metric_key") val metricKey: String? = null,
    @Json(name = "active") val active: Boolean = true,
    @Json(name = "sort_order") val sortOrder: Int = 0,
)
```

## 6. Data & State Management

**Domain model** (`core-model` or feature-local):

```kotlin
data class Achievement(
    val id: String,                 // achievement_id
    val title: String,              // label
    val description: String?,
    val iconUrl: String?,           // absolute URL; UI loads via Coil + fallback
    val rarity: String?,
    val points: Int,
    val earned: Boolean,            // DERIVED client-side: id in earned set
    val earnedAt: Instant?,         // unlocked_at (epoch seconds) -> Instant
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

**Mapping & partitioning** (`AchievementsMappers`): the mapper takes the three
DTO responses and composes `AchievementCatalog`. (CORRECTED: partitioning is by
set membership across responses, not by a per-item `earned` flag.)
- `earnedIds = myAchievements.achievements.map { it.achievementId }.toSet()`.
- `earned`: map `myAchievements.achievements` → `Achievement(earned = true,
  earnedAt = unlockedAt?.let(Instant::ofEpochSecond))`, sorted by `earnedAt`
  descending (nulls last).
- `locked`: `definitions.filter { it.achievementId !in earnedIds }` → mapped with
  `earned = false`; join progress by `metric_key`
  (`progressByMetric[def.metricKey]`), target = `progress.nextThreshold ?: def.threshold`;
  sorted by progress fraction descending (closest-to-complete first), tie-broken
  by `label`.
- `earnedCount = myAchievements.achievementCount` (server-provided);
  `total = definitions.size` (catalog) — falls back to `earned.size` if
  definitions failed to load.
- progress fraction clamped: `currentValue.coerceIn(0, target)`,
  `target.coerceAtLeast(0)`; null/negative target → `progress = null` rather than
  throwing.
- malformed/negative `unlocked_at` -> `null` (logged at WARN, never fatal).
- If the `definitions` call fails (degraded mode), `locked` is empty and the
  screen renders earned-only with a non-fatal note (§7).

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
- **Partial fan-out failure (CORRECTED):** the catalog is composed from three
  GETs. If `/ui/achievements` (earned) succeeds but `/ui/achievements/progress`
  and/or `/ui/achievements/definitions` fail, render in **degraded mode** (earned
  badges shown; locked/progress omitted) rather than failing the whole screen.
  Only a failure of the primary `/ui/achievements` call (with no cache) escalates
  to the full-screen `Error`. A `401` on any of the three after refresh-retry →
  `AuthExpired`.

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
- **Unit — API (MockWebServer):** assert paths `/ui/achievements`,
  `/ui/achievements/progress`, `/ui/achievements/definitions`, GET verb, and JSON
  parsing of `MyAchievementsResponseDto` (`achievements`/`total_points`/
  `achievement_count`), `AchievementProgressResponseDto` (incl.
  `next_threshold: null`), and `AchievementDefinitionsResponseDto`. Verify
  `unlocked_at` parses as epoch-seconds (number) and `active_only` query is sent.
  Mirrors the AND-027 MockWebServer harness from core-testing.
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

- **R1 — Endpoint shape (RESOLVED in review).** Verified: there is no combined
  catalog endpoint. The view composes `GET /ui/achievements` (earned),
  `GET /ui/achievements/progress`, and `GET /ui/achievements/definitions`
  (locked + thresholds). `earned` is **derived** by set membership (earned items
  have no flag); see §5. *Residual risk: the 200 body of `/ui/achievements` is
  untyped in OpenAPI, so the field contract is taken from the web `types.ts`; a
  silent backend drift would only be caught at runtime/contract test.*
- **R2 — Progress representation (RESOLVED in review).** Confirmed integer
  `current_value` with target `next_threshold` (nullable → treat as complete);
  no `percent` float. Definition `threshold` is the fallback target. Mapper
  isolates the join.
- **R3 — Icon source (RESOLVED in review).** `icon_url` is a server-side
  **absolute URL**, not a drawable key (web `BadgeGrid`/`types.ts`). Load via the
  image pipeline (Coil) with a default-badge placeholder on null/failure; no
  client-side key→drawable map is required.
- **R4 — Pagination.** The earned (`/ui/achievements`), progress, and
  definitions GETs are non-paginated (no cursor in OpenAPI or the web client; only
  `/ui/achievements/leaderboard` uses `cursor`, which is out of scope). Paging-3
  is not needed. *Residual: no documented size bound on definitions; acceptable
  for a single-screen catalog.*
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

AC-6. `AchievementsApi` is MockWebServer-tested: GET paths `/ui/achievements`,
`/ui/achievements/progress`, `/ui/achievements/definitions`, and parsing of
`MyAchievementsResponseDto`, `AchievementProgressResponseDto` (incl.
`next_threshold: null`), and `AchievementDefinitionsResponseDto` — including
`unlocked_at` as epoch-seconds and the `active_only` query on definitions.
(CORRECTED from the prior single-`AchievementsResponseDto`/no-query-params claim.)

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source.

1. **`GET /ui/achievements` exists and lists the user's achievements.** VERIFIED.
   Source: OpenAPI `GET /ui/achievements` (`op=get_my_achievements_ui_achievements_get`),
   `reference/openapi.index.txt`; `src/api/endpoints/achievements.ts: getMyAchievements`.
2. **Its 200 body is `{ achievements: UserAchievement[], total_points, achievement_count }`** (NOT `{ items: [...] }`). CORRECTED.
   Source: `src/api/endpoints/achievements.ts: getMyAchievements` (declared return type);
   `src/pages/achievements/BadgeGrid.tsx` (`data.achievements`, `achievement_count`, `total_points`).
   OpenAPI 200 schema is empty (untyped), so the web types are authoritative.
3. **Every item in `/ui/achievements` is already earned; there is no `earned` boolean and no nested `progress` object.** CORRECTED.
   Source: `src/api/types.ts: UserAchievement` (fields: `achievement_id, label, description, icon_url, rarity, points, unlocked_at, trigger_event, displayed`).
4. **Achievement fields are `label` / `icon_url` / `unlocked_at` (epoch seconds), not `title` / `icon` / `earned_at` (ISO string).** CORRECTED.
   Source: `src/api/types.ts: UserAchievement`; `src/pages/achievements/BadgeGrid.tsx` (`ach.label`, `ach.icon_url`).
5. **`icon_url` is an absolute image URL (load via Coil), not a local drawable key.** CORRECTED.
   Source: `src/pages/achievements/BadgeGrid.tsx` (`<img src={ach.icon_url} />`).
6. **In-flight progress comes from a separate `GET /ui/achievements/progress` → `{ progress: AchievementProgress[] }`.** CORRECTED (was folded into a per-item field).
   Source: OpenAPI `GET /ui/achievements/progress`; `src/api/endpoints/achievements.ts: getAchievementProgress`; `src/pages/achievements/ProgressTracker.tsx`.
7. **Progress shape is `{ metric_key, current_value, next_threshold?, highest_value, next_achievement? }`; fraction = `current_value / next_threshold` (null threshold ⇒ 100%).** CORRECTED (prior `{current, target}`).
   Source: `src/api/types.ts: AchievementProgress`; `ProgressTracker.tsx` (`pct = current_value / next_threshold`).
8. **Locked achievements are derived from `GET /ui/achievements/definitions` → `{ definitions: AchievementDefinition[] }` minus the earned set; `threshold`/`metric_key` come from definitions.** CORRECTED (no locked rows exist in `/ui/achievements`).
   Source: OpenAPI `GET /ui/achievements/definitions`; `src/api/endpoints/achievements.ts: listDefinitions`; `src/api/types.ts: AchievementDefinition` (`threshold, metric_key, sort_order, ...`).
9. **`GET /ui/achievements` accepts `displayed` (bool) and `category` (string) query params (and `user_sub`); the prior "no query params" claim was wrong.** CORRECTED.
   Source: OpenAPI `GET /ui/achievements` parameters (`openapi.pretty.json`); `src/api/endpoints/achievements.ts: getMyAchievements`.
10. **`listDefinitions` sends `active_only` (default true).** VERIFIED.
    Source: `src/api/endpoints/achievements.ts: listDefinitions`; OpenAPI `GET /ui/achievements/definitions` (`params=active_only,...`).
11. **Summary counts (`achievement_count`, `total_points`) are server-provided, not purely client-derived.** CORRECTED.
    Source: `src/pages/achievements/BadgeGrid.tsx`.
12. **Auth is cookie-based session; CSRF via `ui_csrf` cookie → `X-CSRF-Token` header, applied to all requests.** VERIFIED.
    Source: `src/api/client.ts` (`credentials: "include"`; `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
13. **401 → `POST /ui/session/refresh` (once) → retry; failed refresh = session expired.** VERIFIED.
    Source: `src/api/client.ts: refreshSession` + the 401 branch.
14. **Error responses use FastAPI `422 HTTPValidationError` = `{ detail: [{ loc, msg, type }] }`.** VERIFIED.
    Source: `openapi.pretty.json` `components.schemas.HTTPValidationError` → `ValidationError` (`loc`, `msg`, `type` required).
15. **The earned/progress/definitions GETs are non-paginated (no cursor); only `/ui/achievements/leaderboard` uses a cursor (out of scope).** VERIFIED.
    Source: OpenAPI index lines for those ops (no `cursor` param) vs `GET /ui/achievements/leaderboard | params=period,limit,cursor,...`.
16. **Write/claim actions (`setDisplayBadges`, admin definitions/seed/advance) are out of scope but exist.** VERIFIED (scoping note).
    Source: OpenAPI `POST /ui/achievements/display-badges`, `/ui/achievements/admin/*`; `src/api/endpoints/achievements.ts`.
17. **Framework choices** — single-`Activity` Navigation-Compose, Hilt VM, `StateFlow` + `collectAsStateWithLifecycle`, Material 3 `LinearProgressIndicator(progress = { fraction })`, Room single-table snapshot, Coil image loading. UNVERIFIED-ASSUMPTION (project convention; not derivable from backend/web sources).
    Source: framework ref — Navigation Compose (https://developer.android.com/jetpack/compose/navigation), Lifecycle-aware collection (https://developer.android.com/topic/libraries/architecture/coroutines#lifecycle-aware), Coil (https://coil-kt.github.io/coil/compose/).

### Corrections made

- **§1, §5:** Replaced the fictional single `GET /ui/achievements` returning
  `{ items: [{ id, title, icon, earned, earned_at, progress:{current,target} }] }`
  with the real three-endpoint composition (earned + progress + definitions) and
  corrected response/DTO shapes.
- **Field renames everywhere:** `id→achievement_id`, `title→label`,
  `icon→icon_url` (URL, not key), `earned_at` (ISO) → `unlocked_at` (epoch
  seconds); removed the non-existent per-item `earned` flag and nested `progress`;
  added `rarity`, `points`, `displayed`, `trigger_event`.
- **Progress:** target is `next_threshold` (nullable) / definition `threshold`,
  not a per-item `target`; sourced from a separate endpoint.
- **§3 FR-3/FR-5:** corrected field names and made earned count/points
  server-provided.
- **§4/§6:** repository now fans out to three GETs; mapper partitions by set
  membership across responses and joins progress by `metric_key`.
- **§5/§11/AC-6:** corrected the "no query params" claim (`displayed`,
  `category`, `active_only` exist) and the MockWebServer DTO names.
- **§7:** added partial-fan-out degraded-mode handling.
- **§13 R1–R4:** marked resolved with verified facts.
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **Untyped 200 body** for `/ui/achievements` (and `/progress`, `/definitions`):
  OpenAPI declares `schema: {}`, so the exact JSON contract is taken from the web
  `src/api/types.ts`. A backend change not reflected in the web client would not
  be caught until the contract test runs. Mitigation: contract/MockWebServer tests
  pinned to the web shapes (TC-AND-093-02..04).
- **Composition semantics** (locked = definitions − earned; join by `metric_key`):
  inferred from the web app's tabbed structure (BadgeGrid earned, ProgressTracker
  progress, definitions for the catalog). The web app does not itself render a
  single merged earned/locked list, so the merge rule is an Android-side product
  decision, not a backend contract.
- **`category` filter values** (`creator | viewer | general`) come from
  `AchievementDefinition.category`; whether `/ui/achievements?category=` filters
  on the same enum is assumed, not exercised by the web client.
- **Framework/architecture choices** (claim 17) follow project convention and are
  not verifiable from the provided sources.

## 17. Test Plan

IDs `TC-AND-093-NN`. "Traces" link to §14 Acceptance Criteria (AC-1..AC-7).
Default target is the JVM/Robolectric or CI emulator `test35` unless a case needs
real hardware/behavior, in which case the **physical Samsung Galaxy A15 5G
(SM-A156U, API 34)** is called out.

- **TC-AND-093-01 — Mapper composes earned + locked + progress.**
  Type: unit (JVM). Target: `AchievementsMappers`.
  Preconditions: fixtures — earned `MyAchievementsResponseDto` (2 items),
  `AchievementProgressResponseDto` (1 in-flight `login_streak_days`,
  `current_value=7`, `next_threshold=10`), `AchievementDefinitionsResponseDto`
  (4 definitions incl. the 2 earned).
  Steps: call the mapper with the three DTOs.
  Expected: `earned.size==2` (sorted `unlocked_at` desc), `locked.size==2`
  (definitions − earned), the streak locked item has `progress.fraction==0.7f`
  and target 10, `earnedCount==achievement_count`, `total==definitions.size`.
  Traces: AC-1, AC-2, AC-3.

- **TC-AND-093-02 — Contract: `/ui/achievements` parsing.**
  Type: contract/MockWebServer. Target: `AchievementsApi.getMyAchievements`.
  Preconditions: MockWebServer enqueues the §5 earned JSON.
  Steps: call `getMyAchievements()`; capture the recorded request.
  Expected: path `/ui/achievements`, method GET; parses `achievements`,
  `total_points`, `achievement_count`; `unlocked_at` deserializes as `Long`
  (epoch seconds). Traces: AC-6.

- **TC-AND-093-03 — Contract: `/ui/achievements/progress` parsing incl. null threshold.**
  Type: contract/MockWebServer. Target: `AchievementsApi.getProgress`.
  Preconditions: enqueue a progress payload with one item `next_threshold: null`
  and one with `next_threshold: 10`.
  Steps: call `getProgress()`.
  Expected: path `/ui/achievements/progress`, GET; `nextThreshold` is `null` then
  `10`; null-threshold item maps to a complete/100% fraction in the mapper.
  Traces: AC-2, AC-6.

- **TC-AND-093-04 — Contract: `/ui/achievements/definitions` with `active_only`.**
  Type: contract/MockWebServer. Target: `AchievementsApi.listDefinitions`.
  Preconditions: enqueue a definitions payload.
  Steps: call `listDefinitions(activeOnly = true)`; inspect the request URL.
  Expected: path `/ui/achievements/definitions`, GET, query `active_only=true`;
  `threshold`/`metric_key` parse. Traces: AC-1, AC-6.

- **TC-AND-093-05 — Mapper edge cases (clamping & bad data).**
  Type: unit (JVM). Target: `AchievementsMappers` / `AchievementProgress.fraction`.
  Preconditions: fixtures with `current_value > next_threshold`, negative values,
  `next_threshold = 0/null`, malformed/absent `unlocked_at`, null `icon_url`.
  Steps: map.
  Expected: fraction `coerceIn(0f,1f)`; target ≤ 0 ⇒ progress null (no throw);
  bad `unlocked_at` ⇒ `earnedAt = null` (WARN-logged); null `icon_url` tolerated.
  Traces: AC-2.

- **TC-AND-093-06 — Repository happy path writes through to Room.**
  Type: unit (Robolectric for in-memory Room). Target:
  `DefaultAchievementsRepository.getAchievements`.
  Preconditions: fake `AchievementsApi` returns all three responses; in-memory DAO.
  Steps: call `getAchievements()`.
  Expected: `ApiResult.Success<AchievementCatalog>`; `dao.replaceAll` invoked once
  (delete+insert transaction); `cachedAchievements()` returns the snapshot.
  Traces: AC-1, AC-5.

- **TC-AND-093-07 — Repository partial fan-out failure → degraded mode.**
  Type: unit (JVM). Target: repository/mapper.
  Preconditions: earned call succeeds; progress and definitions calls throw
  IOException.
  Steps: call `getAchievements()`.
  Expected: `Success` with earned items only, `locked` empty, no thrown error
  (degraded mode per §7); the screen still renders earned badges. Traces: AC-1.

- **TC-AND-093-08 — ViewModel state machine (Loading→Content / Empty / Error).**
  Type: unit (JVM, Turbine on `StateFlow`). Target: `AchievementsViewModel`.
  Preconditions: fake repo variants (non-empty success / empty earned+defs /
  failure with no cache).
  Steps: construct VM; collect `uiState`.
  Expected: `Loading→Content(catalog)`; empty earned+empty definitions →
  `Loading→Empty`; failure with no cache → `Loading→Error(canRetry=true)`.
  Traces: AC-1, AC-5.

- **TC-AND-093-09 — Offline/stale render from cache + flaky-host path.**
  Type: unit (JVM) + instrumented smoke. Target: ViewModel/repository.
  Preconditions: Room snapshot present; network fetch fails (simulated
  IOException / unreachable plaintext dev host).
  Steps: trigger initial load with the network failing.
  Expected: `Content(cached, isStale = true)` under an offline banner, not
  `Error`. Note: the unit case runs on JVM; an optional smoke run against the
  flaky dev host is best done on the **physical device** (real radio/DNS flakiness)
  but is not required for CI. Traces: AC-5.

- **TC-AND-093-10 — ViewModel pull-to-refresh keeps Content on transient failure.**
  Type: unit (JVM, Turbine). Target: `AchievementsViewModel.refresh`.
  Preconditions: VM in `Content`; refresh fetch fails transiently.
  Steps: call `refresh()`.
  Expected: emits `Content(isRefreshing=true)` then returns to the prior
  `Content` (data retained) with a transient inline message; screen is not blown
  away. Traces: AC-4.

- **TC-AND-093-11 — Surviving 401 → AuthExpired, no loop.**
  Type: contract/MockWebServer + unit. Target: api/repository/ViewModel.
  Preconditions: MockWebServer returns 401, then 401 again on the post-refresh
  retry (AND-027 authenticator exhausted).
  Steps: trigger load.
  Expected: `ApiResult.AuthExpired` → `AchievementsUiState.AuthExpired`; exactly
  one refresh attempt; no infinite retry. Traces: AC-7.

- **TC-AND-093-12 — Compose UI renders progress (acceptance core).**
  Type: Compose-UI (CI emulator `test35`). Target: `AchievementsContent` /
  `AchievementRow`.
  Preconditions: fixture catalog with an earned item (badge + date), an in-flight
  locked item (7/10), and a no-progress locked item.
  Steps: set content; assert.
  Expected: Earned and Locked section headers present; a determinate
  `LinearProgressIndicator` with fraction `0.7` and a "7 / 10" label; earned badge
  + formatted `unlocked_at`; no-progress locked row at 0 with a locked affordance;
  header shows "X badges earned · N points". Traces: AC-1, AC-2, AC-3.

- **TC-AND-093-13 — Compose UI: empty / error+retry / auth-required states.**
  Type: Compose-UI (CI emulator `test35`). Target: `AchievementsScreen`.
  Preconditions: drive VM into `Empty`, `Error(canRetry)`, `AuthExpired`.
  Steps: assert each branch.
  Expected: `Empty` shows the empty state (no spinner/error); `Error` shows a
  full-screen retry that invokes `retry()`; `AuthExpired` shows auth-required with
  no retry button/loop. Traces: AC-5, AC-7.

- **TC-AND-093-14 — Accessibility: TalkBack semantics & contrast-independence.**
  Type: instrumented/Compose-UI a11y (PHYSICAL DEVICE — Samsung Galaxy A15 5G,
  API 34, with real TalkBack). Target: `AchievementRow`, progress bar.
  Preconditions: render the mixed fixture catalog; enable TalkBack on device.
  Steps: swipe through rows.
  Expected: each row announces merged `contentDescription`
  (e.g. "On a Roll, locked, 7 of 10"); `LinearProgressIndicator` exposes
  `progressBarRangeInfo` (percentage announced); decorative badges have
  `contentDescription = null`; earned/locked distinguishable without color
  (badge/check glyph + text); touch targets ≥ 48dp; dynamic font scaling and dark
  theme render without truncation. Must run on the **physical device** for real
  TalkBack behavior. Traces: AC-2.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (renders, earned/locked partition) | TC-01, TC-04, TC-06, TC-07, TC-08, TC-12 |
| AC-2 (progress bar + label, earned badge, no-progress locked) | TC-01, TC-03, TC-05, TC-12, TC-14 |
| AC-3 (header earned/total count) | TC-01, TC-12 |
| AC-4 (pull-to-refresh, transient-failure resilience) | TC-10 |
| AC-5 (empty / error-no-cache / stale-with-cache) | TC-06, TC-08, TC-09, TC-13 |
| AC-6 (MockWebServer contract: paths/verbs/params/parsing) | TC-02, TC-03, TC-04 |
| AC-7 (surviving 401 → auth-required, no loop) | TC-11, TC-13 |
