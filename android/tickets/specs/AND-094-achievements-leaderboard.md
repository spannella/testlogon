---
id: AND-094
title: Achievements leaderboard
milestone: M2
epic: E13
priority: P2
size: M
depends_on: [AND-093]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-094 — Achievements leaderboard

## 1. Overview & Goal

This ticket delivers the **Achievements Leaderboard** screen for the TestLogon native
Android app. It surfaces the ranked list of users by achievement score and the signed-in
user's own rank. **Correction (verified against the backend + web reference):** this requires
**two** endpoints, not one — the ranked list comes from `GET /ui/achievements/leaderboard`
(paged, `period`/`limit`/`cursor`), and the user's own rank comes from
`GET /ui/achievements/leaderboard/me` (returns a single rank entry, not the list). Both take a
required-with-default `period` query param. The feature lives in
the `feature-achievements` module alongside the achievements list shipped in **AND-093**,
reusing that module's API client, DI graph, and navigation host.

The user-facing goal is simple and testable: when the user opens the Leaderboard tab, they
see a scrollable, ranked list of competitors and a persistent, visually distinct row (or
sticky header) showing **their own rank** — even when that rank falls outside the visible
top-N page. The screen must degrade gracefully against the unreliable dev backend: it shows
loading, populated, empty, stale-cached, and error states, and never blocks the UI thread.

Non-goals: this ticket does **not** add achievement detail pages, badge artwork pipelines,
social/follow features, or push notifications for rank changes. The earned/locked
achievements grid itself is owned by **AND-093** and is not re-specified here.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Module:** `feature-achievements` (already created by AND-093) → depends on `core-network`,
  `core-model`, `core-ui`, `core-data`, `core-testing`.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). OpenAPI contract at `/openapi.json`.
- **Web reference:** `src/api/endpoints/achievements.ts` (`getLeaderboard` and `getMyRank`) and
  shared types in `src/api/types.ts` (`LeaderboardEntry`, `BadgeSummary`). The web screen
  `src/pages/achievements/LeaderboardTable.tsx` calls **both** endpoints (`getLeaderboard({period,
  limit: 50})` for the list and `getMyRank(period)` for the rank), with a period selector
  (Weekly/Monthly/All Time; web UI defaults to `alltime`). These are the authoritative field shapes.
- **Auth (verified against `src/api/client.ts`):** cookie-based session (`credentials: include`).
  The web client sets `X-CSRF-Token` from the **`ui_csrf` cookie**, and additionally sends
  `Authorization: Bearer <accessToken>` when an access token is present. On `401` it performs a
  **single-flight** `POST /ui/session/refresh` then **one** retry of the original request; if the
  retry is still 401 it logs out (`session_expired`). A pre-refresh unauthenticated 401 (no active
  session) propagates directly. The cookie jar + CSRF + refresh-on-401 are provided by `core-network`
  (AND-027). This screen makes authenticated idempotent GETs and inherits that behavior unchanged.
- **Upstream dependency:** **AND-093 (Achievements)** provides `AchievementsApi`, the Retrofit
  service registration, the `AchievementsRepository`, and the achievements navigation graph that
  this leaderboard screen is attached to. **AND-027** provides the network stack and session
  plumbing.

## 3. Functional Requirements

FR-1. A **Leaderboard** destination is reachable from the achievements feature (a tab/segmented
control or sub-route within the achievements navigation graph from AND-093). Route:
`achievements/leaderboard`.

FR-2. On entry the screen requests **`GET /ui/achievements/leaderboard?period=<p>&limit=50`** (for the
ranked list) and **`GET /ui/achievements/leaderboard/me?period=<p>`** (for the user's own rank), and
renders a vertically scrolling, rank-ordered list. Each row shows: rank position (`rank`), display name
(`display_name`, falling back to `user_sub`), points (`total_points`), and badge/achievement count
(`achievement_count`). **Note (corrected):** the contract has **no `avatar_url`/`username` field** — the
list entry instead carries `display_badges: BadgeSummary[]` (each `{achievement_id, label, icon_url,
rarity}`). Coil may render small badge icons from `display_badges[].icon_url` rather than a user avatar.

FR-3. The **current user's own entry** is always visible. If the user appears within the
returned page, their row is highlighted in place; additionally a **sticky "You" header/footer**
pins the user's rank, name, and score so it remains visible while scrolling. If the user is not
in the returned list, the sticky row still renders their rank from the separate
`GET /ui/achievements/leaderboard/me` response (a single `LeaderboardEntry` with an extra `period`
field — **not** a `me` field inside the list response). The web app guards on `myRank.rank != null`,
so the client must tolerate a `me` response with a null/absent `rank`.

FR-4. The screen supports **pull-to-refresh** which re-issues the GET and replaces the list.

FR-5. State coverage (each independently testable):
  - **Loading** — shimmer/placeholder rows while no cached data exists.
  - **Populated** — list + own-rank row.
  - **Empty** — backend returns zero entries → friendly empty message; own-rank row still shown if present.
  - **Stale** — cached data displayed with a non-blocking "Showing saved leaderboard" banner when the refresh fails.
  - **Error** — no cached data and request failed → full-screen error with **Retry**.

FR-6. Tapping a leaderboard row is a **no-op** in this ticket (detail navigation is out of scope);
rows are not clickable affordances unless AND-093 already established a user-profile destination,
in which case they remain non-interactive here.

FR-7. The list must handle large result sets without jank. **Correction:** the list endpoint
**does** support cursor paging (`limit` ≤ 100, default 50; optional `cursor`; response field
`next_cursor`). For this ticket we mirror the web client and request a single bounded page
(`limit=50`), so a single `LazyColumn` with stable keys is sufficient and Paging 3 is **not**
introduced. If product later requires the full ladder, a follow-up adds cursor-based Paging 3 (see R3).

## 4. Technical Design

Layering follows the project convention: `feature-achievements/ui` → `feature-achievements/data`
(repository) → `core-network` (Retrofit service) → `core-model` (DTO/domain).

### 4.1 Retrofit service (extends AND-093 service)

Add to the existing `AchievementsApi` interface in `core-network` (or
`feature-achievements/data` per AND-093's placement):

```kotlin
interface AchievementsApi {
    // ...existing AND-093 endpoints...

    // Ranked list (paged). period default "weekly" server-side; limit <= 100.
    @GET("ui/achievements/leaderboard")
    suspend fun getLeaderboard(
        @Query("period") period: String = "alltime",
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String? = null,
    ): LeaderboardListDto

    // Current user's own rank (single entry, NOT the list).
    @GET("ui/achievements/leaderboard/me")
    suspend fun getMyRank(
        @Query("period") period: String = "alltime",
    ): MyRankDto
}
```

**Correction:** the prior single `getLeaderboardMe(): LeaderboardResponseDto` was wrong on both the
endpoint set and the shape. The web reference uses two calls (`getLeaderboard` + `getMyRank`), each
parameterised by `period`. Both 200 schemas are untyped (`{}`) in OpenAPI, so the shapes below are
taken from `src/api/types.ts` and `src/api/endpoints/achievements.ts` (authoritative web contract).

### 4.2 DTOs (Moshi) and domain model (`core-model`)

**Corrected DTOs** — field names verified against `src/api/types.ts: LeaderboardEntry` and
`BadgeSummary`. There is **no** `user_id`, `username`, `avatar_url`, `is_me`, `score`, `total`, or
`generated_at` field. The list endpoint wraps entries with `next_cursor` + `period`; the `me`
endpoint returns a single entry plus `period`.

```kotlin
@JsonClass(generateAdapter = true)
data class LeaderboardListDto(
    @Json(name = "entries") val entries: List<LeaderboardEntryDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "period") val period: String? = null,
)

// `me` endpoint = LeaderboardEntry & { period }. rank may be null when the user is unranked.
@JsonClass(generateAdapter = true)
data class MyRankDto(
    @Json(name = "rank") val rank: Int? = null,
    @Json(name = "user_sub") val userSub: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "total_points") val totalPoints: Int = 0,
    @Json(name = "achievement_count") val achievementCount: Int = 0,
    @Json(name = "display_badges") val displayBadges: List<BadgeSummaryDto> = emptyList(),
    @Json(name = "period") val period: String? = null,
)

@JsonClass(generateAdapter = true)
data class LeaderboardEntryDto(
    @Json(name = "rank") val rank: Int,
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "total_points") val totalPoints: Int = 0,
    @Json(name = "achievement_count") val achievementCount: Int = 0,
    @Json(name = "display_badges") val displayBadges: List<BadgeSummaryDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class BadgeSummaryDto(
    @Json(name = "achievement_id") val achievementId: String,
    @Json(name = "label") val label: String,
    @Json(name = "icon_url") val iconUrl: String? = null,
    @Json(name = "rarity") val rarity: String? = null,
)

data class LeaderboardEntry(
    val rank: Int,
    val userSub: String,
    val name: String,        // displayName ?: userSub ?: "Player #$rank"
    val points: Int,         // total_points
    val achievementCount: Int,
    val badges: List<BadgeSummary>,
    val isMe: Boolean,
)

data class BadgeSummary(
    val achievementId: String,
    val label: String,
    val iconUrl: String?,
    val rarity: String?,
)

data class Leaderboard(
    val entries: List<LeaderboardEntry>,
    val me: LeaderboardEntry?,    // built from the separate /me response
    val nextCursor: String?,
    val period: String?,
)
```

Since the contract has **no `is_me` flag**, `isMe` must be resolved **client-side** by matching
`entry.userSub` against the current user's `sub` (from `SessionStore`). The mapper computes the safe
`name` (`displayName ?: userSub ?: "Player #$rank"`) and merges the `/me` entry into the domain model.

### 4.3 Repository

```kotlin
class AchievementsRepository @Inject constructor(
    private val api: AchievementsApi,
    private val cache: LeaderboardCacheDao,        // Room, see §6
    private val session: SessionStore,             // current user id
    private val dispatchers: AppDispatchers,
) {
    fun leaderboard(): Flow<ApiResult<Leaderboard>>   // emits cached-first, then network
    suspend fun refreshLeaderboard(): ApiResult<Unit>
}
```

`leaderboard()` emits `ApiResult.Loading`, then a cached `ApiResult.Success(stale=true)` if Room
has a row, then performs the network calls and emits fresh `Success` or `Error` (with the cached
payload attached for the stale-fallback path). **Two calls** are made per refresh —
`api.getLeaderboard(period, 50)` and `api.getMyRank(period)` — and merged into one `Leaderboard`
domain object. They run concurrently (e.g. `coroutineScope { async {} }`); a failure of the `/me`
call alone should degrade gracefully (list still renders, own-rank bar hidden) rather than failing
the whole screen. Network calls are wrapped by the shared `safeApiCall { }` helper from
`core-network` that produces the typed `ApiResult<T>` and maps FastAPI `detail` (string,
`[{msg}]` 422, or `{code,...}` shapes — see `normalizeErrorDetail` in `src/api/client.ts`).

### 4.4 ViewModel (StateFlow<UiState>)

```kotlin
@HiltViewModel
class LeaderboardViewModel @Inject constructor(
    private val repository: AchievementsRepository,
) : ViewModel() {

    val uiState: StateFlow<LeaderboardUiState>   // stateIn(viewModelScope, WhileSubscribed(5_000), Loading)

    fun onRefresh()
    fun onRetry()
}

sealed interface LeaderboardUiState {
    data object Loading : LeaderboardUiState
    data class Content(
        val entries: List<LeaderboardEntry>,
        val me: LeaderboardEntry?,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : LeaderboardUiState
    data class Empty(val me: LeaderboardEntry?) : LeaderboardUiState
    data class Error(val message: String, val cachedContent: Content?) : LeaderboardUiState
}
```

### 4.5 Compose UI

```kotlin
@Composable
fun LeaderboardRoute(viewModel: LeaderboardViewModel = hiltViewModel())

@Composable
fun LeaderboardScreen(
    state: LeaderboardUiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
)

@Composable private fun LeaderboardRow(entry: LeaderboardEntry, highlighted: Boolean)
@Composable private fun MyRankBar(me: LeaderboardEntry)        // sticky "You" bar
@Composable private fun LeaderboardShimmer()
```

The screen uses a `Scaffold` with a `PullToRefreshBox` (Material3) wrapping a `LazyColumn`.
The own-rank bar is rendered outside the scroll region (pinned to the bottom of the Scaffold)
so it is always visible; `LazyColumn` items use `key = { it.userId }` for stable diffing.
The in-list "me" row uses `highlighted = true` with a `MaterialTheme.colorScheme.primaryContainer`
background to satisfy FR-3's in-place highlight.

## 5. API Contract

**Endpoints (verified):**
- List: `GET /ui/achievements/leaderboard` · params `period` (default `weekly`), `limit` (1–100,
  default 50), `cursor` (optional), `user_sub` (optional). op
  `get_leaderboard_endpoint_ui_achievements_leaderboard_get`.
- Own rank: `GET /ui/achievements/leaderboard/me` · params `period` (default `weekly`), `user_sub`
  (optional). op `get_my_rank_endpoint_ui_achievements_leaderboard_me_get`.

Both also accept optional `X-SESSION-ID` and `X-IMPERSONATION-TOKEN` headers (per OpenAPI params).
**Auth:** cookie session + `X-CSRF-Token` (from `ui_csrf` cookie) + optional `Authorization: Bearer`
(handled by `core-network` interceptors).
**Idempotent:** yes → eligible for bounded backoff retry per project policy.

> The OpenAPI 200 schema for both endpoints is untyped (`"schema": {}`), so the shapes below are the
> **frontend contract** from `src/api/types.ts: LeaderboardEntry`/`BadgeSummary` and the inline
> response types in `src/api/endpoints/achievements.ts`. The `me` 200 is `LeaderboardEntry & {period}`.

**List 200 (`GET /ui/achievements/leaderboard`):**

```json
{
  "entries": [
    { "rank": 1, "user_sub": "u_aaa", "display_name": "Ada L.",   "total_points": 4200, "achievement_count": 12,
      "display_badges": [ { "achievement_id": "first_login", "label": "First Login", "icon_url": "https://.../b.png", "rarity": "common" } ] },
    { "rank": 2, "user_sub": "u_bbb", "display_name": "Grace H.", "total_points": 3980, "achievement_count": 11, "display_badges": [] }
  ],
  "next_cursor": "eyJyYW5rIjo1MH0=",
  "period": "alltime"
}
```

**Own-rank 200 (`GET /ui/achievements/leaderboard/me`):**

```json
{ "rank": 57, "user_sub": "u_self", "display_name": "Sean P.", "total_points": 910, "achievement_count": 4, "display_badges": [], "period": "alltime" }
```

The web client treats a `me` response with `rank == null` as "unranked" (hides the rank chip).

**Error responses** map through the shared FastAPI `detail` mapper, handling all three shapes:
`detail` as `string`, as `[{ "msg": "..." }]` (422 validation), or as `{ "code": "...", ... }`.

- `401 Unauthorized` → `core-network` performs a single (single-flight) `POST /ui/session/refresh`
  then **one** retry of the original request; if still 401, the web client logs out
  (`session_expired`) and the screen surfaces `ApiResult.Error` → Retry (auth layer may route to
  sign-in per AND-027 policy). Verified in `src/api/client.ts`.
- `422 Validation Error` → the **only** error response documented in OpenAPI for these endpoints
  (`HTTPValidationError`: `detail: [{loc, msg, type}]`). Maps to a human message via the `[{msg}]`
  branch of the `detail` mapper. Most likely from an invalid `period`/`limit`.
- `404` (endpoint absent on a given dev deploy) → treated as Empty with `me == null`.
  **Unverified assumption** — not in the OpenAPI spec for these paths; defensive handling only.
- `5xx` / timeout / connection failure → `ApiResult.Error`; stale cache is shown if present. The web
  client throws `ApiError(0, "Network error")` on fetch failure (offline/DNS); the Android layer
  should map transport failures to `ApiResult.Error` likewise.

Tunables: ~20s OkHttp call timeout; bounded backoff (e.g. 3 attempts, jittered) applied only to
this GET because it is idempotent.

## 6. Data & State Management

**StateFlow:** `LeaderboardViewModel.uiState : StateFlow<LeaderboardUiState>` is the single source
of truth for the screen, derived from `repository.leaderboard()`.

**Room cache (`core-data`):** a single-row snapshot table so the screen can render instantly and
support the Stale state.

```kotlin
@Entity(tableName = "leaderboard_snapshot")
data class LeaderboardSnapshotEntity(
    @PrimaryKey val id: String = "me",      // single logical row
    val payloadJson: String,                // serialized {list: LeaderboardListDto, me: MyRankDto?}
    val period: String,                     // cache is per-period; key includes period
    val fetchedAtEpochMs: Long,
)

@Dao
interface LeaderboardCacheDao {
    @Query("SELECT * FROM leaderboard_snapshot WHERE id = 'me'")
    fun observe(): Flow<LeaderboardSnapshotEntity?>

    @Upsert suspend fun upsert(entity: LeaderboardSnapshotEntity)
}
```

The snapshot is keyed per device session, not per remote user; on sign-out the cache is cleared by
the existing logout cleanup hook (AND-027). Cached data older than a soft TTL (e.g. 10 min) is
still shown but always flagged `isStale = true` until a fresh fetch succeeds. DataStore is not used
here (no user preferences introduced).

The current user id (`sub`) used for **client-side** `isMe` resolution (the contract has no `is_me`
flag) comes from `SessionStore`. **Unverified assumption:** the exact endpoint/field that populates
`SessionStore.sub` is owned by AND-027 and not confirmed here (no `/ui/me` operation was found in the
OpenAPI index); confirm the session-identity source with AND-027 before relying on it. If the current
`sub` is unavailable, the in-list highlight degrades to matching against the `/me` entry's `user_sub`.

## 7. Error Handling & Resilience

- All network access via `safeApiCall { api.getLeaderboard(period, 50) }` → `ApiResult<LeaderboardListDto>`
  and `safeApiCall { api.getMyRank(period) }` → `ApiResult<MyRankDto>`.
- **Cache-first emission:** on cold start with cache present, UI shows content immediately while a
  background refresh runs; a failed refresh keeps content and sets `isStale`/shows a dismissible banner.
- **No cache + failure:** `LeaderboardUiState.Error` with a human-readable message from the `detail`
  mapper and a **Retry** button calling `onRetry()`.
- **Timeouts:** rely on the 20s OkHttp timeout; the bounded retry covers transient dev-host flakiness.
- **Empty vs. error** are distinguished so an empty leaderboard never shows an error and vice versa.
- **Cancellation-safe:** all work in `viewModelScope`; `WhileSubscribed(5_000)` stops collection when
  the screen is backgrounded.
- Defensive parsing: missing `display_name` falls back to `user_sub`, then `"Player #<rank>"`
  (there is no `username` field); a `me` response with `rank == null` is treated as "unranked" and the
  rank chip/bar is hidden rather than shown as `0`.

## 8. Security & Privacy

- No new credentials or tokens are handled; the request reuses the existing authenticated cookie jar
  and CSRF header. No auth material is logged.
- The endpoint exposes other users' display names/avatars/scores — this is server-authorized public
  competitive data; the client neither aggregates nor exports it.
- Avatar URLs are loaded through Coil over the configured (plaintext dev) transport; **no** mixed-content
  or arbitrary-host enforcement is added here beyond the app-wide `usesCleartextTraffic` dev config.
- The cached snapshot lives in the app-private Room database (not exported, no `android:exported`
  ContentProvider) and is cleared on logout.
- No PII is written to analytics or logs beyond the current user's own rank value.

## 9. Accessibility & i18n

- All strings (screen title "Leaderboard", empty/error/stale messages, "You", "Retry", "Showing saved
  leaderboard") are defined in `feature-achievements/res/values/strings.xml`; no hardcoded literals.
- Each row exposes a single merged `contentDescription`, e.g. `"Rank 2, Grace H., 3980 points"`; the
  own-rank bar announces `"Your rank: 57, 910 points"` (there is no `total` field in the contract, so
  no "of N" — mirror the web copy `Your rank: #57 (910 pts)`).
- Touch targets ≥ 48dp; row height and the pinned bar respect dynamic font scaling (no fixed text px).
- Color is not the sole differentiator for the "me" highlight — the highlighted row and the bar also
  carry a "You" label/icon for color-blind and high-contrast users.
- Numbers use `NumberFormat` for locale-aware grouping (e.g. `4,200`). Layout supports RTL via
  start/end padding. Shimmer placeholders are marked non-focusable for TalkBack.

## 10. Telemetry & Logging

- Events via the app's existing analytics abstraction (no PII):
  - `leaderboard_viewed { has_me: Boolean, entry_count: Int, from_cache: Boolean }`
  - `leaderboard_refreshed { trigger: "pull" | "retry" }`
  - `leaderboard_load_failed { http_status: Int?, reason: String }`
- Logging uses the shared `Timber`-style logger at `DEBUG`/`WARN`; log the failure reason and latency
  bucket, never response bodies, cookies, or user names.
- A latency timing around each GET feeds the existing network-performance histogram, tagged per
  endpoint: `endpoint="achievements/leaderboard"` (list) and `endpoint="achievements/leaderboard/me"`.

## 11. Testing Strategy

**Unit (JVM, `core-testing` + MockWebServer):**
- DTO→domain mapper: name fallback chain (`display_name` → `user_sub` → `Player #rank`), client-side
  `isMe` resolution via `user_sub == currentSub`, null `rank` on the `/me` entry, empty `entries`.
- Repository: cache-first emission order (Loading → cached Success → fresh Success); refresh failure
  preserves cache and flags stale; `/me`-only failure still renders list; 404 → Empty; 401 →
  refresh-then-retry path (verified at network layer).
- ViewModel: state transitions for Loading/Content/Empty/Error and `isRefreshing` toggling on
  `onRefresh()`/`onRetry()`. Use `Turbine` for StateFlow assertions and a `StandardTestDispatcher`.

**Instrumented / Compose UI tests (`createComposeRule`):**
- Populated state renders N rows with stable keys and a pinned own-rank bar.
- Own row highlighted when present; pinned bar reflects `me` when user absent from `entries`.
- Empty state shows empty message; Error state shows Retry and invokes `onRetry`.
- Pull-to-refresh triggers `onRefresh`.
- Accessibility: assert merged `contentDescription` on rows and the bar; verify "You" semantics.

**Contract test:** because the OpenAPI 200 schema for both endpoints is untyped (`{}`), the fixture is
derived from `src/api/types.ts: LeaderboardEntry`/`BadgeSummary` (and a live capture from the dev host
where possible). A MockWebServer test asserts Moshi parses the real field names (`user_sub`,
`total_points`, `achievement_count`, `display_badges`) and that unknown/missing fields degrade safely,
to catch backend drift.

## 12. Dependencies & Sequencing

- **Depends on AND-093 (Achievements):** requires the `feature-achievements` module, `AchievementsApi`
  Retrofit service, `AchievementsRepository`, and the achievements navigation graph/tab host. This
  ticket extends those rather than creating new ones.
- **Transitively depends on AND-027** for the cookie-based session, CSRF, refresh-on-401, and the
  `safeApiCall`/`ApiResult` plumbing — already satisfied through AND-093.
- **Blocks:** none currently.
- Sequencing: implement DTO + mapper + service method → repository + Room snapshot → ViewModel →
  Compose UI → tab wiring → tests.

## 13. Risks & Open Questions

- **R1 — Endpoint shape (NOW RESOLVED via review).** Confirmed against `src/api/types.ts` and
  `src/api/endpoints/achievements.ts`: fields are `rank`, `user_sub`, `display_name`, `total_points`,
  `achievement_count`, `display_badges[]` — there is **no** `score`, `user_id`, `username`,
  `avatar_url`, `is_me`, `total`, or `generated_at`. The ranked list and own-rank are **two separate
  endpoints**. OpenAPI 200 schemas are untyped (`{}`), so the contract test in §11 + Moshi
  `@Json` adapters remain the drift guard. **Owner: this ticket.**
- **R2 — `me` rank may be null** when the user has no ranked achievements. The web client guards on
  `myRank.rank != null`; the Android UI must hide the pinned bar / rank chip when `rank == null`.
  **Resolved:** treat null `rank` as "unranked" rather than `0`.
- **R3 — List paging.** The list endpoint **does** support `cursor`/`next_cursor` (`limit` ≤ 100).
  This ticket requests a single `limit=50` page (matching web). If product needs the full ladder, a
  follow-up adds cursor-based Paging 3 using `next_cursor`.
- **R4 — Dev host flakiness** may make the screen frequently fall to Stale/Error in QA; this is expected
  and covered by the resilience design, not a code defect.
- **R5 — Badge icon hosts** (`display_badges[].icon_url`, not avatars — there is no avatar field) over
  plaintext HTTP may be blocked on stricter network configs; tolerated for dev.

## 14. Acceptance Criteria

AC-1. Opening the Leaderboard renders a rank-ordered list from `GET /ui/achievements/leaderboard`
(with `period`/`limit`), and the own-rank from `GET /ui/achievements/leaderboard/me`
(satisfies source acceptance "Leaderboard … render").

AC-2. The signed-in user's own rank is always visible — highlighted in place when present in the list
and via a pinned own-rank bar otherwise (satisfies "own rank render").

AC-3. Loading, Populated, Empty, Stale, and Error states each render correctly and are covered by tests.

AC-4. Pull-to-refresh and Error→Retry both re-issue the GET and update the UI.

AC-5. On 401, the client refreshes the session once and retries before surfacing an error (inherited
behavior, asserted at the network layer).

AC-6. No hardcoded user-facing strings; rows and the own-rank bar expose correct TalkBack semantics.

AC-7. No raw response bodies, cookies, or PII appear in logs.

## 15. Definition of Done

- Code merged to `android-port` under `feature-achievements`, package `com.testlogon.android.feature.achievements`.
- `getLeaderboardMe()` service method, DTOs, mapper, repository cache, ViewModel, and Compose screen implemented per §4–§6.
- Leaderboard reachable from the achievements feature; own-rank visibility verified on device/emulator.
- Unit + Compose UI tests from §11 pass in CI; mapper and contract tests included.
- `./gradlew :feature-achievements:testDebugUnitTest :feature-achievements:lintDebug` green; ktlint/detekt clean.
- Strings localized; accessibility semantics verified with TalkBack.
- All ACs in §14 demonstrably met; R1/R2 open questions resolved against `/openapi.json` and recorded in the PR.

## 16. Citations & Assumption Audit

Each key technical claim with a verdict and an exact source pointer. Sources: OpenAPI index/spec
(`reference/openapi.index.txt`, `reference/openapi.pretty.json`) and frontend (`reference/src/...`).

1. **Ranked-list endpoint is `GET /ui/achievements/leaderboard`** (params `period`, `limit`≤100 default 50,
   `cursor`, `user_sub`). VERDICT: Verified. SOURCE: OpenAPI `GET /ui/achievements/leaderboard`
   (op `get_leaderboard_endpoint_ui_achievements_leaderboard_get`); `src/api/endpoints/achievements.ts: getLeaderboard`.
2. **Own-rank endpoint is `GET /ui/achievements/leaderboard/me`** (params `period`, `user_sub`).
   VERDICT: Verified. SOURCE: OpenAPI `GET /ui/achievements/leaderboard/me`
   (op `get_my_rank_endpoint_ui_achievements_leaderboard_me_get`); `src/api/endpoints/achievements.ts: getMyRank`.
3. **The leaderboard requires TWO endpoints, not one** (list + own-rank), and the web screen calls both.
   VERDICT: Corrected (spec originally sourced everything from a single `/me` call). SOURCE:
   `src/pages/achievements/LeaderboardTable.tsx` (calls `getLeaderboard({period, limit:50})` and `getMyRank(period)`).
4. **List entry fields are `rank, user_sub, display_name, total_points, achievement_count, display_badges[]`.**
   VERDICT: Corrected (spec had `user_id, username, avatar_url, score, is_me`). SOURCE: `src/api/types.ts: LeaderboardEntry`.
5. **`BadgeSummary = {achievement_id, label, icon_url, rarity}`.** VERDICT: Verified (added; spec had no badge model).
   SOURCE: `src/api/types.ts: BadgeSummary`.
6. **There is no `avatar_url`/`username` field; rows render badge icons, not avatars.** VERDICT: Corrected.
   SOURCE: `src/api/types.ts: LeaderboardEntry`; `src/pages/achievements/LeaderboardTable.tsx` (renders `display_name || user_sub`, `total_points`, `achievement_count`).
7. **There is no `total` or `generated_at` field, and no `me`/`is_me` field inside the list response.**
   VERDICT: Corrected. SOURCE: `src/api/types.ts: LeaderboardEntry`; inline list response type in
   `src/api/endpoints/achievements.ts: getLeaderboard` (`{entries, next_cursor?, period}`).
8. **`me` 200 shape = `LeaderboardEntry & { period }`; `rank` may be null/absent (unranked).** VERDICT: Corrected.
   SOURCE: `src/api/endpoints/achievements.ts: getMyRank`; `src/pages/achievements/LeaderboardTable.tsx` (`myRank.rank != null` guard).
9. **List response carries `next_cursor`; cursor paging is supported (`limit`≤100).** VERDICT: Corrected
   (spec claimed paging was not in the contract). SOURCE: OpenAPI `GET /ui/achievements/leaderboard` `limit`
   schema (max 100, default 50) + `cursor` param; `src/api/endpoints/achievements.ts: getLeaderboard` (`next_cursor`).
10. **`period` is a query param with server default `weekly`; web UI defaults to `alltime`.** VERDICT: Verified
    (added). SOURCE: OpenAPI `period` schema (`default: "weekly"`) on both ops; `LeaderboardTable.tsx`
    (`useState("alltime")`).
11. **Auth: cookie session + `X-CSRF-Token` from the `ui_csrf` cookie + optional `Authorization: Bearer`.**
    VERDICT: Corrected/expanded (spec omitted the cookie name and the Bearer header). SOURCE: `src/api/client.ts`
    (`getCookie("ui_csrf")` → `X-CSRF-Token`; `Authorization: Bearer <accessToken>`; `credentials: "include"`).
12. **401 handling: single-flight `POST /ui/session/refresh`, then ONE retry; still-401 → logout(`session_expired`).**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (`refreshPromise` single-flight, retry block, `logout("session_expired")`).
13. **FastAPI `detail` mapper handles string / `[{msg}]` (422) / `{code,...}` shapes.** VERDICT: Verified.
    SOURCE: `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError`.
14. **422 (`HTTPValidationError`, `detail:[{loc,msg,type}]`) is the only documented error response for these endpoints.**
    VERDICT: Verified. SOURCE: OpenAPI `responses.422` on both ops referencing `HTTPValidationError`.
15. **Transport/offline failure surfaces as a network error (`ApiError(0)`), mapped to `ApiResult.Error`.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` catch block (`throw new ApiError(0, "Network error", err)`).
16. **Both endpoints also accept optional `X-SESSION-ID` and `X-IMPERSONATION-TOKEN` headers.** VERDICT: Verified.
    SOURCE: OpenAPI params on both ops; `src/api/client.ts` (sets `X-IMPERSONATION-TOKEN` when impersonating).
17. **PullToRefreshBox / Material3 + Compose `LazyColumn` are valid framework choices.** VERDICT: Unverified-assumption
    (framework ref, not validated against an Android docs URL in-session). SOURCE: framework ref —
    developer.android.com Compose Material3 `PullToRefreshBox` / `LazyColumn` (assumed current).

### Corrections made
- C1. Replaced the single-endpoint model with the real **two-endpoint** model (list + `/me`); updated §1, §2,
  §3 (FR-2/FR-3/FR-7), §4.1, §4.3, §5, §14 (AC-1).
- C2. Rewrote DTOs/domain in §4.2 to the verified fields (`user_sub`, `display_name`, `total_points`,
  `achievement_count`, `display_badges[]`) and added `BadgeSummary`; removed nonexistent `user_id`,
  `username`, `avatar_url`, `score`, `is_me`, `total`, `generated_at`.
- C3. `isMe` is now resolved **client-side** (`user_sub == currentSub`) because there is no `is_me` flag (§4.2, §6, §11).
- C4. Corrected paging claim: list endpoint supports `cursor`/`next_cursor`, `limit`≤100 (§3 FR-7, §5, §13 R3).
- C5. Added `period` query param everywhere; corrected default (server `weekly`, web `alltime`) (§2, §3, §4.1, §5).
- C6. Auth section now names the `ui_csrf` cookie and the `Authorization: Bearer` header, and the precise
  single-flight-refresh + one-retry + logout 401 flow (§2, §5, §16#12).
- C7. Replaced "avatar" language with "badge icon" (`display_badges[].icon_url`) throughout (§3, §8, §13 R5).
- C8. Fixed accessibility/a11y example that referenced the removed `total` ("of 1342") and `generated_at` (§7, §9).
- C9. Corrected the contract-test source: OpenAPI 200 is untyped (`{}`), so the fixture derives from web types /
  live capture, not `/openapi.json` (§11).
- C10. Handle `me.rank == null` as "unranked" rather than showing `0` (§3 FR-3, §7, §13 R2).

### Open assumptions
- OA1. **404 → Empty** mapping is defensive only; **404 is not in the OpenAPI spec** for these paths (only 200/422).
  Why unverifiable: no documented 404 schema; behavior on a missing dev deploy is inferred.
- OA2. **Current-user `sub` source for `isMe`.** No `/ui/me` operation exists in the OpenAPI index; `SessionStore`'s
  identity source is owned by AND-027 and not confirmed here. Why unverifiable: out-of-ticket dependency.
- OA3. **Room single-row caching, soft TTL (~10 min), and per-period cache keying** are design choices, not
  contract-derived. Why unverifiable: no backend caching contract; product TTL not specified.
- OA4. **Compose Material3 `PullToRefreshBox`/`LazyColumn`, Moshi, Coil, Hilt** are framework choices (framework ref).
  Why unverifiable in-session: no Android docs fetched; assumed current per project conventions (§2, AND-027/093).
- OA5. **Telemetry event/field names** (`leaderboard_viewed`, etc.) are proposed, not sourced from an existing
  analytics schema. Why unverifiable: analytics taxonomy not in the provided sources.
- OA6. **Score semantics:** `total_points` is the ranking key and `achievement_count` is a secondary stat; the
  exact server sort key is inferred from field naming + web rendering, not from a documented sort contract.

## 17. Test Plan

IDs `TC-AND-094-NN`. "AC-#" traces to §14 acceptance criteria. Targets: JVM/Robolectric (local),
emulator AVD `test35` (API 35 x86_64), or PHYSICAL device Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R, API 34 arm64). Most cases here are non-hardware; the device-specific case is noted.

- **TC-AND-094-01** — Type: unit (JVM). Target: JVM/Robolectric local. Precondition: a `LeaderboardListDto`
  fixture with two entries + a `MyRankDto` fixture (`rank=57`). Steps: run `toDomain(currentSub=null)`.
  Expected: domain `entries` map `user_sub→userSub`, `total_points→points`, `achievement_count`,
  `display_badges→badges`; `name = display_name ?: user_sub ?: "Player #rank"`; `me.rank == 57`.
  Traces: AC-1, AC-2.
- **TC-AND-094-02** — Type: unit (JVM). Target: JVM local. Precondition: list contains an entry whose
  `user_sub == currentSub`. Steps: map with `currentSub` set. Expected: that entry has `isMe = true`
  (client-side resolution; no `is_me` field exists); all others `isMe = false`. Traces: AC-2.
- **TC-AND-094-03** — Type: unit (JVM). Target: JVM local. Precondition: `MyRankDto` with `rank = null`
  (unranked). Steps: map to domain; derive UI state. Expected: own-rank bar/chip hidden, not rendered as
  `0`; list still renders. Traces: AC-2, AC-3.
- **TC-AND-094-04** — Type: contract/MockWebServer. Target: JVM local. Precondition: MockWebServer returns
  the §5 real-shape JSON (`user_sub`/`total_points`/`achievement_count`/`display_badges`, list with
  `next_cursor`). Steps: call `getLeaderboard("alltime",50)` + `getMyRank("alltime")` through Retrofit/Moshi.
  Expected: parses with no error; unknown extra fields ignored; missing `display_name` falls back. Traces: AC-1.
- **TC-AND-094-05** — Type: contract/MockWebServer. Target: JVM local. Precondition: server returns
  `422` with `{"detail":[{"loc":["query","period"],"msg":"invalid","type":"value_error"}]}`. Steps:
  invoke through `safeApiCall`. Expected: `ApiResult.Error` whose message is the `msg` (via `[{msg}]`
  mapper branch); no crash. Traces: AC-1, AC-3.
- **TC-AND-094-06** — Type: contract/MockWebServer. Target: JVM local. Precondition: GET returns `401`
  once, `/ui/session/refresh` returns 200, retry returns 200. Steps: invoke repository refresh.
  Expected: exactly one refresh POST then one retry of the original GET; final `ApiResult.Success`.
  Traces: AC-5.
- **TC-AND-094-07** — Type: contract/MockWebServer. Target: JVM local. Precondition: GET `401`, refresh
  `401`. Steps: invoke. Expected: surfaces `ApiResult.Error` (auth-required) and triggers the
  logout/session-expired hook exactly once; no infinite retry loop. Traces: AC-5.
- **TC-AND-094-08** — Type: integration (repository). Target: JVM/Robolectric (in-memory Room). Precondition:
  Room snapshot row present for `period=alltime`; network refresh then FAILS (5xx/timeout). Steps: collect
  `leaderboard()`. Expected: emission order Loading → cached Success(`isStale=true`) → Error-keeps-cache
  (content retained, stale banner). Traces: AC-3 (Stale), AC-4.
- **TC-AND-094-09** — Type: integration (repository). Target: JVM/Robolectric. Precondition: list call
  succeeds; `/me` call fails. Steps: refresh. Expected: list renders; own-rank bar hidden; whole screen
  does NOT error (graceful per-call degradation). Traces: AC-2, AC-3.
- **TC-AND-094-10** — Type: integration (repository). Target: JVM/Robolectric. Precondition: empty cache;
  list returns `{"entries":[]}`; `/me` returns an unranked entry. Steps: refresh. Expected: `Empty` state
  with friendly message, no error; own-rank bar hidden (rank null). Traces: AC-3 (Empty).
- **TC-AND-094-11** — Type: Compose-UI. Target: emulator `test35` (CI). Precondition: `Content` state with
  N entries, `me` present in list. Steps: render `LeaderboardScreen`. Expected: N rows with stable
  `key=userSub`; the matching row is highlighted AND carries a non-color "You" label; pinned MyRankBar
  visible. Traces: AC-2, AC-3, AC-6.
- **TC-AND-094-12** — Type: Compose-UI. Target: emulator `test35`. Precondition: `Content` where `me` is
  NOT in `entries` but `me` rank is known. Steps: render. Expected: no in-list highlight; pinned MyRankBar
  shows the `/me` rank/points. Traces: AC-2.
- **TC-AND-094-13** — Type: Compose-UI. Target: emulator `test35`. Precondition: `Error` state (no cache).
  Steps: render; tap Retry; perform pull-to-refresh on a `Content` state. Expected: Retry invokes
  `onRetry()` and pull invokes `onRefresh()` (each re-issues the two GETs). Traces: AC-3 (Error), AC-4.
- **TC-AND-094-14** — Type: Compose-UI (accessibility). Target: emulator `test35`. Precondition: populated
  state. Steps: assert semantics with `createComposeRule`. Expected: each row exposes a single merged
  `contentDescription` like `"Rank 2, Grace H., 3980 points"`; MyRankBar announces `"Your rank: 57, 910
  points"` (no "of N"); shimmer placeholders non-focusable; all strings from resources (no hardcoded
  literals). Traces: AC-6.
- **TC-AND-094-15** — Type: instrumented/e2e. Target: **PHYSICAL device A15 5G (arm64, API 34)** — run here
  rather than the emulator to validate real plaintext-HTTP networking against the flaky dev host and
  arm64-vs-x86 / API-34-vs-35 behavior. Precondition: signed-in session; toggle device airplane mode to
  simulate offline, then restore. Steps: open Leaderboard offline (cache present) → observe Stale banner;
  restore network → pull-to-refresh → observe fresh data; confirm badge icon loads over cleartext.
  Expected: no ANR/jank, Stale→fresh transition works, cleartext badge `icon_url` loads. Traces: AC-3
  (Stale), AC-4.
- **TC-AND-094-16** — Type: unit (security/logging). Target: JVM local. Precondition: a logging spy around a
  failed and a successful request. Steps: drive both paths. Expected: no response bodies, cookies
  (`ui_csrf`/session), Bearer tokens, or other-user display names appear in logs; only status/reason/latency
  bucket + own rank value. Traces: AC-7.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (list + own-rank render from the two GETs) | TC-01, TC-04, TC-05 |
| AC-2 (own rank always visible: in-list highlight or pinned bar) | TC-01, TC-02, TC-03, TC-09, TC-11, TC-12 |
| AC-3 (Loading/Populated/Empty/Stale/Error states) | TC-03, TC-05, TC-08, TC-09, TC-10, TC-11, TC-13, TC-15 |
| AC-4 (pull-to-refresh & Error→Retry re-issue GET) | TC-08, TC-13, TC-15 |
| AC-5 (401 → single refresh + one retry before error) | TC-06, TC-07 |
| AC-6 (no hardcoded strings; correct TalkBack semantics) | TC-11, TC-14 |
| AC-7 (no bodies/cookies/PII in logs) | TC-16 |
