---
id: AND-094
title: Achievements leaderboard
milestone: M2
epic: E13
priority: P2
size: M
status: draft
depends_on: [AND-093]
blocks: []
---

# AND-094 — Achievements leaderboard

## 1. Overview & Goal

This ticket delivers the **Achievements Leaderboard** screen for the TestLogon native
Android app. It surfaces the ranked list of users by achievement score and the signed-in
user's own rank, sourced from `GET /ui/achievements/leaderboard/me`. The feature lives in
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
- **Web reference:** `frontend/src/api/endpoints/achievements.ts` (the `achievements.ts`
  client AND-093 ports) and shared types in `frontend/src/api/types.ts`. The leaderboard
  endpoint is consumed there as the reference implementation for field shapes.
- **Auth:** cookie-based session established via `/ui/session/start` → MFA → `/ui/session/finalize`;
  the persistent cookie jar + `X-CSRF-Token` header + single-shot `/ui/session/refresh` on 401
  are provided by `core-network` (AND-027). This screen makes an authenticated idempotent GET
  and inherits that behavior unchanged.
- **Upstream dependency:** **AND-093 (Achievements)** provides `AchievementsApi`, the Retrofit
  service registration, the `AchievementsRepository`, and the achievements navigation graph that
  this leaderboard screen is attached to. **AND-027** provides the network stack and session
  plumbing.

## 3. Functional Requirements

FR-1. A **Leaderboard** destination is reachable from the achievements feature (a tab/segmented
control or sub-route within the achievements navigation graph from AND-093). Route:
`achievements/leaderboard`.

FR-2. On entry the screen requests `GET /ui/achievements/leaderboard/me` and renders a
vertically scrolling, rank-ordered list of entries. Each row shows: rank position, display
name, score (achievement points/count), and an optional avatar (via Coil).

FR-3. The **current user's own entry** is always visible. If the user appears within the
returned page, their row is highlighted in place; additionally a **sticky "You" header/footer**
pins the user's rank, name, and score so it remains visible while scrolling. If the user is not
in the returned list, the sticky row still renders their rank from the `me` field of the response.

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

FR-7. The list must handle large result sets without jank. Paging is **not** required by the
endpoint contract (the `me` endpoint returns a bounded top-N + own rank), so a single
`LazyColumn` with stable keys is sufficient; Paging 3 is not introduced.

## 4. Technical Design

Layering follows the project convention: `feature-achievements/ui` → `feature-achievements/data`
(repository) → `core-network` (Retrofit service) → `core-model` (DTO/domain).

### 4.1 Retrofit service (extends AND-093 service)

Add to the existing `AchievementsApi` interface in `core-network` (or
`feature-achievements/data` per AND-093's placement):

```kotlin
interface AchievementsApi {
    // ...existing AND-093 endpoints...

    @GET("ui/achievements/leaderboard/me")
    suspend fun getLeaderboardMe(): LeaderboardResponseDto
}
```

### 4.2 DTOs (Moshi) and domain model (`core-model`)

```kotlin
@JsonClass(generateAdapter = true)
data class LeaderboardResponseDto(
    @Json(name = "entries") val entries: List<LeaderboardEntryDto> = emptyList(),
    @Json(name = "me") val me: LeaderboardEntryDto? = null,
    @Json(name = "total") val total: Int? = null,
    @Json(name = "generated_at") val generatedAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class LeaderboardEntryDto(
    @Json(name = "rank") val rank: Int,
    @Json(name = "user_id") val userId: String,
    @Json(name = "username") val username: String?,
    @Json(name = "display_name") val displayName: String?,
    @Json(name = "avatar_url") val avatarUrl: String?,
    @Json(name = "score") val score: Int,
    @Json(name = "is_me") val isMe: Boolean = false,
)

data class LeaderboardEntry(
    val rank: Int,
    val userId: String,
    val name: String,        // displayName ?: username ?: "Player #$rank"
    val avatarUrl: String?,
    val score: Int,
    val isMe: Boolean,
)

data class Leaderboard(
    val entries: List<LeaderboardEntry>,
    val me: LeaderboardEntry?,
    val total: Int?,
    val generatedAt: Instant?,
)
```

A mapper `fun LeaderboardResponseDto.toDomain(currentUserId: String?): Leaderboard` resolves
`isMe` defensively (`dto.isMe || dto.userId == currentUserId`) and computes the safe `name`.

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
has a row, then performs the network call and emits fresh `Success` or `Error` (with the cached
payload attached for the stale-fallback path). Network calls are wrapped by the shared
`safeApiCall { }` helper from `core-network` that produces the typed `ApiResult<T>` and maps
FastAPI `detail`.

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

**Endpoint:** `GET /ui/achievements/leaderboard/me`
**Auth:** cookie session + `X-CSRF-Token` header (handled by `core-network` interceptors).
**Idempotent:** yes → eligible for bounded backoff retry per project policy.

**200 response (representative shape; confirm against `/openapi.json`):**

```json
{
  "entries": [
    { "rank": 1, "user_id": "u_aaa", "username": "ada",   "display_name": "Ada L.",   "avatar_url": "https://.../a.png", "score": 4200, "is_me": false },
    { "rank": 2, "user_id": "u_bbb", "username": "grace", "display_name": "Grace H.", "avatar_url": null,                "score": 3980, "is_me": false }
  ],
  "me": { "rank": 57, "user_id": "u_self", "username": "spannella", "display_name": "Sean P.", "avatar_url": null, "score": 910, "is_me": true },
  "total": 1342,
  "generated_at": "2026-06-05T12:00:00Z"
}
```

**Error responses** map through the shared FastAPI `detail` mapper, handling all three shapes:
`detail` as `string`, as `[{ "msg": "..." }]` (422 validation), or as `{ "code": "...", ... }`.

- `401 Unauthorized` → `core-network` performs a single `POST /ui/session/refresh` then one retry;
  if still 401, surfaces `ApiResult.Error` → screen shows error with Retry (and the auth layer may
  route to sign-in per AND-027 policy).
- `404` (endpoint absent on a given dev deploy) → treated as Empty with `me == null`.
- `5xx` / timeout / connection failure → `ApiResult.Error`; stale cache is shown if present.

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
    val payloadJson: String,                // serialized LeaderboardResponseDto
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

The current user id used for `isMe` resolution comes from the cached `/ui/me` result exposed by
`SessionStore`; the leaderboard never calls `/ui/me` directly.

## 7. Error Handling & Resilience

- All network access via `safeApiCall { api.getLeaderboardMe() }` → `ApiResult<LeaderboardResponseDto>`.
- **Cache-first emission:** on cold start with cache present, UI shows content immediately while a
  background refresh runs; a failed refresh keeps content and sets `isStale`/shows a dismissible banner.
- **No cache + failure:** `LeaderboardUiState.Error` with a human-readable message from the `detail`
  mapper and a **Retry** button calling `onRetry()`.
- **Timeouts:** rely on the 20s OkHttp timeout; the bounded retry covers transient dev-host flakiness.
- **Empty vs. error** are distinguished so an empty leaderboard never shows an error and vice versa.
- **Cancellation-safe:** all work in `viewModelScope`; `WhileSubscribed(5_000)` stops collection when
  the screen is backgrounded.
- Defensive parsing: missing `display_name`/`username` falls back to `"Player #<rank>"`; unparseable
  `generated_at` yields `null` and is simply not displayed.

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
  own-rank bar announces `"Your rank: 57 of 1342, 910 points"`.
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
- A latency timing around the GET feeds the existing network-performance histogram tag
  `endpoint="achievements/leaderboard/me"`.

## 11. Testing Strategy

**Unit (JVM, `core-testing` + MockWebServer):**
- DTO→domain mapper: name fallback chain, `isMe` resolution via `is_me` and via id match, null
  `generated_at`, empty `entries`.
- Repository: cache-first emission order (Loading → cached Success → fresh Success); refresh failure
  preserves cache and flags stale; 404 → Empty; 401 → refresh-then-retry path (verified at network layer).
- ViewModel: state transitions for Loading/Content/Empty/Error and `isRefreshing` toggling on
  `onRefresh()`/`onRetry()`. Use `Turbine` for StateFlow assertions and a `StandardTestDispatcher`.

**Instrumented / Compose UI tests (`createComposeRule`):**
- Populated state renders N rows with stable keys and a pinned own-rank bar.
- Own row highlighted when present; pinned bar reflects `me` when user absent from `entries`.
- Empty state shows empty message; Error state shows Retry and invokes `onRetry`.
- Pull-to-refresh triggers `onRefresh`.
- Accessibility: assert merged `contentDescription` on rows and the bar; verify "You" semantics.

**Contract test:** a fixture asserts the parsed shape against a sample captured from `/openapi.json`
to catch backend field drift.

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

- **R1 — Endpoint shape unverified.** Field names (`score` vs `points`, `me` vs `current_user`, presence
  of `total`) must be confirmed against `/openapi.json` and `frontend/src/api/endpoints/achievements.ts`.
  Mitigation: Moshi adapters with `@Json` aliases and the contract test in §11. **Owner: this ticket.**
- **R2 — `me` may be omitted** when the user has no achievements yet. UI must handle `me == null`
  (hide the pinned bar, show an encouraging empty/CTA copy). **Open question:** does the backend return
  rank `0`/`null` or omit `me` entirely? Resolve before merge.
- **R3 — Unbounded list size.** If `entries` is large (full ladder rather than top-N), reconsider Paging 3.
  Current assumption: bounded top-N. Confirm with backend; if violated, a follow-up ticket adds paging.
- **R4 — Dev host flakiness** may make the screen frequently fall to Stale/Error in QA; this is expected
  and covered by the resilience design, not a code defect.
- **R5 — Avatar hosts** over plaintext HTTP may be blocked on stricter network configs; tolerated for dev.

## 14. Acceptance Criteria

AC-1. Opening the Leaderboard renders a rank-ordered list from `GET /ui/achievements/leaderboard/me`
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
