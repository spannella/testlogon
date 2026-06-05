---
id: AND-091
title: Activity feed
milestone: M2
epic: E13
priority: P1
size: M
status: draft
depends_on: [AND-027, AND-098]
blocks: []
---

# AND-091 — Activity feed

## 1. Overview & Goal

Implement the **Activity feed**: a paginated, scrollable screen that renders the
authenticated user's account activity events (logins, MFA challenges, session
revocations, password/profile changes, security alerts) sourced from the
FastAPI backend. The feed is read-only, cursor-paginated, pull-to-refresh
capable, and degrades gracefully on the unreliable dev backend (offline / stale
states, bounded retry).

This ticket delivers the **`activityFeed` API surface** (the Android analogue of
the web reference `activityFeed.ts`) plus the **paged Compose screen** wired to
Paging 3. It builds directly on the generic Paging-3 list scaffolding from
**AND-098** (`feed-list-paging-3`) and the authenticated, cookie-based network
stack from **AND-027** (`authapi-session-endpoints`). The success bar is narrow
and testable: *activity renders and paginates*.

Out of scope: the generic Paging source/footer UI primitives (owned by
AND-098), session lifecycle and refresh-on-401 (owned by AND-027), and any
write/acknowledge actions on activity events (not requested by this ticket).

## 2. Context & References

- **Module:** new `feature-activity` module under the standard layering
  `app -> feature-activity -> core-*` (`core-network`, `core-model`, `core-ui`,
  `core-data`, `core-testing`).
- **Package root:** `com.testlogon.android.feature.activity`.
- **Web reference:** `frontend/src/api/endpoints/activityFeed.ts`, shared types
  in `frontend/src/api/types.ts`. The Android `ActivityApi` mirrors the web
  endpoint paths and query params 1:1.
- **OpenAPI:** `GET http://18.222.237.167:8000/openapi.json` — verify the
  `/ui/activity` path, query params, and the `ActivityEvent` schema against this
  at implementation time; treat the JSON shapes below as the contract and
  reconcile any drift via an Open Question (§13).
- **Upstream tickets:**
  - **AND-027** — provides authenticated `Retrofit`, persistent cookie jar,
    `ui_csrf` -> `X-CSRF-Token` echo, and the 401 -> `POST /ui/session/refresh`
    -> retry interceptor. `ActivityApi` is registered on the same authenticated
    `Retrofit` instance.
  - **AND-098** — provides the reusable Paging 3 list scaffold: a
    `LazyColumn`-based list composable with append/refresh `LoadState` footers
    (loading spinner, retryable error footer) and pull-to-refresh. AND-091
    supplies the `PagingSource` and item composable; it consumes those
    primitives rather than re-implementing them.

## 3. Functional Requirements

FR-1. On entering the Activity screen, the app loads the first page of activity
events for the authenticated user and renders them newest-first in a vertical
scrolling list.

FR-2. Scrolling to the end automatically appends the next page using the
backend cursor until `next_cursor` is null (end of feed), at which point no
further append requests are issued.

FR-3. Each event row renders: an icon keyed off `event_type`, a human-readable
title, an optional detail/subtitle line, a relative timestamp (e.g. "2h ago"),
and a location/device hint (`ip` / `user_agent` summary) when present.

FR-4. Pull-to-refresh re-fetches from the head of the feed and replaces the
list, preserving scroll-to-top behavior.

FR-5. Empty feed (zero events) shows a dedicated empty state, not a spinner or
error.

FR-6. Initial-load failure shows a full-screen retryable error; append failure
shows the AND-098 inline retry footer without discarding already-loaded items.

FR-7. While offline or when the dev backend is unreachable, previously cached
events (Room) render with a "stale / offline" banner; refresh is offered.

FR-8. The screen requires an authenticated session; an unauthenticated/expired
session (post-refresh-retry 401) surfaces an auth-required state and does not
loop.

## 4. Technical Design

### Module & files

```
feature-activity/
  src/main/kotlin/com/testlogon/android/feature/activity/
    data/ActivityApi.kt
    data/ActivityRemoteMediator.kt      // or ActivityPagingSource (see below)
    data/ActivityRepository.kt
    data/ActivityEventDto.kt
    data/ActivityMappers.kt
    model/ActivityEvent.kt              // domain model (may live in core-model)
    ui/ActivityFeedScreen.kt
    ui/ActivityFeedViewModel.kt
    ui/ActivityRow.kt
    ui/ActivityUiState.kt
    di/ActivityModule.kt
```

### Paging strategy

Because FR-7 requires offline/stale rendering from Room, use **Paging 3
`RemoteMediator` + Room** rather than a network-only `PagingSource`. Room is the
single source of truth; the mediator fetches pages by cursor and writes them
through. If AND-098's scaffold standardizes on a network-only `PagingSource`,
fall back to that and drop FR-7's cache to a best-effort first-page snapshot
(recorded as Open Question §13).

```kotlin
@OptIn(ExperimentalPagingApi::class)
class ActivityRemoteMediator @Inject constructor(
    private val api: ActivityApi,
    private val db: ActivityDatabase,
) : RemoteMediator<Int, ActivityEventEntity>() {
    override suspend fun load(
        loadType: LoadType,
        state: PagingState<Int, ActivityEventEntity>
    ): MediatorResult { /* cursor read/write + ApiResult mapping */ }
}
```

### Repository

```kotlin
interface ActivityRepository {
    fun activityPager(): Flow<PagingData<ActivityEvent>>   // 25/page
    suspend fun refresh(): ApiResult<Unit>
}

class DefaultActivityRepository @Inject constructor(
    private val api: ActivityApi,
    private val db: ActivityDatabase,
) : ActivityRepository
```

`PagingConfig(pageSize = 25, prefetchDistance = 10, enablePlaceholders = false)`.

### ViewModel

```kotlin
@HiltViewModel
class ActivityFeedViewModel @Inject constructor(
    repository: ActivityRepository,
) : ViewModel() {
    val items: Flow<PagingData<ActivityEvent>> =
        repository.activityPager().cachedIn(viewModelScope)

    private val _uiState = MutableStateFlow(ActivityUiState())
    val uiState: StateFlow<ActivityUiState> = _uiState.asStateFlow()
}
```

`ActivityUiState` carries cross-cutting flags (`isStale: Boolean`,
`isAuthExpired: Boolean`) derived from mediator/refresh outcomes; the list's own
`LoadState` (from `collectAsLazyPagingItems()`) drives footers and the
full-screen loading/error/empty branches.

### UI

```kotlin
@Composable
fun ActivityFeedScreen(viewModel: ActivityFeedViewModel = hiltViewModel())

@Composable
private fun ActivityRow(event: ActivityEvent, modifier: Modifier = Modifier)
```

`ActivityFeedScreen` consumes the AND-098 paged-list scaffold:
`items.collectAsLazyPagingItems()`, wraps it in the shared pull-to-refresh +
`LazyColumn` with append/refresh footer handling, and supplies `ActivityRow` as
the item slot and the empty/offline/auth states described in §3 and §7.

Navigation: register `"activity"` route in the single-Activity
Navigation-Compose graph (no arguments).

## 5. API Contract

`ActivityApi` registered on the AND-027 authenticated `Retrofit` (cookie jar +
`X-CSRF-Token` echo applied transparently by the shared OkHttp client).

```kotlin
interface ActivityApi {
    @GET("ui/activity")
    suspend fun getActivity(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 25,
    ): ActivityPageDto
}
```

**Request:** `GET /ui/activity?limit=25` (first page), then
`GET /ui/activity?cursor=<next_cursor>&limit=25`. GET only — eligible for the
bounded backoff retry on idempotent GETs (§7).

**Response 200 (`ActivityPageDto`):**

```json
{
  "items": [
    {
      "id": "evt_01HZX...",
      "event_type": "login_success",
      "created_at": "2026-06-05T14:03:22Z",
      "ip": "203.0.113.7",
      "user_agent": "Mozilla/5.0 (...)",
      "detail": "Signed in from Chrome on macOS",
      "metadata": { "factor": "totp" }
    }
  ],
  "next_cursor": "eyJrIjoiZXZ0XzAxSFp..."
}
```

`next_cursor` is `null` on the last page. `metadata` is a free-form object and
is mapped to `Map<String, Any?>?` (Moshi).

**Errors:** FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`) via the
shared `ApiResult<T>` decoder from core-network. `401` is handled upstream
(refresh-once-then-retry); a `401` that survives retry maps to
`ApiResult.AuthExpired`.

DTOs:

```kotlin
@JsonClass(generateAdapter = true)
data class ActivityPageDto(
    @Json(name = "items") val items: List<ActivityEventDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
)

@JsonClass(generateAdapter = true)
data class ActivityEventDto(
    @Json(name = "id") val id: String,
    @Json(name = "event_type") val eventType: String,
    @Json(name = "created_at") val createdAt: String,   // ISO-8601
    @Json(name = "ip") val ip: String? = null,
    @Json(name = "user_agent") val userAgent: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "metadata") val metadata: Map<String, Any?>? = null,
)
```

## 6. Data & State Management

**Domain model** (`core-model` or feature-local):

```kotlin
data class ActivityEvent(
    val id: String,
    val type: ActivityEventType,   // sealed/enum + Unknown(raw) fallback
    val createdAt: Instant,
    val ip: String?,
    val deviceSummary: String?,    // derived from user_agent
    val detail: String?,
)
```

`ActivityEventType` is a closed set (`LOGIN_SUCCESS`, `LOGIN_FAILED`,
`MFA_CHALLENGE`, `SESSION_REVOKED`, `PASSWORD_CHANGED`, `SECURITY_ALERT`, ...)
with an `UNKNOWN(raw: String)` fallback so unrecognized server types render with
a default icon rather than crashing.

**Room** (`core-data` conventions): `ActivityEventEntity` (PK `id`, sortable
`created_at` epoch-millis, JSON-stringified metadata) and a paging keys table
`ActivityRemoteKeys(eventId, nextCursor)`. `@Query` exposes
`PagingSource<Int, ActivityEventEntity>` ordered by `created_at DESC`. Refresh
clears the table + keys inside a single transaction before writing the new head
page. Cache is per-user; clear on logout (hook into AND-027 session teardown).

**State surfaces:** `StateFlow<ActivityUiState>` for screen-level flags +
`LazyPagingItems` `CombinedLoadStates` for list-level states. No DataStore usage
required for this ticket beyond what core-data already provides.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the core-network ~20s OkHttp timeout; do not override.
- **Retry:** `GET /ui/activity` is idempotent -> eligible for the shared bounded
  backoff retry (capped attempts, jittered) provided by core-network. No retry
  on non-idempotent calls (there are none here).
- **Initial load failure:** mediator returns `MediatorResult.Error`;
  `refresh` `LoadState.Error` -> full-screen retryable error. If a Room snapshot
  exists, render it with the stale banner (FR-7) instead of the error screen.
- **Append failure:** `append` `LoadState.Error` -> AND-098 inline retry footer;
  loaded items retained.
- **Empty vs error:** distinguish `LoadState.NotLoading(endOfPaginationReached)`
  with zero items (empty state) from errors.
- **401 after refresh-retry:** mapped to `isAuthExpired = true`; screen shows an
  auth-required state and stops paging — no refresh/retry loop.
- **Offline:** OkHttp `IOException` with cached rows present -> stale/offline
  banner + manual refresh; with no cache -> error screen.

## 8. Security & Privacy

- All requests ride the existing cookie-based session (AND-027). The persistent
  cookie jar and `X-CSRF-Token` echo are applied by the shared client; this
  ticket adds no new auth code. (The CSRF header is irrelevant to GET but is
  emitted uniformly by the shared client.)
- Dev backend is **plaintext HTTP**; this is a dev-only allowance. The release
  network-security-config must NOT cleartext-permit production hosts. No
  activity payloads are written to logs (§10).
- Activity events contain sensitive PII (IP addresses, user agents, login
  geography). Room cache lives in app-private storage; no export, no backup of
  the activity table (`android:fullBackupContent` exclusion or
  `allowBackup=false` per app policy). Cache is wiped on logout.
- No secrets, tokens, or raw cookies are rendered in the UI or telemetry.

## 9. Accessibility & i18n

- All strings (titles, detail templates, empty/error/offline copy, relative
  time) in `strings.xml`; no hardcoded UI text. Event-type titles via a
  resource map keyed by `ActivityEventType`.
- `ActivityRow` exposes a single merged `contentDescription` combining title +
  relative time + device hint for TalkBack; icons are decorative
  (`contentDescription = null`).
- Relative timestamps localized via `DateUtils.getRelativeTimeSpanString` /
  Compose-friendly equivalent; absolute time available via long-press/tooltip.
- Touch targets >= 48dp; supports dynamic font scaling and dark theme via
  Material 3 tokens from core-ui. List is fully keyboard/D-pad scrollable.
- Pull-to-refresh has an accessible action; loading/error footers announce state
  changes via `liveRegion`.

## 10. Telemetry & Logging

- Events via the core telemetry facade: `activity_feed_viewed`,
  `activity_feed_refresh{trigger}`, `activity_feed_page_loaded{page_index}`,
  `activity_feed_load_error{stage: initial|append, reason}`,
  `activity_feed_empty`. No event includes IP, user agent, or `detail`
  content — only counts, indices, and coarse reason codes.
- Logging through the core logger at `DEBUG`/`WARN`; never log full response
  bodies or PII. Network-level logging uses the shared OkHttp logging
  interceptor already gated to debug builds (no `BODY` level in release).

## 11. Testing Strategy

- **Unit — mappers:** `ActivityMappers` DTO->domain incl. unknown
  `event_type` -> `UNKNOWN`, null optionals, malformed `created_at` handling.
- **Unit — API (MockWebServer):** assert path `/ui/activity`, `cursor`/`limit`
  query params, GET verb, and JSON parsing of `ActivityPageDto` (including
  `next_cursor: null`). Mirrors the AND-027 MockWebServer harness from
  core-testing.
- **Unit — RemoteMediator:** `LoadType.REFRESH`/`APPEND`/`PREPEND` ->
  `Success(endOfPaginationReached=...)` and `Error`; cursor read/write; refresh
  transaction clears keys.
- **Repository / Paging:** `PagingData` differ asserts first page renders and a
  second page appends; `endOfPaginationReached` on `next_cursor == null`.
- **ViewModel:** `cachedIn` survives config change; `isStale`/`isAuthExpired`
  flags set from mediator outcomes (Turbine on `StateFlow`).
- **UI (Compose):** renders list (FR-1), empty state (FR-5), full-screen error +
  retry (FR-6), append-error footer, and offline banner (FR-7). The acceptance
  check "Activity renders + paginates" is covered by a Compose test that loads
  two MockWebServer pages and asserts append-on-scroll.
- **Coverage gate:** mappers + mediator + repository >= 80% line coverage.

## 12. Dependencies & Sequencing

- **AND-027 (P0, M1)** — REQUIRED before integration: authenticated `Retrofit`,
  cookie jar, CSRF echo, 401-refresh-retry. `ActivityApi` cannot be exercised
  against the backend without it.
- **AND-098 (P0, M2)** — REQUIRED: provides the Paging 3 list scaffold
  (footers, pull-to-refresh, error/loading slots) that this screen composes.
  AND-091 must not duplicate that scaffolding.
- **Blocks:** none recorded in the backlog.
- **Sequencing:** land DTOs + `ActivityApi` + MockWebServer tests first (no
  upstream blocker for these); integrate the Paging source/screen once AND-098
  merges; wire the cookie/auth path once AND-027 is available on
  `android-port`.

## 13. Risks & Open Questions

- **R1 — Endpoint shape unverified.** `/ui/activity`, its query params, and the
  `ActivityEvent` schema are assumed from the web reference; confirm against
  `/openapi.json` and `activityFeed.ts`. *Open: exact path and cursor param
  name.*
- **R2 — Pagination contract.** Assumed opaque `cursor` + `next_cursor`; backend
  may instead use offset/limit or page-number. *Open: confirm before building
  the mediator.*
- **R3 — AND-098 paging model.** If AND-098 standardizes on a network-only
  `PagingSource`, FR-7 offline caching is reduced. *Open: align mediator vs
  source with AND-098 owner.*
- **R4 — Dev backend instability** (plaintext, flaky). Mitigated by timeouts,
  bounded GET retry, and stale/offline UI; flaky CI runs against the live host
  should mock via MockWebServer.
- **R5 — Event-type enumeration drift.** New server `event_type`s appear over
  time; mitigated by `UNKNOWN` fallback, but icon/title coverage needs periodic
  review.

## 14. Acceptance Criteria

AC-1. Navigating to the Activity screen loads and renders the first page of
events newest-first against the backend (maps source acceptance "Activity
renders").

AC-2. Scrolling to the end appends subsequent pages via `next_cursor` until the
end of the feed, with no further requests after `next_cursor == null` (maps
"paginates"). Verified by a two-page Compose/MockWebServer test.

AC-3. Pull-to-refresh replaces the list from the head and returns to top.

AC-4. Zero events -> empty state; initial failure -> full-screen retry; append
failure -> inline retry footer with items retained.

AC-5. Offline with cached events -> events render under a stale/offline banner
(when RemoteMediator+Room path is used).

AC-6. `ActivityApi` is MockWebServer-tested: path `/ui/activity`, `cursor`/
`limit` params, GET verb, and `ActivityPageDto` parsing (incl. null
`next_cursor`).

AC-7. A surviving 401 (post refresh-retry) yields an auth-required state with no
retry loop.

## 15. Definition of Done

- `feature-activity` module created under `com.testlogon.android.feature.activity`
  with the layering in §4; builds on `android-port` (Gradle 8.9 / AGP 8.7.3 /
  JDK 17).
- `ActivityApi`, DTOs, mappers, repository, RemoteMediator (or PagingSource),
  ViewModel, and `ActivityFeedScreen`/`ActivityRow` implemented per §4–§6 and
  registered via Hilt (`ActivityModule`) on the AND-027 authenticated Retrofit.
- Activity route added to the Navigation-Compose graph.
- All strings externalized; TalkBack, dynamic font, and dark-theme verified
  (§9).
- Telemetry events emitted with no PII (§10).
- Tests in §11 pass in CI; mappers/mediator/repository >= 80% line coverage; no
  cleartext logging of bodies/PII.
- All AC-1..AC-7 demonstrably met against MockWebServer and (smoke) the dev
  backend.
- Code review approved; ktlint/detekt clean; no new lint baseline regressions.
