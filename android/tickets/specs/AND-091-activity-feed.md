---
id: AND-091
title: Activity feed
milestone: M2
epic: E13
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **OpenAPI:** `GET http://18.222.237.167:8000/openapi.json` — **verified** at
  review time (2026-06-06): the endpoint is `GET /ui/activity/feed` (op
  `get_activity_feed_ui_activity_feed_get`), query params `cursor`, `limit`
  (default **20**, min 1, max 100), `user_sub`, plus optional headers
  `X-SESSION-ID` and `X-IMPERSONATION-TOKEN`; the item schema is `ActivityOut`
  and the page wrapper is `ActivityFeedResponse`. See the corrected contract in
  §5 and the full audit in §16.
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

FR-3. Each event row renders: an icon keyed off `activity_type`, a
human-readable title, an optional detail/subtitle line derived from
`target_type`/`target_id` and selected `metadata` keys, a relative timestamp
(e.g. "2h ago") from `created_at` (epoch **seconds**, integer), and a read/unread
indicator from `read`. **Correction (review):** the backend `ActivityOut` schema
has NO `ip`, `user_agent`, or top-level `detail` fields (verified against
OpenAPI `ActivityOut` and `src/api/types.ts: ActivityItem`). Any location/device
hint can only come from inside the free-form `metadata` map and must be treated
as optional/best-effort, not a guaranteed field.

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

`ActivityApi` registered on the AND-027 authenticated `Retrofit`. Per the web
reference (`src/api/client.ts`), the transport attaches: the session cookie
(`credentials: include` -> persistent cookie jar on Android), an
`Authorization: Bearer <accessToken>` header from the auth store, and the CSRF
token read from the `ui_csrf` cookie echoed as `X-CSRF-Token`. AND-027 owns this
client; this ticket only registers the GET. (The Bearer header + cookie are both
sent; CSRF is irrelevant to a GET but emitted uniformly.)

> **Reviewed & corrected (2026-06-06).** The path, query params, response
> wrapper, and item schema below are now reconciled against OpenAPI
> `GET /ui/activity/feed` and `src/api/endpoints/activityFeed.ts` /
> `src/api/types.ts`. Previous draft assumed `/ui/activity`, `limit=25`, an
> ISO-8601 `created_at`, and `ip`/`user_agent`/`detail` fields — all corrected.

```kotlin
interface ActivityApi {
    @GET("ui/activity/feed")
    suspend fun getActivity(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 25,   // server default 20, max 100; 25 is a client choice <= 100
    ): ActivityFeedResponseDto
}
```

**Request:** `GET /ui/activity/feed?limit=25` (first page), then
`GET /ui/activity/feed?cursor=<next_cursor>&limit=25`. GET only — eligible for
the bounded backoff retry on idempotent GETs (§7). Note: `limit`'s server
default is **20** (min 1, max 100); the client sends an explicit 25. The
endpoint also accepts an optional `user_sub` query param and optional
`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers — none are used by this ticket
(self-scoped feed via the session; impersonation is out of scope).

**Response 200 (`ActivityFeedResponse`, item = `ActivityOut`):**

```json
{
  "items": [
    {
      "activity_id": "act_01HZX...",
      "actor_id": "usr_123",
      "activity_type": "login_success",
      "target_type": "session",
      "target_id": "sess_456",
      "created_at": 1749132202,
      "read": false,
      "metadata": { "factor": "totp", "ip": "203.0.113.7" }
    }
  ],
  "next_cursor": "eyJrIjoiYWN0XzAxSFp...",
  "total_unread": 3
}
```

`next_cursor` is `null` on the last page. `created_at` is an **integer epoch
(seconds)**, not an ISO-8601 string. `total_unread` is an integer (default 0).
Required item fields per OpenAPI are `activity_id`, `actor_id`, `activity_type`;
`target_type`/`target_id` default to `""`, `read` defaults to `false`,
`created_at` defaults to `0`, and `metadata` is a free-form object mapped to
`Map<String, Any?>?` (Moshi).

**Errors:** documented error response is **`422 HTTPValidationError`** with the
FastAPI `detail` shape (string | `[{msg, type, loc}]` | `{code, ...}`), decoded
via the shared `ApiResult<T>` decoder from core-network (the web client's
`normalizeErrorDetail` in `src/api/client.ts` handles all three shapes). `401`
is NOT enumerated on this operation in OpenAPI; it is produced by the session
middleware and handled upstream (refresh-once-then-retry per
`src/api/client.ts`); a `401` that survives retry maps to
`ApiResult.AuthExpired`.

DTOs:

```kotlin
@JsonClass(generateAdapter = true)
data class ActivityFeedResponseDto(
    @Json(name = "items") val items: List<ActivityEventDto>,
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total_unread") val totalUnread: Int = 0,
)

@JsonClass(generateAdapter = true)
data class ActivityEventDto(
    @Json(name = "activity_id") val activityId: String,
    @Json(name = "actor_id") val actorId: String,
    @Json(name = "activity_type") val activityType: String,
    @Json(name = "target_type") val targetType: String = "",
    @Json(name = "target_id") val targetId: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,   // epoch SECONDS
    @Json(name = "read") val read: Boolean = false,
    @Json(name = "metadata") val metadata: Map<String, Any?>? = null,
)
```

## 6. Data & State Management

**Domain model** (`core-model` or feature-local):

```kotlin
data class ActivityEvent(
    val id: String,                // from activity_id
    val type: ActivityEventType,   // sealed/enum + Unknown(raw) fallback, parsed from activity_type
    val actorId: String,
    val createdAt: Instant,        // Instant.ofEpochSecond(created_at)
    val targetType: String?,       // "" -> null
    val targetId: String?,         // "" -> null
    val read: Boolean,
    val detail: String?,           // DERIVED at map time from metadata/target_*, not a server field
)
```

> **Correction (review):** the domain model is mapped from `ActivityOut`
> (`activity_id`, `actor_id`, `activity_type`, `target_type`, `target_id`,
> `created_at` epoch-seconds, `read`, `metadata`). There is no server `ip`,
> `user_agent`, or `detail` field — any device/location hint and the `detail`
> subtitle are derived from `metadata`/`target_*` during mapping. `createdAt`
> is built with `Instant.ofEpochSecond(...)`.

`ActivityEventType` is a closed set (`LOGIN_SUCCESS`, `LOGIN_FAILED`,
`MFA_CHALLENGE`, `SESSION_REVOKED`, `PASSWORD_CHANGED`, `SECURITY_ALERT`, ...)
parsed from `activity_type`, with an `UNKNOWN(raw: String)` fallback so
unrecognized server types render with a default icon rather than crashing.

**Room** (`core-data` conventions): `ActivityEventEntity` (PK `id` from
`activity_id`, sortable `created_at` stored as epoch — note the server sends
epoch **seconds**; normalize on write, JSON-stringified metadata) and a paging
keys table `ActivityRemoteKeys(eventId, nextCursor)`. `@Query` exposes
`PagingSource<Int, ActivityEventEntity>` ordered by `created_at DESC`. Refresh
clears the table + keys inside a single transaction before writing the new head
page. Cache is per-user; clear on logout (hook into AND-027 session teardown).

**State surfaces:** `StateFlow<ActivityUiState>` for screen-level flags +
`LazyPagingItems` `CombinedLoadStates` for list-level states. No DataStore usage
required for this ticket beyond what core-data already provides.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the core-network ~20s OkHttp timeout; do not override.
- **Retry:** `GET /ui/activity/feed` is idempotent -> eligible for the shared bounded
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

- All requests ride the existing authenticated session (AND-027): session
  cookie + `Authorization: Bearer` header + `ui_csrf` -> `X-CSRF-Token` echo,
  all applied by the shared client (verified against `src/api/client.ts`); this
  ticket adds no new auth code. (The CSRF header is irrelevant to GET but is
  emitted uniformly by the shared client.)
- Dev backend is **plaintext HTTP**; this is a dev-only allowance. The release
  network-security-config must NOT cleartext-permit production hosts. No
  activity payloads are written to logs (§10).
- Activity events may carry sensitive PII inside the free-form `metadata` map
  (e.g. IP addresses, login geography); there are no dedicated `ip`/`user_agent`
  columns on the server schema (see §5 correction), so treat the whole
  `metadata` blob as potentially sensitive. Room cache lives in app-private
  storage; no export, no backup of
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
  `activity_type` -> `UNKNOWN`, `target_type`/`target_id` `""` -> null,
  `created_at` epoch-seconds -> `Instant`, null/absent `metadata` handling.
- **Unit — API (MockWebServer):** assert path `/ui/activity/feed`,
  `cursor`/`limit` query params, GET verb, and JSON parsing of
  `ActivityFeedResponseDto` (including `next_cursor: null` and `total_unread`).
  Mirrors the AND-027 MockWebServer harness from core-testing.
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

- **R1 — Endpoint shape (RESOLVED at review).** Confirmed `GET /ui/activity/feed`
  with `cursor`/`limit`/`user_sub` query params and the `ActivityOut` item schema
  against `openapi.pretty.json` and `src/api/endpoints/activityFeed.ts`. The
  original draft's `/ui/activity` path and `event_type`/`ip`/`user_agent`/`detail`
  fields were wrong and are corrected in §5/§6. No remaining open question here.
- **R2 — Pagination contract (RESOLVED at review).** Confirmed opaque string
  `cursor` + nullable string `next_cursor` (not offset/page-number) per the
  OpenAPI param schema and `ActivityFeedResponse`. Safe to build the cursor
  mediator.
- **R3 — AND-098 paging model.** If AND-098 standardizes on a network-only
  `PagingSource`, FR-7 offline caching is reduced. *Open: align mediator vs
  source with AND-098 owner.*
- **R4 — Dev backend instability** (plaintext, flaky). Mitigated by timeouts,
  bounded GET retry, and stale/offline UI; flaky CI runs against the live host
  should mock via MockWebServer.
- **R5 — Activity-type enumeration drift.** `activity_type` is a free-form
  string on the server (`ActivityOut.activity_type`, no enum constraint); new
  values appear over time. Mitigated by the `UNKNOWN` fallback, but icon/title
  coverage needs periodic review.

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

AC-6. `ActivityApi` is MockWebServer-tested: path `/ui/activity/feed`, `cursor`/
`limit` params, GET verb, and `ActivityFeedResponseDto` parsing (incl. null
`next_cursor` and `total_unread`).

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
`openapi.index.txt` / `openapi.pretty.json` (OpenAPI), the frontend reference
under `reference/src/`, and Android docs (labeled "framework ref").

1. **Endpoint path is `GET /ui/activity/feed`.** VERDICT: Corrected (draft said
   `/ui/activity`). SOURCE: OpenAPI `GET /ui/activity/feed`
   (op `get_activity_feed_ui_activity_feed_get`);
   `src/api/endpoints/activityFeed.ts: getActivityFeed`.
2. **Query params are `cursor` (opaque string), `limit`, `user_sub`; optional
   headers `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`.** VERDICT: Verified (draft
   listed only `cursor`/`limit`; the rest are additive, unused by this ticket).
   SOURCE: OpenAPI `GET /ui/activity/feed` params; param schemas in
   `openapi.pretty.json` (path `/ui/activity/feed`).
3. **`limit` server default = 20, min 1, max 100.** VERDICT: Corrected (draft
   implied a default of 25). SOURCE: OpenAPI `limit` param schema
   (`default: 20, minimum: 1, maximum: 100`) under `/ui/activity/feed`.
4. **Response wrapper = `ActivityFeedResponse` with `items`, `next_cursor`
   (nullable string), `total_unread` (int, default 0).** VERDICT: Corrected
   (draft `ActivityPageDto` omitted `total_unread`). SOURCE: OpenAPI
   `components.schemas.ActivityFeedResponse`;
   `src/api/types.ts: ActivityFeedPageResponse`.
5. **Item schema = `ActivityOut`: `activity_id`, `actor_id`, `activity_type`
   (required); `target_type`, `target_id` (default ""), `created_at` (int epoch
   seconds, default 0), `read` (bool, default false), `metadata` (free-form
   object).** VERDICT: Corrected (draft used `id`, `event_type`, ISO-8601
   `created_at`, `ip`, `user_agent`, `detail`). SOURCE: OpenAPI
   `components.schemas.ActivityOut`; `src/api/types.ts: ActivityItem`.
6. **No `ip` / `user_agent` / top-level `detail` fields exist server-side.**
   VERDICT: Corrected (draft FR-3/§5/§6 asserted them). SOURCE: absence in
   `components.schemas.ActivityOut`; `src/api/types.ts: ActivityItem`.
7. **`created_at` is an integer epoch in SECONDS, not an ISO-8601 string.**
   VERDICT: Corrected. SOURCE: `ActivityOut.created_at` (`type: integer`,
   `default: 0`); `ActivityItem.created_at: number`.
8. **`next_cursor` is `null` on the last page (opaque string cursor pagination,
   not offset/page-number).** VERDICT: Verified. SOURCE:
   `ActivityFeedResponse.next_cursor` (`anyOf [string, null]`); cursor param
   `anyOf [string, null]`; `src/api/endpoints/activityFeed.ts` passes `cursor`
   straight through.
9. **Documented error response is `422 HTTPValidationError`; FastAPI `detail`
   may be a string, an array of `{msg,...}`, or an object with `code`.** VERDICT:
   Verified. SOURCE: OpenAPI `GET /ui/activity/feed` resp `422:HTTPValidationError`;
   `src/api/client.ts: normalizeErrorDetail` handles all three shapes.
10. **401 is NOT enumerated on this operation; it comes from session middleware
    and is handled by refresh-once-then-retry, surviving 401 -> auth-expired.**
    VERDICT: Verified. SOURCE: OpenAPI lists only `200`/`422` for the op;
    `src/api/client.ts` (401 branch calls `POST /ui/session/refresh`, retries
    once, then `logout("session_expired")`).
11. **Auth transport = session cookie (`credentials: include`) + `Authorization:
    Bearer <accessToken>` + `ui_csrf` cookie echoed as `X-CSRF-Token`.** VERDICT:
    Corrected (draft described it as purely "cookie-based" and omitted the Bearer
    header). SOURCE: `src/api/client.ts` (`headers.set("Authorization", ...)`,
    `getCookie("ui_csrf")` -> `X-CSRF-Token`, `credentials: "include"`).
12. **Refresh endpoint is `POST /ui/session/refresh` (no request body).**
    VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/refresh`
    (op `ui_session_refresh_ui_session_refresh_post`, `req=` empty);
    `src/api/client.ts: refreshSession`.
13. **Sibling activity endpoints exist (`/ui/activity/feed/filter`,
    `/unread-count`, `/mark-read`, `/record`) but are out of scope.** VERDICT:
    Verified (informational). SOURCE: OpenAPI lines for those paths;
    `src/api/endpoints/activityFeed.ts` (`getActivityFeedFiltered`,
    `getActivityUnreadCount`, `markActivitiesRead`, `recordActivity`).
14. **`UnreadCountResponse` shape is `{ count: int }`** (relevant only if a badge
    is later added). VERDICT: Verified. SOURCE:
    `components.schemas.UnreadCountResponse`; `src/api/types.ts: UnreadCountResponse`.
15. **Paging 3 `RemoteMediator` + Room is required for offline/stale (FR-7).**
    VERDICT: Unverified-assumption (framework design choice). SOURCE: framework
    ref — Android Paging 3 `RemoteMediator`
    (https://developer.android.com/topic/libraries/architecture/paging/v3-network-db).
16. **`metadata` maps to `Map<String, Any?>?` via Moshi.** VERDICT: Verified
    (shape) / framework ref (mapping). SOURCE: `ActivityOut.metadata`
    (`additionalProperties: true`); Moshi map adapter (framework ref,
    https://github.com/square/moshi).

### Corrections made

- Endpoint path `/ui/activity` -> **`/ui/activity/feed`** (§2, §5, §7, §11, §14).
- Item DTO field names: `id`->`activity_id`, `event_type`->`activity_type`; added
  `actor_id`, `target_type`, `target_id`, `read`; removed non-existent `ip`,
  `user_agent`, top-level `detail` (§5, §6, FR-3, §8).
- `created_at` retyped from ISO-8601 `String` to **`Long` epoch seconds** ->
  `Instant.ofEpochSecond` (§5, §6, §11).
- Response wrapper renamed `ActivityPageDto` -> **`ActivityFeedResponseDto`** and
  added `total_unread` (§5, §11, §14).
- `limit` server default clarified as **20** (client still sends 25, <= max 100)
  (§2, §5).
- Auth description corrected to include the **`Authorization: Bearer`** header
  alongside the session cookie and CSRF echo (§5, §8).
- Error contract pinned to **`422 HTTPValidationError`** with the three-shape
  `detail` (§5).
- R1/R2 in §13 marked RESOLVED with the verified facts; R5 noted `activity_type`
  is an unconstrained free-form string.

### Open assumptions

- **OA-1 (FR-7 offline cache via RemoteMediator+Room).** Not verifiable from
  backend/web sources — the web reference is online-only with no local cache.
  Pure Android design decision; falls back to a best-effort first-page snapshot
  if AND-098 standardizes on a network-only `PagingSource`.
- **OA-2 (event-type -> icon/title resource mapping).** `activity_type` is an
  unconstrained server string; the closed enum + icons/titles are a client
  product decision, not a server contract. Covered by `UNKNOWN` fallback.
- **OA-3 (self-scoped feed).** Assumed the session identifies the user and
  `user_sub` is unused for self-view. OpenAPI marks `user_sub` optional but does
  not document the default-to-self behavior; confirm server semantics if a
  surviving empty feed is observed for an authenticated user.
- **OA-4 (`detail` subtitle derivation).** Which `metadata`/`target_*` keys feed
  the human-readable subtitle is a client choice; the server provides no
  prescribed subtitle field.
- **OA-5 (relative-time semantics).** `created_at` is epoch seconds; the
  client-side relative formatting and dev/device clock skew handling are
  unspecified by the contract.

## 17. Test Plan

Test targets: **JVM** (JVM unit/Robolectric, no device), **emu35** (headless AVD
`test35`, API 35 x86_64), **deviceA15** (physical Samsung Galaxy A15 5G, SM-A156U,
serial R5CX821TA9R, API 34 arm64-v8a). Choose the lightest target that exercises
the behavior; use **deviceA15** only where real hardware/ABI/API-34 behavior
matters.

- **TC-AND-091-01 — Happy path: first page renders newest-first.**
  Type: contract/MockWebServer + unit. Target: JVM.
  Preconditions: MockWebServer enqueues a 200 `ActivityFeedResponse` with 25
  `ActivityOut` items (descending `created_at`) and a non-null `next_cursor`.
  Steps: call `ActivityApi.getActivity()`; map to domain; feed through repository
  pager; assert first differ snapshot.
  Expected: request is `GET /ui/activity/feed?limit=25` (no `cursor`); 25 items
  parsed; order newest-first; `activity_id`->id, `activity_type`->type,
  `created_at` epoch-seconds -> `Instant`.
  Traces: AC-1, AC-6.

- **TC-AND-091-02 — Pagination: append second page until end.**
  Type: contract/MockWebServer + Compose-UI. Target: emu35.
  Preconditions: page 1 (200, `next_cursor="c2"`), page 2 (200,
  `next_cursor=null`).
  Steps: load screen; scroll to end to trigger append; scroll again.
  Expected: 2nd request carries `cursor=c2&limit=25`; items appended; after
  `next_cursor==null` no further `/ui/activity/feed` request is issued
  (`endOfPaginationReached`).
  Traces: AC-2, AC-6.

- **TC-AND-091-03 — DTO/mapping edge cases.**
  Type: unit. Target: JVM.
  Preconditions: JSON with absent optionals (`target_type=""`, `target_id=""`,
  missing `read`, missing `metadata`), an unknown `activity_type`, and
  `next_cursor: null` / `total_unread` present.
  Steps: parse with Moshi; map to domain.
  Expected: `""` target fields -> null; missing `read` -> false; unknown type ->
  `ActivityEventType.UNKNOWN(raw)`; null cursor -> end; `total_unread` parsed; no
  crash on absent `metadata`.
  Traces: AC-2, AC-6.

- **TC-AND-091-04 — Empty feed shows empty state (not spinner/error).**
  Type: Compose-UI. Target: emu35.
  Preconditions: 200 with `items: []`, `next_cursor: null`.
  Steps: load screen.
  Expected: `LoadState.NotLoading(endOfPaginationReached=true)` + 0 items ->
  dedicated empty state; no spinner, no error.
  Traces: AC-4.

- **TC-AND-091-05 — Initial-load failure -> full-screen retryable error.**
  Type: contract/MockWebServer + Compose-UI. Target: emu35.
  Preconditions: first request returns 500 (or 422 `HTTPValidationError`); no
  Room snapshot present.
  Steps: load screen; tap Retry; enqueue a 200 page.
  Expected: refresh `LoadState.Error` -> full-screen error with Retry; retry
  issues a fresh `GET /ui/activity/feed` and renders items.
  Traces: AC-4.

- **TC-AND-091-06 — Append failure -> inline retry footer, items retained.**
  Type: Compose-UI. Target: emu35.
  Preconditions: page 1 OK (`next_cursor="c2"`); append request returns error.
  Steps: load; scroll to trigger append; tap footer Retry with a 200 enqueued.
  Expected: append `LoadState.Error` -> AND-098 inline retry footer; page-1 items
  remain; retry appends page 2.
  Traces: AC-4.

- **TC-AND-091-07 — Pull-to-refresh replaces list and returns to top.**
  Type: Compose-UI. Target: emu35.
  Preconditions: initial 2 pages loaded and scrolled down; refresh enqueues a new
  head page.
  Steps: trigger pull-to-refresh.
  Expected: list refetched from head (request has no `cursor`), replaced, scroll
  position reset to top.
  Traces: AC-3.

- **TC-AND-091-08 — Error `detail` shapes decode without crashing.**
  Type: unit. Target: JVM.
  Preconditions: three 422/4xx bodies — `detail` as string, as
  `[{"msg":"...","type":"...","loc":[...]}]`, and as `{"code":"role_required"}`.
  Steps: run each through the core-network `ApiResult` decoder.
  Expected: each yields a typed error with a human-readable message (mirrors
  `normalizeErrorDetail`); no parse crash.
  Traces: AC-4.

- **TC-AND-091-09 — Offline with cache -> stale banner; cold offline -> error.**
  Type: integration (Robolectric + in-memory Room) / instrumented. Target: JVM
  (Robolectric) with an emu35 confirmation pass.
  Preconditions: (a) Room has a prior page, network raises `IOException`; (b)
  empty Room, network raises `IOException`.
  Steps: enter screen for each.
  Expected: (a) cached rows render under stale/offline banner with manual
  refresh; (b) full-screen error (no infinite spinner).
  Traces: AC-5.

- **TC-AND-091-10 — Real-network flaky-host / airplane-mode behavior.**
  Type: instrumented/e2e. Target: **deviceA15 (must run on physical device)** —
  exercises the real OkHttp stack against the flaky plaintext dev host and a real
  radio toggle (airplane mode), which the emulator cannot faithfully reproduce.
  Preconditions: app authenticated; one prior page cached.
  Steps: load feed; enable airplane mode; pull-to-refresh; disable; retry.
  Expected: offline -> stale banner over cached rows (no crash, bounded GET retry
  honored); on reconnect, refresh succeeds and banner clears.
  Traces: AC-5.

- **TC-AND-091-11 — Surviving 401 -> auth-required, no retry loop.**
  Type: contract/MockWebServer + integration. Target: emu35.
  Preconditions: first `/ui/activity/feed` -> 401; `POST /ui/session/refresh` ->
  200; retried `/ui/activity/feed` -> 401 again.
  Steps: enter screen; observe interceptor behavior.
  Expected: exactly one refresh + one retry; surviving 401 -> `isAuthExpired`,
  auth-required state; no further refresh/retry requests (no loop).
  Traces: AC-7.

- **TC-AND-091-12 — Security: no PII/cleartext leakage; cache not backed up.**
  Type: instrumented. Target: emu35 (Robolectric acceptable for log assertions).
  Preconditions: a page whose `metadata` contains an IP; release-style logging
  config.
  Steps: load feed; capture logcat; inspect telemetry payloads; inspect backup
  config.
  Expected: no response bodies/`metadata`/IP in logs; telemetry has only
  counts/indices/coarse reasons (§10); activity table excluded from backup
  (`allowBackup=false` or `fullBackupContent` exclusion).
  Traces: AC-1 (security cross-cut over the rendered feed).

- **TC-AND-091-13 — Accessibility: TalkBack, touch targets, dynamic font, dark.**
  Type: Compose-UI + manual. Target: emu35 for automated checks; **deviceA15 for
  the manual TalkBack pass** (real screen-reader behavior).
  Preconditions: feed with mixed event types + empty/error/offline variants.
  Steps: enable TalkBack; traverse rows, empty/error/offline states; verify
  merged `contentDescription` (title + relative time + device hint), decorative
  icons (`contentDescription=null`), >=48dp targets, font scale 2.0x, dark theme,
  footer `liveRegion` announcements.
  Expected: each row announced once with combined description; no unlabeled
  actionable controls; layout intact at large font; states announced.
  Traces: AC-1, AC-3, AC-4.

- **TC-AND-091-14 — ABI/API parity smoke (arm64/API-34 vs x86_64/API-35).**
  Type: instrumented/e2e. Target: run on **deviceA15 (arm64-v8a, API 34)** and
  compare against emu35 (x86_64, API 35).
  Preconditions: same MockWebServer/dev-host scenario as TC-01/02.
  Steps: run the render+paginate happy path on both targets.
  Expected: identical parsing, paging, and rendering results across ABI and API
  level (no Moshi/Paging/Compose behavioral divergence).
  Traces: AC-1, AC-2.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (renders first page newest-first) | TC-01, TC-12, TC-13, TC-14 |
| AC-2 (paginates via `next_cursor`, stops at null) | TC-02, TC-03, TC-14 |
| AC-3 (pull-to-refresh from head, return to top) | TC-07, TC-13 |
| AC-4 (empty / initial-error / append-error states) | TC-03, TC-04, TC-05, TC-06, TC-08, TC-13 |
| AC-5 (offline cached render + stale banner) | TC-09, TC-10 |
| AC-6 (MockWebServer: path/params/verb/parse) | TC-01, TC-02, TC-03 |
| AC-7 (surviving 401 -> auth-required, no loop) | TC-11 |
