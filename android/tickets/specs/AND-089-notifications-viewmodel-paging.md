---
id: AND-089
title: Notifications ViewModel + paging
milestone: M2
epic: E12
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-084]
blocks: []
---

# AND-089 — Notifications ViewModel + paging

## 1. Overview & Goal

This ticket delivers the presentation-layer logic for the in-app notifications inbox: a Paging 3 source that lazily loads the user's notification feed from the backend, and an `unread badge` state that drives the global navigation badge and the inbox header. It is the bridge between the `notifications` repository/API layer shipped in AND-084 and the eventual notifications list UI (Compose screen, owned by a downstream E12 ticket — not this one).

The deliverable is a `NotificationsViewModel` in `feature-notifications` that exposes (a) a `Flow<PagingData<NotificationUi>>` for the paged list and (b) a `StateFlow<UnreadBadgeUiState>` for the unread count badge, plus the `PagingSource`/`RemoteMediator` plumbing that backs the paged flow. Mark-read intents and the resulting badge re-computation are coordinated here. No new endpoints or DTOs are introduced; those are owned by AND-084. The scope of AND-089 is explicitly "Paging 3 source, unread badge state," and the acceptance bar is "Paging + badge unit-tested."

Goal: a fully unit-tested, lifecycle-safe ViewModel + paging stack that any list screen can bind to with zero additional data wiring, correctly reflecting unread counts after load, mark-read, mark-all-read, and refresh.

## 2. Context & References

- Module layering: `app -> feature-notifications -> core-* (core-network, core-model, core-data, core-ui, core-testing)`. This ticket lives in `feature-notifications` and consumes the repository from `core-data`/`feature-notifications` data layer produced by AND-084.
- Upstream dependency AND-084 (Notifications API + DTOs) provides `notifications.ts`-equivalent endpoints/DTOs and the `NotificationsRepository` with `list`, `markRead`, and `unreadCount` operations. This ticket binds to that repository interface and does not redefine it.
- Downstream: the notifications list Compose screen and the alert-preferences surface (AND-088) consume the badge state. The badge is also surfaced in the bottom-nav/top-app-bar host owned by the navigation shell.
- Web reference: `frontend/src/api/endpoints/notifications.ts` and shared types in `frontend/src/api/types.ts` define the canonical field names and pagination shape; mirror them.
- Backend: FastAPI + DynamoDB, OpenAPI at `/openapi.json`. Dev host `http://18.222.237.167:8000` is plaintext HTTP and unreliable; design for ~20s timeouts, bounded backoff retry for idempotent GETs only, and offline/stale UI states.
- Auth is cookie-based with a persistent cookie jar and `X-CSRF-Token` echo; all notification calls ride the authenticated session established by the session/MFA flow. A 401 triggers a single `POST /ui/session/refresh` then retry, handled by the shared OkHttp authenticator (core-network), transparent to this ViewModel.
- Stack baseline: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11/OkHttp 4.12/Moshi 1.15, Room 2.6, Paging 3, minSdk 24.

## 3. Functional Requirements

FR-1. Expose a paged stream `notifications: Flow<PagingData<NotificationUi>>` ordered newest-first by `createdAt`, cached in `viewModelScope` via `cachedIn`.

FR-2. Page size is 20 with `prefetchDistance = 10`; `enablePlaceholders = false`. Initial load uses `initialLoadSize = 40` (Paging default ratio) but is clamped to avoid over-fetching the unreliable backend.

FR-3. Expose `badge: StateFlow<UnreadBadgeUiState>` containing the current unread `count`, a `display` string (capped, e.g. `"99+"` for counts > 99), and a `loading`/`stale` indicator. Initial value is `UnreadBadgeUiState.Loading`.

FR-4. The unread count is sourced from the repository's `unreadCount()` (server-authoritative) and refreshed on: (a) ViewModel init, (b) successful paged refresh, (c) after a mark-read or mark-all-read intent completes, and (d) on explicit `refresh()`.

FR-5. Provide `fun markAsRead(id: String)` and `fun markAllAsRead()` intents. On optimistic success, the affected item(s) flip to read locally and the badge decrements; the Paging stream is invalidated so the backing source re-reads canonical state.

FR-6. Provide `fun refresh()` that invalidates the paging source and re-fetches the unread count.

FR-7. Provide `fun retry()` that re-attempts the last failed load (delegates to the Paging `LoadState` retry lambda surfaced to the UI; this ticket exposes the mechanism, the screen wires the button).

FR-8. Map domain `Notification` to a UI model `NotificationUi` with stable `id` (from `notification_id`), the raw `created_at` epoch-seconds value for relative-timestamp formatting, read/unread flag (from `read`), a derived category (from the free-form `notification_type` string), title, body, and an optional deep-link target derived from the `data` object (there is no server `deep_link` field).

FR-9. Distinct concurrent mark-read intents must be conflated/serialized so the badge never goes negative and never double-counts.

## 4. Technical Design

Package root: `com.testlogon.android.feature.notifications`.

### 4.1 UI models

```kotlin
package com.testlogon.android.feature.notifications.model

data class NotificationUi(
    val id: String,            // maps from NotificationOut.notification_id (NOT "id")
    val category: NotificationCategory, // DERIVED from NotificationOut.notification_type (server sends a free-form string, not an enum)
    val title: String,
    val body: String,
    val isRead: Boolean,       // maps from NotificationOut.read (NOT "is_read")
    val createdAtEpochSec: Long, // CORRECTED: server created_at is epoch SECONDS (integer), not an ISO string and not ms; multiply by 1000 before java.time use
    val deepLink: String?,     // there is NO server "deep_link" field; derive from NotificationOut.data if present, else null
)

data class UnreadBadgeUiState(
    val count: Int = 0,
    val display: String = "",     // "" when 0, "n" up to 99, "99+" above
    val isLoading: Boolean = true,
    val isStale: Boolean = false, // last unreadCount fetch failed; showing cached value
) {
    companion object {
        val Loading = UnreadBadgeUiState(isLoading = true)
        fun of(count: Int, stale: Boolean = false) = UnreadBadgeUiState(
            count = count.coerceAtLeast(0),
            display = when {
                count <= 0 -> ""
                count > 99 -> "99+"
                else -> count.toString()
            },
            isLoading = false,
            isStale = stale,
        )
    }
}
```

### 4.2 Paging source

AND-084 owns the repository. This ticket implements the `PagingSource` (cursor-keyed) against it. Backend pagination is cursor-based (see §5); keys are opaque cursor strings.

```kotlin
package com.testlogon.android.feature.notifications.paging

class NotificationsPagingSource(
    private val repository: NotificationsRepository,
) : PagingSource<String, NotificationUi>() {

    override suspend fun load(
        params: LoadParams<String>,
    ): LoadResult<String, NotificationUi> = when (
        val result = repository.list(cursor = params.key, limit = params.loadSize)
    ) {
        is ApiResult.Success -> LoadResult.Page(
            data = result.value.items.map { it.toUi() },
            prevKey = null, // forward-only feed
            nextKey = result.value.nextCursor,
        )
        is ApiResult.Failure -> LoadResult.Error(result.toException())
    }

    override fun getRefreshKey(state: PagingState<String, NotificationUi>): String? = null
}
```

`getRefreshKey` returns `null` so refresh always restarts from the head of the feed (newest-first feeds re-anchor at the top). A Room-backed `RemoteMediator` is **out of scope** for this ticket; offline cache for the inbox is deferred to a downstream caching ticket. The `Pager` is constructed directly from the `PagingSource`.

### 4.3 ViewModel

```kotlin
package com.testlogon.android.feature.notifications

@HiltViewModel
class NotificationsViewModel @Inject constructor(
    private val repository: NotificationsRepository,
    @Dispatcher(IO) private val io: CoroutineDispatcher,
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0L)

    val notifications: Flow<PagingData<NotificationUi>> =
        refreshTrigger.flatMapLatest {
            Pager(
                config = PagingConfig(
                    pageSize = 20,
                    prefetchDistance = 10,
                    initialLoadSize = 40,
                    enablePlaceholders = false,
                ),
                pagingSourceFactory = { NotificationsPagingSource(repository) },
            ).flow
        }.cachedIn(viewModelScope)

    private val _badge = MutableStateFlow(UnreadBadgeUiState.Loading)
    val badge: StateFlow<UnreadBadgeUiState> = _badge.asStateFlow()

    // serializes mutating intents so the badge math is race-free
    private val intents = Channel<Intent>(Channel.UNLIMITED)

    init {
        viewModelScope.launch { processIntents() }
        refreshUnreadCount()
    }

    fun refresh() {
        refreshTrigger.value = System.currentTimeMillis()
        refreshUnreadCount()
    }

    fun markAsRead(id: String) { intents.trySend(Intent.MarkRead(id)) }
    fun markAllAsRead() { intents.trySend(Intent.MarkAllRead) }

    private fun refreshUnreadCount() = viewModelScope.launch {
        when (val r = repository.unreadCount()) {
            is ApiResult.Success -> _badge.value = UnreadBadgeUiState.of(r.value)
            is ApiResult.Failure ->
                _badge.value = _badge.value.copy(isLoading = false, isStale = true)
        }
    }

    private suspend fun processIntents() {
        for (intent in intents) when (intent) {
            is Intent.MarkRead -> {
                when (repository.markRead(intent.id)) {
                    is ApiResult.Success -> {
                        _badge.value = UnreadBadgeUiState.of(
                            (_badge.value.count - 1).coerceAtLeast(0)
                        )
                        refreshTrigger.value = System.currentTimeMillis() // invalidate page
                    }
                    is ApiResult.Failure -> refreshUnreadCount() // reconcile
                }
            }
            Intent.MarkAllRead -> {
                when (repository.markAllRead()) {
                    is ApiResult.Success -> {
                        _badge.value = UnreadBadgeUiState.of(0)
                        refreshTrigger.value = System.currentTimeMillis()
                    }
                    is ApiResult.Failure -> refreshUnreadCount()
                }
            }
        }
    }

    private sealed interface Intent {
        data class MarkRead(val id: String) : Intent
        data object MarkAllRead : Intent
    }
}
```

Notes: `flatMapLatest` over `refreshTrigger` is the canonical Paging-3 invalidation pattern — pushing a new value rebuilds the `Pager` and re-reads from the head. The `Channel`-based intent loop guarantees mark-read mutations are processed one-at-a-time, satisfying FR-9. `repository.markAllRead()` is assumed present from AND-084's "mark read" surface; if AND-084 ships only single mark-read, see Open Question OQ-2.

### 4.4 DI

`feature-notifications` provides `NotificationsViewModel` via `@HiltViewModel`; the `NotificationsRepository` binding and Retrofit service come from AND-084's module. No new Hilt module is required here beyond a `@Dispatcher(IO)` qualifier already present in `core-network`.

## 5. API Contract

This ticket introduces **no new endpoints**; the contract is owned by AND-084. It is reproduced here only as the interface this ViewModel binds to. The repository is expected to expose:

```kotlin
interface NotificationsRepository {
    suspend fun list(cursor: String?, limit: Int): ApiResult<NotificationPage>
    suspend fun markRead(id: String): ApiResult<Unit>
    suspend fun markAllRead(): ApiResult<Unit>
    suspend fun unreadCount(): ApiResult<Int>
}

data class NotificationPage(val items: List<Notification>, val nextCursor: String?)
```

Note (review): AND-084's `markRead(id)` is expected to wrap the batch endpoint by sending `{ "notification_ids": [id] }`; `unreadCount()` wraps `GET /ui/notifications/unread-count` returning the `count` field. Since the list response itself carries `unread_count`, an optional optimization (not required by this ticket) is to seed the badge from the first page rather than a separate `unreadCount()` call; the design here keeps `unreadCount()` as the authoritative source for simplicity.

Underlying endpoints, VERIFIED against the backend OpenAPI index/spec and `reference/src/api/endpoints/notifications.ts`. The draft below was corrected on review — several paths, methods, status codes, and field names were wrong:

- `GET /ui/notifications?cursor=<opaque>&limit=<n>` → `200 NotificationListResponse`. (op `list_notifications_ui_notifications_get`.) Verified shape:
  ```json
  {
    "items": [
      {
        "notification_id": "ntf_01H...",
        "notification_type": "system",
        "title": "New sign-in",
        "body": "A new device signed in to your account.",
        "data": { "route": "app://devices" },
        "read": false,
        "created_at": 1749132202,
        "batch_key": null,
        "batch_count": 1,
        "batch_actors": []
      }
    ],
    "next_cursor": "eyJwayI6...",
    "unread_count": 7
  }
  ```
  CORRECTIONS vs. draft: item key is `notification_id` (not `id`); category comes from `notification_type` string (not a `category` enum); read flag is `read` (not `is_read`); `created_at` is an **integer epoch in seconds** (not an ISO-8601 string); there is **no `deep_link` field** (deep-link must be derived from `data`); the list response ALSO carries a top-level `unread_count` integer (the spec previously ignored this — it can seed the badge on first page load, avoiding a separate call). Additional fields `data`, `batch_key`, `batch_count`, `batch_actors` exist. Only `notification_id` is required; all others are defaulted server-side. `next_cursor` is `null`/absent on the last page.
- `POST /ui/notifications/mark-read` → `200` with body `{ "ok": boolean, "marked_count": integer }`. Request body is `MarkNotificationsReadIn` = `{ "notification_ids": string[] }`. CORRECTION: this is a **batch endpoint keyed by an array of IDs**, NOT a per-id path `POST /ui/notifications/{id}/read`, and it returns `200` with a JSON body, NOT `204`. The Android `markRead(id)` should send `{ "notification_ids": [id] }`.
- `POST /ui/notifications/mark-all-read` → `200` with body `{ "ok": boolean, "marked_count": integer }`. Empty JSON body (`{}`). CORRECTION: path is `mark-all-read` (NOT `read-all`), method/response are `200` + JSON (NOT `204`). This RESOLVES OQ-2 — a bulk mark-all endpoint exists upstream.
- `GET /ui/notifications/unread-count` → `200`. The OpenAPI response schema is untyped (`{}`), but the web client (`getNotificationUnreadCount`) reads the body as `{ "count": number }`. CORRECTION: treat `{"count": N}` as the verified-by-frontend shape; flag the untyped OpenAPI as an open assumption (§16).

All endpoints take optional `user_sub` query plus `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers (impersonation/admin paths; the normal mobile client omits them). All calls send the session cookies and `X-CSRF-Token` (sourced from the `ui_csrf` cookie, per `src/api/client.ts`). FastAPI errors map via the shared `detail` mapper (`string | [{msg}] | {code,...}`) into `ApiResult.Failure`; validation failures are `422 HTTPValidationError` (`detail: [{loc, msg, type}]`). Only the `GET`s are retried with bounded backoff; `POST`s are not auto-retried (handled by repository/core-network, not here).

## 6. Data & State Management

- Source of truth for the list is the server feed, surfaced as `PagingData<NotificationUi>` and cached with `cachedIn(viewModelScope)` so configuration changes (rotation) do not re-fetch.
- Source of truth for the badge is `repository.unreadCount()`. Optimistic decrement is applied immediately on mark-read for responsiveness, then reconciled by the next authoritative fetch (after page invalidation). The count is `coerceAtLeast(0)` everywhere.
- `refreshTrigger: MutableStateFlow<Long>` is the single invalidation lever; both `refresh()` and successful mutations push to it.
- No DataStore/Room writes occur in this ticket. Unread-count persistence across cold starts and offline inbox caching are deferred (see Risks). On cold start, `badge` begins at `Loading` and resolves on first `unreadCount()`.
- `NotificationCategory` is an Android-side enum in `core-model` derived from the server's free-form `notification_type` string (the backend does NOT send a category enum). The observed `notification_type` values in the web client are `follow, like, comment, mention, tip, message, system` (see `src/pages/notifications/NotificationsPage.tsx` TYPE_ICONS map); any unrecognized value MUST map to `UNKNOWN` rather than throwing. The earlier draft's `SECURITY/ACCOUNT/BILLING` values are not in the verified contract; treat the enum mapping as an Android presentation concern keyed off the verified `notification_type` strings.

## 7. Error Handling & Resilience

- Paged load failures surface through Paging `LoadState.Error`; the screen renders error/empty/retry from `loadState` (mechanism only here; UI is downstream). `retry()` is exposed by passing the `LazyPagingItems.retry` lambda up — the ViewModel itself relies on Paging's built-in retry of the failing append/refresh.
- `unreadCount()` failure does not clear the badge: it sets `isStale = true` and keeps the last known count so the UI can show a dimmed/stale badge instead of flickering to zero.
- Mark-read failure triggers `refreshUnreadCount()` to reconcile the optimistic decrement back to server truth (no silent divergence).
- Backend is unreliable: list/unread-count `GET`s use the core-network ~20s timeout and bounded exponential backoff (idempotent only). Mutations are single-shot; the intent channel prevents pile-up.
- All `ApiResult.Failure` branches are total — no uncaught exceptions escape `viewModelScope`; a `CoroutineExceptionHandler` in the dispatcher provider is the backstop.

## 8. Security & Privacy

- No new auth surface. All requests inherit the cookie-based session and `X-CSRF-Token` header from core-network's interceptor/authenticator; a 401 triggers the single `POST /ui/session/refresh` + retry transparently.
- Notification bodies may contain sensitive security text (sign-in alerts). Do not log titles/bodies; telemetry uses ids and categories only (§10).
- Deep links are validated against an allow-list of in-app routes before navigation (handled by the nav shell); the ViewModel passes through the raw `deep_link` value without acting on it.
- No PII is written to DataStore or Room in this ticket.

## 9. Accessibility & i18n

- This ticket is logic-only; no Composables ship here. However, it defines presentation contracts that the downstream screen must honor:
  - The badge `display` string is for visual rendering only; the screen must supply a separate, fully-pluralized content description (e.g. `"%d unread notifications"` via `pluralStringResource`) — `display` ("99+") is not a valid screen-reader string.
  - `NotificationUi` carries `category` and raw `createdAtEpochMs` so the screen can localize relative timestamps and category labels via string resources; no English strings are baked into the model.
- All user-facing copy is owned by the downstream list/preferences tickets; this ticket adds none.

## 10. Telemetry & Logging

Use the `core-analytics` logger (DI-injected `AnalyticsClient`) with these events:

- `notifications_list_loaded` { page_index, item_count, source: "network" }
- `notifications_load_error` { load_type: "refresh"|"append", error_code }
- `notification_marked_read` { notification_id, category }
- `notifications_marked_all_read` { prior_unread_count }
- `notifications_unread_count` { count, stale }

Logging rules: never log notification `title`/`body`; ids and categories only. Verbose page-key/cursor logging is gated behind `BuildConfig.DEBUG`. `LoadState` transitions are logged at `debug`.

## 11. Testing Strategy

Acceptance is "Paging + badge unit-tested." Tests live in `feature-notifications/src/test` using `core-testing` (JUnit4, Turbine, `kotlinx-coroutines-test`, Paging's `cached-paging-data`/`AsyncPagingDataDiffer`, MockK).

Paging tests:
1. `load` returns `LoadResult.Page` with mapped items and correct `nextKey` from `next_cursor`.
2. `load` with `null` `next_cursor` yields `nextKey = null` (terminal page).
3. Repository `ApiResult.Failure` yields `LoadResult.Error`.
4. End-to-end via `AsyncPagingDataDiffer`: first page emits 40, append emits next 20, exhausts at terminal page.
5. `refresh()` rebuilds the source (new `pagingSourceFactory` invocation observed).

Badge tests (Turbine on `badge`):
6. Init emits `Loading` then `of(count)` from `unreadCount()`.
7. `unreadCount()` failure → `isStale = true`, count preserved.
8. `markAsRead` success decrements badge by 1 and triggers invalidation.
9. `markAsRead` on count 0 keeps badge at 0 (no negative).
10. `markAllAsRead` success → count 0.
11. Mark-read failure → badge reconciles to server `unreadCount()`.
12. Concurrent `markAsRead` x3 are serialized; final count == server-reconciled value (no double-decrement past zero).
13. `display` formatting: 0 → "", 5 → "5", 150 → "99+".

Use `StandardTestDispatcher` + `runTest`; inject a `TestDispatcher` via the `@Dispatcher(IO)` qualifier. Target ≥ 90% line coverage on `NotificationsViewModel`, `NotificationsPagingSource`, and the mapper.

## 12. Dependencies & Sequencing

- **Depends on AND-084** (Notifications API + DTOs): provides `NotificationsRepository`, `Notification` domain model, DTOs, and `NotificationPage`. AND-089 cannot merge before AND-084's repository interface lands.
- Transitively depends on AND-027 (core-network/ApiResult plumbing, via AND-084).
- **Blocks** the downstream notifications list Compose screen (E12) and informs the badge consumed by the navigation shell. Not a hard blocker for AND-088 (alert preferences) but shares the `feature-notifications` module.
- Library prerequisite: `androidx.paging:paging-runtime` + `paging-compose` and `androidx.paging:paging-testing` already on the version catalog from the M2 baseline; if absent, add to `gradle/libs.versions.toml` as part of this ticket.

## 13. Risks & Open Questions

- OQ-1: RESOLVED on review — the feed IS cursor-based. `NotificationListResponse.next_cursor` is `string | null`, confirmed in both the OpenAPI schema (`components.schemas.NotificationListResponse`) and `src/api/types.ts`. The `GET /ui/notifications` params are `cursor` + `limit`. Keep `PagingSource<String, _>`; no offset variant needed.
- OQ-2: RESOLVED on review — `POST /ui/notifications/mark-all-read` exists (op `mark_all_read_ui_notifications_mark_all_read_post`) and is used by the web client (`markAllNotificationsRead`). `markAllAsRead()` is safe to keep; no per-id fan-out required. Note: mark-read is itself a batch endpoint (`notification_ids: []`), so even single mark-read goes through the batch shape.
- OQ-3: Push-driven badge updates — when an FCM notification arrives while the app is foregrounded, should the badge live-update? Current design only refreshes on user actions/refresh. Live push reconciliation is deferred to the push ticket.
- Risk: optimistic decrement can briefly diverge from server truth on flaky network; mitigated by post-mutation invalidation + reconcile, but a rapid mark-read burst on a slow backend may show a transiently stale count. Acceptable for M2.
- Risk: no offline cache means cold start with no network shows an empty/error inbox; flagged for a future Room `RemoteMediator` ticket.

## 14. Acceptance Criteria

AC-1. `NotificationsViewModel` exposes `notifications: Flow<PagingData<NotificationUi>>` (cached in `viewModelScope`) and `badge: StateFlow<UnreadBadgeUiState>`.
AC-2. `NotificationsPagingSource.load` maps repository results to `LoadResult.Page` with correct `nextKey` and emits `LoadResult.Error` on failure — covered by unit tests.
AC-3. Badge initializes to `Loading`, resolves to the server unread count, and formats `0/n/99+` correctly — unit-tested.
AC-4. `markAsRead` decrements the badge (never below 0), invalidates the paged feed, and reconciles on failure — unit-tested.
AC-5. `markAllAsRead` sets the badge to 0 on success and invalidates the feed — unit-tested.
AC-6. `unreadCount()` failure yields `isStale = true` with the prior count preserved — unit-tested.
AC-7. Concurrent mark-read intents are serialized with no negative or double-counted badge — unit-tested.
AC-8. `refresh()` rebuilds the paging source and re-fetches the unread count — unit-tested.
AC-9. No notification title/body is logged; telemetry events fire with ids/categories only.
AC-10. All package declarations use `com.testlogon.android.feature.notifications`.

## 15. Definition of Done

- All AC met; the paging + badge unit suite (≥ 13 cases, §11) passes in CI on the `android-port` branch.
- Code in `feature-notifications` compiles against the AND-084 repository interface with no new endpoint definitions.
- ktlint/detekt clean; no new public API lacks KDoc on `NotificationsViewModel`, `UnreadBadgeUiState`, and `NotificationsPagingSource`.
- Hilt graph resolves; `NotificationsViewModel` is injectable into a host screen with no manual wiring.
- Test coverage ≥ 90% on the three core classes; tests use injected test dispatchers (no real delays).
- No `BuildConfig.DEBUG`-gated logs leak notification content; telemetry events verified in tests or via a fake `AnalyticsClient`.
- Open questions OQ-1/OQ-2 resolved or explicitly ticketed before merge; PR description links AND-084 and notes any pagination-shape adjustment.
- Reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI index `reference/openapi.index.txt`, OpenAPI spec `reference/openapi.pretty.json` (schemas under `components.schemas.<Name>`), and frontend `reference/src/...`.

1. **List endpoint is `GET /ui/notifications` with `cursor` + `limit` query params, returning `NotificationListResponse`.** — Verified. OpenAPI `GET /ui/notifications` (op `list_notifications_ui_notifications_get`, `resp=200:NotificationListResponse`, `params=cursor,limit,user_sub,...`); frontend `src/api/endpoints/notifications.ts: getNotifications`.
2. **`NotificationListResponse = { items: NotificationOut[], next_cursor?: string|null, unread_count: int }`.** — Verified (and the draft was incomplete: it omitted `unread_count`). `components.schemas.NotificationListResponse`; `src/api/types.ts: NotificationListResponse`.
3. **Feed pagination is cursor-based with opaque `next_cursor` (null on last page).** — Verified. `components.schemas.NotificationListResponse.next_cursor` (`anyOf string|null`); `src/api/types.ts` line ~5272. (Resolves OQ-1.)
4. **Notification item key is `notification_id` (NOT `id`).** — Corrected. `components.schemas.NotificationOut` requires `notification_id`; `src/api/types.ts: NotificationOut`. Draft used `id`.
5. **Read flag is `read` (NOT `is_read`).** — Corrected. `components.schemas.NotificationOut.read` (boolean, default false); `src/api/types.ts: NotificationOut.read`. Draft used `is_read`.
6. **`created_at` is an integer epoch in SECONDS (NOT an ISO-8601 string, NOT ms).** — Corrected. `components.schemas.NotificationOut.created_at` (`type: integer`, default 0); `src/pages/notifications/NotificationsPage.tsx: formatTimeAgo` computes `Date.now()/1000 - ts`, confirming seconds. Draft modeled an ISO string and `createdAtEpochMs`.
7. **There is no server `deep_link` field; category is not a server enum.** — Corrected. `components.schemas.NotificationOut` has `notification_type` (free-form string) and a generic `data` object; no `deep_link`, no `category`. Deep-link must be derived from `data`. `src/pages/notifications/NotificationsPage.tsx` keys icons off `notification_type` (follow/like/comment/mention/tip/message/system).
8. **Mark-read is a batch endpoint `POST /ui/notifications/mark-read` with body `{ notification_ids: string[] }`, response `200 { ok, marked_count }`.** — Corrected. OpenAPI `POST /ui/notifications/mark-read` (op `mark_read_...`, `req=MarkNotificationsReadIn`); `components.schemas.MarkNotificationsReadIn = { notification_ids: string[] }`; `src/api/endpoints/notifications.ts: markNotificationsRead` returns `{ ok, marked_count }`. Draft claimed `POST /ui/notifications/{id}/read` → `204`.
9. **Mark-all-read is `POST /ui/notifications/mark-all-read` (empty body), response `200 { ok, marked_count }`.** — Corrected. OpenAPI `POST /ui/notifications/mark-all-read` (op `mark_all_read_...`); `src/api/endpoints/notifications.ts: markAllNotificationsRead`. Draft used `read-all` and `204`. (Resolves OQ-2.)
10. **Unread-count is `GET /ui/notifications/unread-count`, body `{ count: number }`.** — Verified by frontend / Unverified by OpenAPI typing. OpenAPI `GET /ui/notifications/unread-count` exists (op `get_unread_count_...`) but its `200` schema is empty `{}` (untyped) at `paths./ui/notifications/unread-count`. Frontend `src/api/endpoints/notifications.ts: getNotificationUnreadCount` reads `{ count: number }`; a separate `components.schemas.UnreadCountResponse = { count }` exists and is used by sibling unread-count endpoints (`/ui/activity/feed/unread-count`, `/ui/alerts/unread-count`). Treated as verified-by-frontend.
11. **Auth: CSRF via `X-CSRF-Token` header sourced from the `ui_csrf` cookie; cookie-based session.** — Verified. `src/api/client.ts` lines ~168-171 (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`) and `credentials: "include"`.
12. **401 triggers a single `POST /ui/session/refresh` then one retry, then logout on repeat 401.** — Verified. `src/api/client.ts: refreshSession` (`POST /ui/session/refresh`) and the single-flight `refreshPromise` + retry block (lines ~119-237).
13. **FastAPI error `detail` mapper handles `string | [{msg}] | {code,...}`; validation errors are `422 HTTPValidationError`.** — Verified. `src/api/client.ts: normalizeErrorDetail` (string/array-of-{msg}/object-with-code branches); OpenAPI `GET /ui/notifications` lists `422:HTTPValidationError`; `components.schemas.HTTPValidationError.detail = [{loc,msg,type}]`.
14. **Optimistic mark-read + invalidate-then-reconcile pattern matches the web client's behavior.** — Verified (analogous). `src/pages/notifications/NotificationsPage.tsx` invalidates both the list and unread-count queries on mark-read/mark-all success (`onSuccess` invalidateQueries). The web client invalidates rather than optimistically decrementing; the Android optimistic decrement is an additive UX choice reconciled by the same invalidation — labeled an assumption below.
15. **Paging 3 `flatMapLatest(refreshTrigger){ Pager(...).flow }.cachedIn(viewModelScope)` invalidation pattern.** — Verified (framework ref). Android Paging 3 docs: https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data (invalidation / `cachedIn`). `PagingConfig`/`PagingSource`/`getRefreshKey`: https://developer.android.com/reference/kotlin/androidx/paging/PagingSource .
16. **`@HiltViewModel` injection of a `NotificationsViewModel` with an injected `CoroutineDispatcher`.** — Verified (framework ref). Hilt + ViewModel: https://developer.android.com/training/dependency-injection/hilt-jetpack . `viewModelScope`: https://developer.android.com/topic/libraries/architecture/coroutines#viewmodelscope .
17. **minSdk 24 / Paging-testing harness (`AsyncPagingDataDiffer`, `paging-testing`).** — Verified (framework ref). https://developer.android.com/reference/kotlin/androidx/paging/testing/package-summary .

### Corrections made

- §4.1 `NotificationUi`: `id` now documented as mapping from `notification_id`; `isRead` from `read`; `createdAtEpochMs` → `createdAtEpochSec` (server sends epoch seconds); `category` documented as derived from `notification_type` string; `deepLink` documented as derived from `data` (no server `deep_link`).
- §4 / §6: `NotificationCategory` clarified as an Android-side derived enum keyed off the verified `notification_type` strings; removed reliance on the unverified `SECURITY/ACCOUNT/BILLING` values.
- §5 API Contract: corrected the list-item field names and `created_at` type; added the previously-missing `unread_count` on the list response and the `data/batch_*` fields; corrected mark-read to the batch path `POST /ui/notifications/mark-read` (`notification_ids[]`, `200` JSON) instead of `POST /ui/notifications/{id}/read` (`204`); corrected mark-all to `POST /ui/notifications/mark-all-read` (`200` JSON) instead of `read-all` (`204`); documented `unread-count` body and the untyped OpenAPI caveat; added `user_sub`/`X-SESSION-ID`/`X-IMPERSONATION-TOKEN` params and the `422 HTTPValidationError` shape.
- §13: OQ-1 and OQ-2 marked RESOLVED with sources.

### Open assumptions

- **Unread-count response is exactly `{ count: int }`.** OpenAPI types the `200` body as empty `{}`; only the frontend confirms `{ count }`. If the deployed backend differs, AND-084's `unreadCount()` mapping must adapt. (Unverifiable from OpenAPI alone.)
- **Optimistic badge decrement on mark-read.** The web client does not decrement optimistically — it invalidates and refetches. The Android optimistic-then-reconcile behavior (FR-5/FR-9) is an additive UX decision, not mirrored from the reference app.
- **`deepLink` derivation from `data`.** The exact key inside `data` carrying a route is not specified by the schema (`data` is `additionalProperties: true`). Mapping logic is an assumption to confirm with AND-084 / backend owners.
- **Cursor opacity / ordering newest-first.** `next_cursor` is opaque and ordering is not asserted by the schema; newest-first is inferred from inbox semantics and the web "Load more" forward-only paging. Treated as an assumption pending backend confirmation.
- **AND-084 repository surface** (`list/markRead/markAllRead/unreadCount` returning `ApiResult`). Not present in this repo to verify; assumed per the dependency. If AND-084 exposes only the batch `markRead(ids: List<String>)` rather than `markRead(id: String)`, this ViewModel adapts trivially.
- **Retry/backoff + 20s timeout + `X-CSRF-Token` echo on Android.** These are core-network (AND-027) concerns asserted by the spec; the web client confirms CSRF/refresh semantics but Android transport tuning is not verifiable from the reference sources.

## 17. Test Plan

All cases are JVM-local unless noted. The acceptance bar is "Paging + badge unit-tested," so the suite is dominated by JVM unit + contract tests; instrumented/emulator/device cases are included only where they add real coverage (this ticket ships no Composables, so most device-class testing is downstream). Test IDs trace to the §14 Acceptance Criteria.

Targets legend: **JVM** = local JVM unit / Robolectric (no device); **MWS** = contract test with OkHttp `MockWebServer` exercising the AND-084 service mapping; **emulator** = headless AVD `test35` (API 35, x86_64); **device** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a).

- **TC-AND-089-01** — Type: unit (JVM). Target: `NotificationsPagingSource`. Preconditions: fake `NotificationsRepository.list` returns `ApiResult.Success(NotificationPage(items=20, nextCursor="c2"))`. Steps: call `load(LoadParams.Refresh(key=null, loadSize=40))`. Expected: `LoadResult.Page` with 20 mapped `NotificationUi`, `prevKey=null`, `nextKey="c2"`; mapping preserves `notification_id→id`, `read→isRead`, `created_at→createdAtEpochSec`. Traces: AC-2.
- **TC-AND-089-02** — Type: unit (JVM). Target: `NotificationsPagingSource`. Preconditions: `list` returns `nextCursor=null`. Steps: `load` a refresh. Expected: `LoadResult.Page` with `nextKey=null` (terminal page). Traces: AC-2.
- **TC-AND-089-03** — Type: unit (JVM). Target: `NotificationsPagingSource`. Preconditions: `list` returns `ApiResult.Failure` (mapped from a `422 HTTPValidationError`/`500`). Steps: `load`. Expected: `LoadResult.Error` carrying the mapped exception; no crash. Traces: AC-2.
- **TC-AND-089-04** — Type: unit (JVM, `AsyncPagingDataDiffer` + `runTest`). Target: `NotificationsViewModel.notifications`. Preconditions: fake repo yields page1 (40 items, nextCursor="c2"), page2 (20 items, nextCursor=null). Steps: collect `PagingData`, assert initial 40, trigger append, assert next 20, assert terminal. Expected: items in order, no duplicates, append stops at terminal. Traces: AC-1, AC-2.
- **TC-AND-089-05** — Type: unit (JVM, Turbine on `badge`). Target: `NotificationsViewModel.badge`. Preconditions: `unreadCount()` returns `Success(7)`. Steps: construct VM, collect `badge`. Expected: first emission `UnreadBadgeUiState.Loading`, then `of(7)` with `display="7"`, `isLoading=false`, `isStale=false`. Traces: AC-1, AC-3.
- **TC-AND-089-06** — Type: unit (JVM). Target: `UnreadBadgeUiState.of` formatting. Preconditions: none. Steps: evaluate `of(0)`, `of(5)`, `of(150)`, `of(-3)`. Expected: `display` = `""`, `"5"`, `"99+"`, `""` respectively and `count` coerced ≥ 0 (`-3→0`). Traces: AC-3.
- **TC-AND-089-07** — Type: unit (JVM, Turbine). Target: `NotificationsViewModel.markAsRead`. Preconditions: badge resolved at 7; `repository.markRead(id)` returns `Success`. Steps: call `markAsRead("ntf_1")`; advance dispatcher. Expected: badge decrements to 6 optimistically; `refreshTrigger` fires (paging invalidation observable via new `pagingSourceFactory` call); repo received `notification_ids=["ntf_1"]` (verify via captured arg). Traces: AC-4, AC-8.
- **TC-AND-089-08** — Type: unit (JVM, Turbine). Target: `markAsRead` floor. Preconditions: badge resolved at 0; `markRead` returns `Success`. Steps: call `markAsRead("x")`. Expected: badge stays at 0 (no negative), `display=""`. Traces: AC-4, AC-7.
- **TC-AND-089-09** — Type: unit (JVM, Turbine). Target: `markAllAsRead`. Preconditions: badge at 7; `markAllRead()` returns `Success`. Steps: call `markAllAsRead()`. Expected: badge → `of(0)` (`display=""`), `refreshTrigger` fires. Traces: AC-5.
- **TC-AND-089-10** — Type: unit (JVM, Turbine). Target: `unreadCount()` failure path. Preconditions: badge previously resolved at 7; next `unreadCount()` returns `Failure`. Steps: call `refresh()`. Expected: badge keeps `count=7`, `isStale=true`, `isLoading=false` (no flicker to 0). Traces: AC-6.
- **TC-AND-089-11** — Type: unit (JVM, Turbine). Target: `markAsRead` failure reconcile. Preconditions: badge at 7; `markRead` returns `Failure`; subsequent `unreadCount()` returns `Success(7)`. Steps: call `markAsRead("x")`. Expected: optimistic decrement is reconciled back to server truth 7 via `refreshUnreadCount()`; no silent divergence. Traces: AC-4, AC-6.
- **TC-AND-089-12** — Type: unit (JVM, `StandardTestDispatcher`). Target: intent serialization (FR-9). Preconditions: badge at 3; three `markAsRead` calls fired without advancing; `markRead` each returns `Success`. Steps: fire 3 intents, then `advanceUntilIdle()`. Expected: intents processed one-at-a-time via the channel; final count = 0 (3→2→1→0), never negative, no double-decrement; repo called exactly 3 times. Traces: AC-7.
- **TC-AND-089-13** — Type: unit (JVM, Turbine + differ). Target: `refresh()`. Preconditions: VM constructed; spy `pagingSourceFactory`. Steps: call `refresh()`. Expected: a new `PagingSource` instance is created (factory re-invoked via `refreshTrigger`) AND `unreadCount()` is re-fetched (badge re-resolves). Traces: AC-8.
- **TC-AND-089-14** — Type: contract / MockWebServer (JVM). Target: AND-084 service mapping consumed by the paging source (boundary contract). Preconditions: `MockWebServer` enqueues the verified `200 NotificationListResponse` JSON (snake_case, `created_at` integer seconds, `unread_count`), a `200 {ok,marked_count}` for `mark-read`, and `{count:N}` for `unread-count`. Steps: drive `list`/`markRead`/`unreadCount` through the real Retrofit/Moshi stack; assert the request to `mark-read` carries body `{"notification_ids":["ntf_1"]}` and header `X-CSRF-Token`. Expected: snake_case → camelCase mapping correct; `created_at` interpreted as seconds; CSRF header present; paths exactly `/ui/notifications`, `/ui/notifications/mark-read`, `/ui/notifications/unread-count`. Traces: AC-1, AC-2, AC-4.
- **TC-AND-089-15** — Type: contract / MockWebServer (JVM). Target: error-shape handling. Preconditions: `MockWebServer` returns `422` with `{"detail":[{"loc":["query","limit"],"msg":"...","type":"..."}]}`, then a `500`, then a connection drop (simulating the flaky dev host `18.222.237.167:8000`). Steps: call `list` for each. Expected: each maps to `ApiResult.Failure` → `LoadResult.Error` (no crash); the dropped-connection/offline case surfaces as `Error` and `unreadCount` failure sets `isStale=true` rather than zeroing the badge. Traces: AC-2, AC-6.
- **TC-AND-089-16** — Type: unit (JVM). Target: telemetry + logging redaction. Preconditions: fake `AnalyticsClient`; logger spy; load a page then `markAsRead`. Steps: exercise load-success, load-error, mark-read; capture analytics events and any log output. Expected: `notifications_list_loaded`/`notification_marked_read`/`notifications_unread_count` fire with ids+categories only; assert NO event or log line contains a notification `title` or `body`. Traces: AC-9.
- **TC-AND-089-17** — Type: unit (JVM, package assertion / lint). Target: package naming. Steps: reflectively assert `NotificationsViewModel`, `NotificationsPagingSource`, `NotificationUi`, `UnreadBadgeUiState` declare package `com.testlogon.android.feature.notifications(.*)`; ktlint/detekt run clean. Expected: all in the required root package; lint clean. Traces: AC-10.
- **TC-AND-089-18** — Type: instrumented (emulator `test35`). Target: lifecycle safety of `cachedIn(viewModelScope)`. Preconditions: host an `Activity`/`Fragment` collecting `notifications`; trigger a configuration change (rotation). Steps: rotate, re-collect. Expected: no re-fetch of page 1 (cached `PagingData` survives), no crash, `viewModelScope` not leaked. Runs on emulator (no real hardware needed). Traces: AC-1, AC-8.

Note on device usage: this ticket is logic-only with no camera/biometric/push/WebRTC/Telecom surface, so the physical Galaxy A15 is NOT required for any case here. The arm64-vs-x86 / API-34-vs-35 concern is moot for pure-Kotlin coroutine/Paging logic; emulator coverage (TC-18) is sufficient. Real-device push-driven badge live-update is explicitly deferred (OQ-3) to the push ticket and is out of this ticket's scope.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (exposes paged flow + badge StateFlow) | TC-04, TC-05, TC-14, TC-18 |
| AC-2 (PagingSource maps Page/Error, nextKey) | TC-01, TC-02, TC-03, TC-04, TC-14, TC-15 |
| AC-3 (badge Loading→count, 0/n/99+ format) | TC-05, TC-06 |
| AC-4 (markAsRead decrements, invalidates, reconciles) | TC-07, TC-08, TC-11, TC-14 |
| AC-5 (markAllAsRead → 0, invalidates) | TC-09 |
| AC-6 (unreadCount failure → isStale, count preserved) | TC-10, TC-11, TC-15 |
| AC-7 (concurrent mark-read serialized, no negative/double) | TC-08, TC-12 |
| AC-8 (refresh rebuilds source + refetches count) | TC-07, TC-09, TC-13, TC-18 |
| AC-9 (no title/body logged; ids/categories only) | TC-16 |
| AC-10 (package `com.testlogon.android.feature.notifications`) | TC-17 |
