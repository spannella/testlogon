---
id: AND-089
title: Notifications ViewModel + paging
milestone: M2
epic: E12
priority: P0
size: M
status: draft
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

FR-8. Map domain `Notification` to a UI model `NotificationUi` with stable `id`, formatted relative timestamp source fields, read/unread flag, category, title, body, and optional deep-link target.

FR-9. Distinct concurrent mark-read intents must be conflated/serialized so the badge never goes negative and never double-counts.

## 4. Technical Design

Package root: `com.testlogon.android.feature.notifications`.

### 4.1 UI models

```kotlin
package com.testlogon.android.feature.notifications.model

data class NotificationUi(
    val id: String,
    val category: NotificationCategory,
    val title: String,
    val body: String,
    val isRead: Boolean,
    val createdAtEpochMs: Long,
    val deepLink: String?, // app:// route or null
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

Underlying endpoints (mirroring `frontend/src/api/endpoints/notifications.ts`; confirm against `/openapi.json`):

- `GET /ui/notifications?cursor=<opaque>&limit=20` → `200`
  ```json
  {
    "items": [
      {
        "id": "ntf_01H...",
        "category": "security",
        "title": "New sign-in",
        "body": "A new device signed in to your account.",
        "is_read": false,
        "created_at": "2026-06-05T14:03:22Z",
        "deep_link": "app://devices"
      }
    ],
    "next_cursor": "eyJwayI6..."
  }
  ```
  `next_cursor` is `null` on the last page.
- `POST /ui/notifications/{id}/read` → `204` (idempotent).
- `POST /ui/notifications/read-all` → `204`.
- `GET /ui/notifications/unread-count` → `200 {"count": 7}`.

All calls send the session cookies and `X-CSRF-Token`. FastAPI errors map via the shared `detail` mapper (`string | [{msg}] | {code,...}`) into `ApiResult.Failure`. Only the two `GET`s are retried with bounded backoff; `POST`s are not auto-retried (handled by repository/core-network, not here).

## 6. Data & State Management

- Source of truth for the list is the server feed, surfaced as `PagingData<NotificationUi>` and cached with `cachedIn(viewModelScope)` so configuration changes (rotation) do not re-fetch.
- Source of truth for the badge is `repository.unreadCount()`. Optimistic decrement is applied immediately on mark-read for responsiveness, then reconciled by the next authoritative fetch (after page invalidation). The count is `coerceAtLeast(0)` everywhere.
- `refreshTrigger: MutableStateFlow<Long>` is the single invalidation lever; both `refresh()` and successful mutations push to it.
- No DataStore/Room writes occur in this ticket. Unread-count persistence across cold starts and offline inbox caching are deferred (see Risks). On cold start, `badge` begins at `Loading` and resolves on first `unreadCount()`.
- `NotificationCategory` is an enum in `core-model` (`SECURITY, ACCOUNT, BILLING, SYSTEM, UNKNOWN`); unknown server values map to `UNKNOWN` rather than throwing.

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

- OQ-1: Pagination shape — confirm against `/openapi.json` whether the feed is cursor-based (`next_cursor`) or offset/page-number. Design assumes opaque cursor; if offset, swap `PagingSource<String, _>` for `PagingSource<Int, _>` and compute `getRefreshKey` from anchor position.
- OQ-2: Does AND-084 expose `markAllRead()`? If only single mark-read exists, `markAllAsRead()` must either be removed from this ticket or fan-out per-id (poor). Prefer adding the bulk endpoint upstream.
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
