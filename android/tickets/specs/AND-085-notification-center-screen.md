---
id: AND-085
title: Notification center screen
milestone: M2
epic: E12
priority: P0
size: M
status: draft
depends_on: [AND-084, AND-098]
blocks: []
---

# AND-085 — Notification center screen

## 1. Overview & Goal

Implement the authenticated **Notification Center** screen for the TestLogon Android app: a vertically scrolling, **Paging 3**-backed list of the signed-in user's notifications, each rendered with a read/unread visual treatment, a relative timestamp, and a tap target that **deep-links** to the resource the notification references. The screen exposes a **mark-all-read** action and supports per-item read-on-tap, pull-to-refresh, and the standard loading / empty / error / offline-stale states required for the unreliable dev backend.

This ticket owns the **presentation layer only**: the `NotificationsViewModel`, its `NotificationsUiState`, the Compose `NotificationCenterScreen`, the row composable, the deep-link resolution helper, and the wiring of the `Pager`/`PagingSource` into a `Flow<PagingData<NotificationUi>>`. All networking, DTO definitions, domain mapping, and the `NotificationsRepository` (list, mark-read, mark-all-read, unread-count) are delivered by **AND-084** and are consumed unchanged. The Paging 3 source + UI footer patterns (refresh, append loading/error footers) follow the conventions established in **AND-098**.

Goal acceptance (from backlog): *Renders + paginates; tap routes correctly.*

## 2. Context & References

- **Module:** `feature-notifications` (new screen-layer additions; the data layer already lives here from AND-084).
- **Namespace:** `com.testlogon.android.feature.notifications`.
- **Layering:** `app → feature-notifications → core-* (core-ui, core-model, core-data)`. The screen depends on `core-ui` (Material 3 theme, shared state composables from AND-021, `ApiResult` helpers from AND-018) and `core-model` (domain `Notification` type). It MUST NOT depend on `core-network` directly; all I/O flows through `NotificationsRepository`.
- **Dependencies:**
  - **AND-084 — Notifications API + DTOs:** provides `NotificationsApi`, the DTO/adapter layer mapping `notifications.ts`, the domain model `Notification`, and `NotificationsRepository` exposing `notificationsPagingSource()`, `markRead(id)`, `markAllRead()`, and `unreadCount()`. This ticket only calls those methods.
  - **AND-098 — Feed list (Paging 3):** establishes the canonical Paging 3 wiring (Pager config, `LazyPagingItems` collection, append/refresh footer composables, error retry). This screen reuses those `core-ui` paging footer composables and the same `Pager` configuration conventions.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Paging 3, Coil (notification icons/avatars). minSdk 24, compileSdk/targetSdk 35, JDK 17.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). Cookie-based session + `X-CSRF-Token`; 401 → single `POST /ui/session/refresh` retry handled by the OkHttp interceptor/Authenticator stack (AND-013, out of scope here). OpenAPI at `/openapi.json`.
- **Web reference:** `frontend/src/api/endpoints/notifications.ts`, shared types in `frontend/src/api/types.ts`. AND-084 is the authority for exact DTO field names and domain mapping; the JSON shapes in §5 mirror that reference for navigation context only.

## 3. Functional Requirements

1. **Paged list.** Render notifications newest-first in a `LazyColumn` driven by `LazyPagingItems<NotificationUi>`. Pages are fetched on demand as the user scrolls (cursor- or page-based, per AND-084's `PagingSource`). Page size 20.
2. **Read/unread treatment.** Unread items are visually distinct: a leading unread dot indicator, a tinted row background (`MaterialTheme.colorScheme.surfaceVariant` at reduced alpha), and a heavier title weight (`FontWeight.SemiBold`). Read items use the default surface, normal weight, and no dot.
3. **Read-on-tap.** Tapping a row (a) optimistically marks it read in the UI, (b) calls `repository.markRead(id)`, and (c) navigates to the notification's deep-link target (§3.5). The read state must survive the navigation round-trip and a subsequent refresh.
4. **Mark-all-read.** A top-app-bar action (overflow or trailing icon) invokes `repository.markAllRead()`, optimistically flips all loaded rows to read, and clears the screen's unread badge. The action is disabled when the visible unread count is zero.
5. **Tap → deep-link routing.** Each notification carries a typed target derived from its `type` + `data` payload. The screen resolves it to an in-app `NavController` route. Supported targets at minimum:
   - `PROFILE` → public profile route (`AND-073`), keyed by `u_identifier`.
   - `FEED_ITEM` → feed detail/feed list (`AND-098`), keyed by item id.
   - `SESSIONS` → active sessions screen (`AND-043`).
   - `SETTINGS` → settings hub (`AND-077`).
   - `UNKNOWN` → no navigation; row is still markable-read and shows a generic icon.
6. **Pull-to-refresh.** A `PullToRefreshBox` triggers `lazyPagingItems.refresh()`; the indicator clears when the refresh `LoadState` settles.
7. **Append footers.** While appending, show a loading footer row; on append error, show a retry footer that calls `lazyPagingItems.retry()`.
8. **Empty state.** When the initial load settles with zero items, show the shared `EmptyState` composable (AND-021): icon, "No notifications yet" headline, supporting text.
9. **Error & offline.** Initial-load failure shows the shared `ErrorState`/`OfflineState` (AND-021) with a retry that calls `refresh()`. Stale cached data, if present from AND-084's Room cache, renders behind an offline banner rather than a blank error.
10. **Entry point.** Reachable from the authenticated graph (top-bar bell icon on Dashboard / More hub) via route `notifications`. Back navigation returns to the launching destination.

## 4. Technical Design

**Route & navigation.** Register in the authenticated nav graph (AND-024):

```kotlin
const val NotificationsRoute = "notifications"

fun NavGraphBuilder.notificationCenterScreen(navController: NavController) {
    composable(NotificationsRoute) {
        NotificationCenterScreen(
            onNavigateTarget = { target -> navController.navigateToTarget(target) },
            onBack = { navController.popBackStack() },
        )
    }
}
```

**UI model.** A lightweight presentation model adapts the domain `Notification` (from core-model). Mapping happens in the ViewModel via `PagingData.map`.

```kotlin
data class NotificationUi(
    val id: String,
    val title: String,
    val body: String?,
    val createdAtEpochMs: Long,
    val isRead: Boolean,
    val iconUrl: String?,          // Coil
    val target: NotificationTarget // resolved deep-link
)

sealed interface NotificationTarget {
    data class Profile(val uIdentifier: String) : NotificationTarget
    data class FeedItem(val itemId: String) : NotificationTarget
    data object Sessions : NotificationTarget
    data object Settings : NotificationTarget
    data object Unknown : NotificationTarget
}
```

**Target resolution.** A pure helper maps domain `type` + `data` to a `NotificationTarget`; it is the unit-test seam for §3.5.

```kotlin
object NotificationTargetResolver {
    fun resolve(type: String, data: Map<String, String?>): NotificationTarget = when (type) {
        "profile.follow", "profile.mention" ->
            data["u_identifier"]?.let(NotificationTarget::Profile) ?: NotificationTarget.Unknown
        "feed.comment", "feed.like" ->
            data["item_id"]?.let(NotificationTarget::FeedItem) ?: NotificationTarget.Unknown
        "session.new_login" -> NotificationTarget.Sessions
        "account.security"  -> NotificationTarget.Settings
        else -> NotificationTarget.Unknown
    }
}
```

**ViewModel.** Hilt-injected; exposes the paged flow plus an overlay state for the top-bar action and one-shot navigation events. Optimistic read state is held in a `MutableStateFlow<Set<String>>` of locally-read ids that is merged into the paged data via `PagingData.map`, so a server round-trip is not required to reflect the tap.

```kotlin
@HiltViewModel
class NotificationsViewModel @Inject constructor(
    private val repository: NotificationsRepository,
) : ViewModel() {

    private val locallyRead = MutableStateFlow<Set<String>>(emptySet())
    private val allReadFlag = MutableStateFlow(false)

    val pagedNotifications: Flow<PagingData<NotificationUi>> =
        repository.notificationsPagingSource()             // Flow<PagingData<Notification>>
            .cachedIn(viewModelScope)
            .combine(locallyRead) { paging, readIds ->
                paging.map { it.toUi(forcedRead = it.id in readIds || allReadFlag.value) }
            }

    val uiState: StateFlow<NotificationsUiState> = /* unread count + action enablement */ ...

    private val _events = Channel<NotificationsEvent>(Channel.BUFFERED)
    val events: Flow<NotificationsEvent> = _events.receiveAsFlow()

    fun onItemClick(item: NotificationUi) {
        locallyRead.update { it + item.id }
        viewModelScope.launch { repository.markRead(item.id) }   // fire-and-confirm
        if (item.target != NotificationTarget.Unknown) {
            _events.trySend(NotificationsEvent.Navigate(item.target))
        }
    }

    fun onMarkAllRead() {
        allReadFlag.value = true
        viewModelScope.launch {
            when (val r = repository.markAllRead()) {
                is ApiResult.Failure -> { allReadFlag.value = false; _events.trySend(NotificationsEvent.Error(r.error)) }
                is ApiResult.Success -> Unit
            }
        }
    }
}

sealed interface NotificationsEvent {
    data class Navigate(val target: NotificationTarget) : NotificationsEvent
    data class Error(val error: ApiError) : NotificationsEvent
}
```

**Composable.** `NotificationCenterScreen` collects `pagedNotifications` via `collectAsLazyPagingItems()`, wires the `PullToRefreshBox`, and renders rows plus append/refresh footers from the shared paging composables (AND-098/core-ui). Navigation events are consumed in a `LaunchedEffect` that calls `onNavigateTarget`.

```kotlin
@Composable
fun NotificationCenterScreen(
    onNavigateTarget: (NotificationTarget) -> Unit,
    onBack: () -> Unit,
    viewModel: NotificationsViewModel = hiltViewModel(),
)

@Composable
private fun NotificationRow(item: NotificationUi, onClick: () -> Unit)
```

## 5. API Contract

This ticket performs **no direct HTTP calls**; the contract is owned by **AND-084**. The shapes below are reproduced only to document the navigation-relevant fields the UI consumes.

- **List (paged):** `GET /ui/notifications?cursor={cursor}&limit=20`
```json
{
  "items": [
    {
      "id": "ntf_01H...",
      "type": "feed.comment",
      "title": "Ada commented on your post",
      "body": "Nice work!",
      "is_read": false,
      "created_at": "2026-06-05T14:02:11Z",
      "icon_url": "https://.../avatar.png",
      "data": { "item_id": "post_123", "u_identifier": "ada" }
    }
  ],
  "next_cursor": "eyJrIjoi...",
  "unread_count": 7
}
```
- **Mark one read:** `POST /ui/notifications/{id}/read` → `204` (idempotent server-side).
- **Mark all read:** `POST /ui/notifications/read-all` → `{ "unread_count": 0 }`.

All requests ride the cookie session and echo `X-CSRF-Token`. The mark/POST calls are non-idempotent from the retry policy's view (no automatic backoff retry; GETs only per AND-016). Error `detail` follows the standard FastAPI union (string | `[{msg}]` | `{code,...}`) mapped to `ApiError` by core-network (AND-015).

## 6. Data & State Management

- **Source of truth:** `Flow<PagingData<Notification>>` from `repository.notificationsPagingSource()`, `cachedIn(viewModelScope)`. Optimistic read state (`locallyRead` set + `allReadFlag`) is merged via `PagingData.map`; it is intentionally screen-scoped and is reconciled on the next `refresh()` when the server returns authoritative `is_read`.
- **UiState (non-paged overlay):**

```kotlin
data class NotificationsUiState(
    val unreadCount: Int = 0,
    val markAllEnabled: Boolean = false,
    val isOffline: Boolean = false,
)
```

- **Unread count** is sourced from the page response's `unread_count` (exposed by the repository) and decremented locally as items are read; it drives `markAllEnabled` and any caller-visible bell badge.
- **Process death:** Paging state restores from `LazyPagingItems` save/restore; `locallyRead`/`allReadFlag` are deliberately not persisted (a refresh after restore re-derives read state from the server cache). Scroll position is preserved via `rememberLazyListState` saved instance state.
- **Caching:** AND-084's Room-backed cache (if present) provides offline-stale items; this screen only reads through the repository and never writes the cache directly.

## 7. Error Handling & Resilience

- **Initial load (`refresh` LoadState.Error):** render shared `ErrorState`/`OfflineState` with a retry → `lazyPagingItems.refresh()`. Distinguish connectivity/timeout (offline copy) from server errors using the `ApiError` type carried by the failed `LoadState`.
- **Append error:** inline retry footer → `lazyPagingItems.retry()`; the already-loaded list stays interactive.
- **Mark-read failure:** the optimistic flip remains (read is low-stakes and the server is idempotent); a debug-level log is emitted, no disruptive UI. Mark-**all**-read failure rolls back `allReadFlag` and surfaces a transient `Snackbar` ("Couldn't mark all as read — try again").
- **Timeouts/unreliable host:** GET list relies on the global ~20s OkHttp timeout and bounded backoff for idempotent GETs (AND-016); POSTs do not auto-retry.
- **401:** handled transparently by the refresh Authenticator (AND-013); the screen sees only success or a settled error after one refresh attempt.
- **Offline-stale:** when cached items render but the live refresh failed, show a non-blocking offline banner above the list (`isOffline = true`) and keep rows tappable; navigation still works, mark-read is queued optimistically.

## 8. Security & Privacy

- All calls are session-authenticated (cookie jar + `ui_csrf` echoed as `X-CSRF-Token`); no notification endpoint is reachable unauthenticated, and this screen sits behind the auth-gated graph (AND-025).
- Notification `title`/`body` may contain PII; never log full content (see §10). Deep-link `data` values (`u_identifier`, `item_id`) are treated as opaque routing keys and validated before navigation (unknown/missing keys → `NotificationTarget.Unknown`, no navigation).
- Coil image loads for `icon_url` go through the shared OkHttp stack so they carry the session and respect cleartext config; no third-party image CDN bypass.
- No notification data is persisted beyond AND-084's authenticated app cache; nothing is written to logs, clipboard, or external storage.

## 9. Accessibility & i18n

- Every row exposes a single merged semantics node with a content description combining read-state + title + relative time (e.g., "Unread: Ada commented on your post, 3 minutes ago"); the unread dot is decorative (`contentDescription = null`).
- Tap target ≥ 48dp height; the whole row is one clickable element. The mark-all-read action has a labeled `contentDescription` ("Mark all notifications as read").
- All strings live in `feature-notifications` `strings.xml` (no hardcoded literals); relative timestamps use `DateUtils.getRelativeTimeSpanString` / locale-aware formatting. Pluralized counts (unread badge) use `plurals`.
- Supports dynamic type and RTL (start/end paddings, no hardcoded left/right). Color is never the sole read/unread signal — the leading dot + weight reinforce it for color-vision deficiency.
- Honors the app appearance/theme settings (AND-081) via Material 3 color scheme.

## 10. Telemetry & Logging

- Reuse the redacted telemetry helper from AND-052. Emit structured, **non-PII** events: `notif_center_open`, `notif_list_loaded {count, unread_count}`, `notif_item_tap {type, target_kind}`, `notif_mark_read {result}`, `notif_mark_all_read {result}`, `notif_load_error {stage: refresh|append, error_code}`.
- Never log `title`, `body`, `u_identifier`, `item_id`, cookies, or CSRF tokens. Log only `type`, target *kind* (enum name), counts, and mapped error codes.
- Paging `LoadState` transitions are logged at debug only; production builds keep telemetry at info and redact per the core-network logging policy (AND-009).

## 11. Testing Strategy

- **Unit — target resolution:** `NotificationTargetResolverTest` covers every `type`, missing-key fallbacks → `Unknown`, and unknown `type` → `Unknown`.
- **Unit — ViewModel:** with a fake `NotificationsRepository` emitting a static `PagingData`, assert: `onItemClick` adds to `locallyRead` and emits `Navigate` only for non-`Unknown` targets; `onMarkAllRead` flips `allReadFlag`, calls the repo once, and rolls back + emits `Error` on failure; `markAllEnabled` reflects unread count. Use `cash.app.turbine` for `events`/`uiState` and `kotlinx-coroutines-test`.
- **Paging:** snapshot the `PagingData<NotificationUi>` via `AsyncPagingDataDiffer`/`asSnapshot {}` to verify mapping (read overlay applied) and ordering.
- **Compose UI tests (AND-051 emulator):**
  - List renders ≥ 2 items; unread row exposes the unread semantics; read row does not.
  - Tapping a row marks it read (dot disappears) and invokes `onNavigateTarget` with the expected target (captured via test callback) — covers backlog acceptance "tap routes correctly".
  - Append footer appears while paging and a second page renders on scroll — covers "renders + paginates".
  - Mark-all-read disables the action and clears unread treatment; failure path shows the retry snackbar.
  - Empty, error, and offline-stale states render their shared composables.
- **MockWebServer (AND-046):** drive the real repository against canned `/ui/notifications` page JSON + `read-all` responses to validate end-to-end paging and refresh.

## 12. Dependencies & Sequencing

- **Blocked by AND-084** (Notifications API + DTOs): supplies `NotificationsRepository`, `NotificationsApi`, domain `Notification`, and the `PagingSource`. Hard prerequisite — this ticket adds no networking or DTOs.
- **Blocked by AND-098** (Feed list, Paging 3): supplies the canonical Paging 3 wiring and the shared append/refresh footer composables reused here.
- **Soft/route dependencies** for deep-link destinations: AND-073 (public profile), AND-043 (active sessions), AND-077 (settings hub), AND-098 (feed). If a destination route is not yet merged, the resolver still returns the typed target and navigation is feature-flagged/no-oped until the route exists; this does not block merge.
- **Upstream:** AND-024 (authenticated nav graph) for route registration; AND-021 (state composables), AND-018 (`ApiResult`), AND-052 (telemetry) from core.
- **Blocks:** none listed. A future bell-badge widget on Dashboard/More may consume `unreadCount`.

## 13. Risks & Open Questions

1. **Pagination scheme** (cursor vs. page index) is defined by AND-084; this spec assumes cursor (`next_cursor`). If AND-084 ships page-index, only the `Pager` config constant changes — no UI impact. *Owner: AND-084.*
2. **`type` taxonomy** — the exact set of notification `type` strings and their `data` keys must be confirmed against `notifications.ts` / `/openapi.json`. The resolver is built to fail safe to `Unknown`; new types are additive. *Open: confirm full enum.*
3. **Server read reconciliation** — optimistic read may briefly disagree with the server if `markRead` fails silently; mitigated by idempotent server behavior and reconciliation on refresh. Acceptable for low-stakes read state.
4. **Unread count source** — whether `unread_count` is per-page or global affects badge accuracy; assumed global on the page response. *Confirm with AND-084.*
5. **Deep-link target availability** — some destination routes may lag; see §12 no-op handling.

## 14. Acceptance Criteria

1. Opening the notification center loads and renders the user's notifications newest-first from `GET /ui/notifications` and **paginates** additional pages on scroll (append footer shown during load). *(Backlog: "Renders + paginates".)*
2. Unread items are visually distinct (dot + tint + weight); read items are not.
3. Tapping a row marks it read in the UI, calls `repository.markRead(id)`, and **navigates to the correct in-app destination** per `NotificationTargetResolver` for each supported `type`; `Unknown` targets mark-read without navigating. *(Backlog: "tap routes correctly".)*
4. **Mark-all-read** flips all loaded rows to read, calls `repository.markAllRead()`, and is disabled when unread count is zero; failure rolls back and shows a retry snackbar.
5. Pull-to-refresh re-fetches page one and the indicator clears when the load settles.
6. Empty, error/offline, append-error states each render their shared composable with a working retry.
7. No PII is logged; deep-link keys are validated before navigation.
8. Unit (resolver + ViewModel + paging snapshot) and Compose UI tests for the above all pass in CI (AND-050/AND-051).

## 15. Definition of Done

- `feature-notifications` screen layer implemented: `NotificationsViewModel`, `NotificationsUiState`, `NotificationsEvent`, `NotificationCenterScreen`, `NotificationRow`, `NotificationTargetResolver`, route registration in the authenticated graph.
- Consumes AND-084's repository only; no new networking, DTOs, or `core-network` dependency added.
- Paging 3 wiring (`Pager` config, `cachedIn`, `collectAsLazyPagingItems`, refresh/append footers) matches AND-098 conventions.
- All strings externalized; accessibility semantics, dynamic type, and RTL verified.
- Redacted telemetry events emitted; no PII or secrets in logs.
- Unit + Compose UI tests written and green on the headless emulator (AND-051); ktlint/detekt clean (AND-005).
- Code reviewed and merged to `android-port`; screen reachable from the authenticated nav graph and demonstrably renders, paginates, and routes against the dev backend.
