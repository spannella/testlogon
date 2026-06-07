---
id: AND-085
title: Notification center screen
milestone: M2
epic: E12
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
5. **Tap → deep-link routing.** Each notification carries a typed target derived from its `notification_type` + `data` payload. The screen resolves it to an in-app `NavController` route. **NOTE (verification):** the backend `notification_type` taxonomy is a flat set of strings — the web reference uses `follow`, `like`, `comment`, `mention`, `tip`, `message`, `system` (`src/pages/notifications/NotificationsPage.tsx: TYPE_ICONS`). The dotted forms used earlier in drafts (`profile.follow`, `feed.comment`, …) are **not** present in the sources and have been corrected below. The `data` payload is typed only as `Record<string, unknown>` in the backend (`NotificationOut.data`, `additionalProperties: true`); specific keys (`u_identifier`, `item_id`) are an **unverified assumption** and MUST be confirmed against AND-084's adapter before relying on them. Supported targets at minimum (resolver fails safe to `UNKNOWN` for any unrecognized type/missing key):
   - `PROFILE` → public profile route (`AND-073`), keyed by a profile id from `data` (key TBD per AND-084).
   - `FEED_ITEM` → feed detail/feed list (`AND-098`), keyed by an item id from `data` (key TBD per AND-084).
   - `SESSIONS` → active sessions screen (`AND-043`).
   - `SETTINGS` → settings hub (`AND-077`).
   - `UNKNOWN` → no navigation; row is still markable-read and shows a generic icon.

   **Web behavior caveat:** the web reference's `NotificationsPage` does **not** deep-link on tap — it only renders a per-row "Mark read" button and derives the icon from `notification_type` locally. Tap-to-navigate is therefore an Android-specific design with no web precedent (see §16 / Open assumptions); the backlog acceptance "tap routes correctly" is satisfied by the resolver + nav wiring defined here, not by mirroring the web client.
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
    val iconUrl: String?,          // Coil — UNVERIFIED: NotificationOut has no icon_url;
                                   // either derive icon from notification_type locally
                                   // (as the web client does) or have AND-084 synthesize a URL.
    val createdAtSeconds: Long? = null, // backend created_at is epoch SECONDS (int)
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
// type values below match the verified backend taxonomy
// (src/pages/notifications/NotificationsPage.tsx: TYPE_ICONS).
// The data[] keys are an UNVERIFIED assumption — confirm against AND-084's adapter.
object NotificationTargetResolver {
    fun resolve(type: String, data: Map<String, String?>): NotificationTarget = when (type) {
        "follow", "mention" ->
            data["u_identifier"]?.let(NotificationTarget::Profile) ?: NotificationTarget.Unknown
        "comment", "like" ->
            data["item_id"]?.let(NotificationTarget::FeedItem) ?: NotificationTarget.Unknown
        "message" ->
            data["item_id"]?.let(NotificationTarget::FeedItem) ?: NotificationTarget.Unknown
        "system" -> NotificationTarget.Settings
        // "tip" and any unrecognized type fail safe to Unknown
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

> **Verification note (corrected against OpenAPI + frontend).** The earlier draft of this section listed wrong endpoint paths, a wrong response shape, and field names that do not exist in the backend. The corrected, verified contract follows. Field names below are the **wire** names from `components.schemas.NotificationOut`; AND-084 owns the domain mapping.

- **List (paged):** `GET /ui/notifications?cursor={cursor}&limit={limit}` → `200: NotificationListResponse`.
  Query params per OpenAPI: `cursor`, `limit` (plus the impersonation/session headers `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`, which are out of scope here). The web client requests `limit=30`; this screen uses page size 20 (see §3.1) — a deliberate client choice, not a contract requirement.
```json
{
  "items": [
    {
      "notification_id": "ntf_01H...",
      "notification_type": "comment",
      "title": "Ada commented on your post",
      "body": "Nice work!",
      "read": false,
      "created_at": 1749132131,
      "data": { "item_id": "post_123", "u_identifier": "ada" },
      "batch_key": null,
      "batch_count": 1,
      "batch_actors": []
    }
  ],
  "next_cursor": "eyJrIjoi...",
  "unread_count": 7
}
```
  **Corrected field shapes (verified):** the item id is **`notification_id`** (not `id`); the type field is **`notification_type`** (not `type`); the read flag is **`read`** (not `is_read`); **`created_at` is a Unix epoch *integer* (seconds)** — not an ISO-8601 string and not milliseconds (so `NotificationUi.createdAtEpochMs` must multiply by 1000, or be renamed to seconds). There is **no `icon_url` field** in `NotificationOut`; the web client derives the row icon from `notification_type` locally — the spec's Coil `iconUrl`/`icon_url` is therefore an **unverified assumption** unless AND-084 adds a synthesized URL (see §16). `NotificationOut` additionally carries **`batch_key` / `batch_count` / `batch_actors`** (notification batching) — the UI should account for `batch_count > 1` (the web client shows an "N events" badge). `unread_count` defaults to 0 and is global to the response. Only `items` is `required`; all other item fields have defaults.
- **Mark read (batch):** `POST /ui/notifications/mark-read` with body `MarkNotificationsReadIn { "notification_ids": string[] }` → `200` (response body `{ ok, marked_count }` per the web client). This is a **batch** endpoint keyed by an array of ids — there is **no** `POST /ui/notifications/{id}/read` per-item endpoint. `repository.markRead(id)` (AND-084) wraps a single-element array.
- **Mark all read:** `POST /ui/notifications/mark-all-read` (note hyphen: `mark-all-read`, **not** `read-all`) → `200` with body `{ ok, marked_count }` per the web client. It does **not** return `{ unread_count: 0 }`; the screen should re-derive unread state from a subsequent list `refresh()` / unread-count call, not from this response.
- **Unread count:** `GET /ui/notifications/unread-count` → `200 { "count": number }` (the field is **`count`**, not `unread_count`). Consumed by AND-084's `unreadCount()`.

All requests ride the cookie session and echo the CSRF token. **Verified transport (frontend `src/api/client.ts`):** the web client reads the **`ui_csrf` cookie** and sends it as header **`X-CSRF-Token`**, with `credentials: "include"`. On `401` it performs a single `POST /ui/session/refresh` (verified path) and retries once. The mark/POST calls are non-idempotent from the retry policy's view (no automatic backoff retry; GETs only per AND-016). Error `detail` follows the standard FastAPI union (string | `[{msg}]` | `{code,...}`) mapped to `ApiError` by core-network (AND-015); validation failures return `422: HTTPValidationError`.

## 6. Data & State Management

- **Source of truth:** `Flow<PagingData<Notification>>` from `repository.notificationsPagingSource()`, `cachedIn(viewModelScope)`. Optimistic read state (`locallyRead` set + `allReadFlag`) is merged via `PagingData.map`; it is intentionally screen-scoped and is reconciled on the next `refresh()` when the server returns the authoritative `read` flag (wire field `read`, not `is_read`).
- **UiState (non-paged overlay):**

```kotlin
data class NotificationsUiState(
    val unreadCount: Int = 0,
    val markAllEnabled: Boolean = false,
    val isOffline: Boolean = false,
)
```

- **Unread count** is sourced from the page response's `unread_count` (verified field on `NotificationListResponse`, global to the response, default 0) and/or `GET /ui/notifications/unread-count` (`{ count }`) via the repository, and decremented locally as items are read; it drives `markAllEnabled` and any caller-visible bell badge.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI index `reference/openapi.index.txt`, OpenAPI spec `reference/openapi.pretty.json` (`components.schemas.*`), and frontend `reference/src/*`.

1. **List endpoint is `GET /ui/notifications` with `cursor` + `limit` query params.** Verified. — OpenAPI `GET /ui/notifications` (`op=list_notifications_ui_notifications_get`, `params=cursor,limit,...`); `src/api/endpoints/notifications.ts: getNotifications`.
2. **List response schema is `NotificationListResponse { items: NotificationOut[], next_cursor: string|null, unread_count: int (default 0) }`.** Verified. — `components.schemas.NotificationListResponse`; `src/api/types.ts: NotificationListResponse`.
3. **Notification item id field is `notification_id` (NOT `id`).** Corrected. — `components.schemas.NotificationOut.notification_id` (required); `src/api/types.ts: NotificationOut`.
4. **Type field is `notification_type` (NOT `type`).** Corrected. — `components.schemas.NotificationOut.notification_type`; `src/api/types.ts: NotificationOut`.
5. **Read flag is `read` (NOT `is_read`).** Corrected. — `components.schemas.NotificationOut.read`; `src/api/types.ts: NotificationOut`.
6. **`created_at` is a Unix epoch integer in SECONDS (NOT an ISO-8601 string, NOT ms).** Corrected. — `components.schemas.NotificationOut.created_at` (`type: integer`, default 0); `src/pages/notifications/NotificationsPage.tsx: formatTimeAgo` computes `Date.now()/1000 - ts`.
7. **There is no `icon_url` field on `NotificationOut`.** Corrected (was claimed). — `components.schemas.NotificationOut` (fields: notification_id, notification_type, title, body, data, read, created_at, batch_key, batch_count, batch_actors); the web client derives icons from `notification_type` (`src/pages/notifications/NotificationsPage.tsx: TYPE_ICONS`).
8. **`NotificationOut` carries batching fields `batch_key`, `batch_count`, `batch_actors`.** Verified (newly surfaced; was omitted). — `components.schemas.NotificationOut`; `src/pages/notifications/NotificationsPage.tsx` renders a "{batch_count} events" badge when `batch_count > 1`.
9. **Mark-read endpoint is `POST /ui/notifications/mark-read` with body `MarkNotificationsReadIn { notification_ids: string[] }` (batch), NOT `POST /ui/notifications/{id}/read`.** Corrected. — OpenAPI `POST /ui/notifications/mark-read` (`req=MarkNotificationsReadIn`); `components.schemas.MarkNotificationsReadIn.notification_ids`; `src/api/endpoints/notifications.ts: markNotificationsRead`.
10. **Mark-all-read endpoint is `POST /ui/notifications/mark-all-read` (hyphenated), NOT `/ui/notifications/read-all`.** Corrected. — OpenAPI `POST /ui/notifications/mark-all-read`; `src/api/endpoints/notifications.ts: markAllNotificationsRead`.
11. **Mark-all-read returns `{ ok, marked_count }`, NOT `{ unread_count: 0 }`.** Corrected. — `src/api/endpoints/notifications.ts: markAllNotificationsRead` (`api.post<{ ok: boolean; marked_count: number }>`); OpenAPI `resp=200:` (no named schema).
12. **Unread-count endpoint is `GET /ui/notifications/unread-count` returning `{ count }` (field `count`, NOT `unread_count`).** Corrected/clarified. — OpenAPI `GET /ui/notifications/unread-count`; `src/api/endpoints/notifications.ts: getNotificationUnreadCount` (`api.get<{ count: number }>`).
13. **Auth/CSRF: session is cookie-based; CSRF read from `ui_csrf` cookie and sent as header `X-CSRF-Token`; requests use `credentials: include`.** Verified. — `src/api/client.ts` (lines ~167–183: `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`).
14. **401 handling: single retry after `POST /ui/session/refresh`.** Verified. — `src/api/client.ts: refreshSession` (`fetch(withApiBase("/ui/session/refresh"))`), 401 branch retries once; OpenAPI `POST /ui/session/refresh` (`resp=200:`); `src/api/endpoints/auth.ts: refreshSession`.
15. **Backend error `detail` is the FastAPI union; validation errors are `422: HTTPValidationError`.** Verified. — OpenAPI `GET /ui/notifications ... resp=200:NotificationListResponse;422:HTTPValidationError`; mark endpoints likewise carry `422:HTTPValidationError`.
16. **Notification `type` taxonomy is a flat set: `follow`, `like`, `comment`, `mention`, `tip`, `message`, `system` (NOT dotted forms like `profile.follow`/`feed.comment`).** Corrected. — `src/pages/notifications/NotificationsPage.tsx: TYPE_ICONS`; `NotificationOut.notification_type` is an open `string` with default `""`, so the resolver must fail safe.
17. **The `data` payload key names (`u_identifier`, `item_id`) used for deep-link routing.** Unverified-assumption. — `components.schemas.NotificationOut.data` is `type: object, additionalProperties: true` (no declared keys); web client never reads `data` keys. Must be confirmed against AND-084's adapter.
18. **Tap-to-deep-link navigation behavior.** Unverified-assumption (Android-specific, no web precedent). — `src/pages/notifications/NotificationsPage.tsx` performs no navigation on item interaction; it exposes only a per-row "Mark read" button. Routing is satisfied by `NotificationTargetResolver` + nav wiring defined in this spec.
19. **Pull-to-refresh + Paging-3 cursor pagination.** Unverified-assumption / Android design choice. — Web client uses TanStack Query with a manual "Load more" cursor button (`src/pages/notifications/NotificationsPage.tsx`), not infinite scroll or pull-to-refresh; the cursor field (`next_cursor`) is verified, the Android Paging-3 wiring is owned by AND-098/AND-084.
20. **Page size 20.** Unverified-assumption (client choice). — Web client requests `limit=30` (`getNotifications({ limit: 30 })`); `limit` is a free query param, so 20 is a valid but non-canonical client choice.
21. **Compose / Material 3 / Paging 3 / Coil framework choices.** Framework ref (not backend-verifiable). — Android docs: Paging 3 (https://developer.android.com/topic/libraries/architecture/paging/v3-overview), Compose `PullToRefreshBox` (https://developer.android.com/reference/kotlin/androidx/compose/material3/pulltorefresh/package-summary), accessibility semantics (https://developer.android.com/develop/ui/compose/accessibility).

### Corrections made

- §5: replaced wrong endpoint paths `POST /ui/notifications/{id}/read` → `POST /ui/notifications/mark-read` (batch, body `MarkNotificationsReadIn`); `POST /ui/notifications/read-all` → `POST /ui/notifications/mark-all-read`.
- §5: corrected mark-all-read response from `{ unread_count: 0 }` → `{ ok, marked_count }`; clarified unread-count endpoint returns `{ count }`.
- §5 + JSON sample: corrected item field names `id→notification_id`, `type→notification_type`, `is_read→read`; corrected `created_at` from ISO string → epoch **integer seconds**; removed non-existent `icon_url`; added the real `batch_key/batch_count/batch_actors` fields.
- §3.5 + §4 resolver: replaced fabricated dotted `type` strings with the verified flat taxonomy and marked the `data` keys as unverified.
- §4 UI model: flagged `iconUrl` as unverified and added `createdAtSeconds` note (epoch seconds, not ms).
- §6: corrected `is_read` → `read`; clarified unread-count source.
- §8/§13/transport: confirmed `ui_csrf`→`X-CSRF-Token`, `credentials: include`, and the single `POST /ui/session/refresh` retry against `src/api/client.ts`.

### Open assumptions

- **`data` payload key names for routing** (`u_identifier`, `item_id`): not declarable from the backend (`data` is an untyped object) and unused by the web client. Resolution depends on AND-084's adapter; resolver fails safe to `UNKNOWN` until confirmed.
- **Deep-link / tap-to-navigate**: no web precedent; an Android product decision. The set of routable `notification_type` values and their destinations needs product/AND-084 confirmation.
- **Notification icon source**: `NotificationOut` has no `icon_url`; whether to derive from `notification_type` (web parity) or have AND-084 synthesize a URL is unresolved.
- **Page size 20** vs the web client's 30: a client choice, not a contract; harmless but worth aligning.
- **Whether `unread_count` is best read from the list response vs the dedicated `/unread-count` endpoint** after mark-all (since mark-all returns only `{ ok, marked_count }`): assumed re-derive via refresh; confirm with AND-084.

## 17. Test Plan

Test target legend: **JVM** = local JVM unit/Robolectric (no device); **emu test35** = headless AVD `test35` (x86_64, API 35) for fast CI UI/instrumented suites; **device A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). This screen has no camera/biometric/WebRTC/FCM hardware dependency, so most cases run on JVM or emu test35; a few are flagged for device A15 to catch arm64/API-34-vs-35 differences and real-host network behavior.

- **TC-AND-085-01 — Resolver maps every known type + fails safe.**
  Type: unit (JVM). Target: `NotificationTargetResolver`. Preconditions: none.
  Steps: call `resolve()` for each verified type (`follow`, `mention`, `comment`, `like`, `message`, `system`, `tip`) with representative `data`; then with an unrecognized type; then with the routing key missing.
  Expected: `follow`/`mention` → `Profile` when `u_identifier` present else `Unknown`; `comment`/`like`/`message` → `FeedItem` when `item_id` present else `Unknown`; `system` → `Settings`; `tip` and unknown type → `Unknown`; missing key → `Unknown`. Traces: AC-3.
- **TC-AND-085-02 — Paging snapshot: mapping, ordering, read overlay.**
  Type: unit (JVM, `asSnapshot {}` / `AsyncPagingDataDiffer`). Target: `NotificationsViewModel.pagedNotifications` with a fake repository emitting a static `PagingData<Notification>`. Preconditions: fake emits ≥3 items newest-first incl. one unread.
  Steps: collect snapshot; then add an id to `locallyRead` and re-snapshot.
  Expected: domain→`NotificationUi` mapping uses `notification_id`/`notification_type`/`read`/`created_at`(seconds); order preserved newest-first; after overlay the targeted row maps to `isRead = true` without a server round-trip. Traces: AC-1, AC-2, AC-3.
- **TC-AND-085-03 — onItemClick: optimistic read + markRead + conditional Navigate.**
  Type: unit (JVM, Turbine + coroutines-test). Target: `NotificationsViewModel.onItemClick`. Preconditions: fake repo records `markRead` calls.
  Steps: click a row with a routable target; assert `locallyRead` contains its id, repo `markRead(id)` called once, and a `NotificationsEvent.Navigate(target)` is emitted. Repeat for an `Unknown` target.
  Expected: read marked + `markRead` called in both cases; `Navigate` emitted only for non-`Unknown`. Traces: AC-3.
- **TC-AND-085-04 — onMarkAllRead success + disable when zero unread.**
  Type: unit (JVM, Turbine). Target: `NotificationsViewModel.onMarkAllRead` / `uiState.markAllEnabled`. Preconditions: fake repo `markAllRead()` returns `ApiResult.Success`.
  Steps: with unread>0, assert `markAllEnabled == true`; invoke `onMarkAllRead`; assert `allReadFlag` set, repo called once, all rows flip read; set unread count to 0 and assert `markAllEnabled == false`.
  Expected: as above; no error event. Traces: AC-4.
- **TC-AND-085-05 — onMarkAllRead failure rolls back + emits Error.**
  Type: unit (JVM, Turbine). Target: `onMarkAllRead`. Preconditions: fake repo `markAllRead()` returns `ApiResult.Failure(ApiError)`.
  Steps: invoke; observe events + flag.
  Expected: `allReadFlag` reverts to false, rows return to prior read state, `NotificationsEvent.Error` emitted (drives retry snackbar). Traces: AC-4, AC-6.
- **TC-AND-085-06 — Contract: list page parses real `NotificationListResponse` JSON.**
  Type: contract/MockWebServer (JVM). Target: AND-084 `NotificationsApi`/`PagingSource` via the real Retrofit/Moshi adapter (consumed here). Preconditions: MockWebServer enqueues a `/ui/notifications` body using the verified wire shape (`notification_id`, `notification_type`, `read`, integer `created_at`, `data`, `batch_*`, `next_cursor`, `unread_count`).
  Steps: trigger initial load; capture request; assert parsed items + `next_cursor` + `unread_count`.
  Expected: request is `GET /ui/notifications?...limit=20`, carries `X-CSRF-Token` header from the `ui_csrf` cookie; parsing succeeds with correct field mapping and epoch-seconds timestamp. Traces: AC-1.
- **TC-AND-085-07 — Contract: mark-read / mark-all-read hit correct paths + bodies.**
  Type: contract/MockWebServer (JVM). Target: repository `markRead(id)` / `markAllRead()`. Preconditions: MockWebServer enqueues `200 { ok, marked_count }` for both.
  Steps: call `markRead("ntf_1")` and `markAllRead()`; inspect recorded requests.
  Expected: `POST /ui/notifications/mark-read` with body `{"notification_ids":["ntf_1"]}`; `POST /ui/notifications/mark-all-read` with empty/`{}` body; both send `X-CSRF-Token`; neither auto-retries on failure (POST policy). Traces: AC-3, AC-4.
- **TC-AND-085-08 — Contract: validation/error responses surface as ApiError.**
  Type: contract/MockWebServer (JVM). Target: repository + `LoadState`/`ApiResult`. Preconditions: enqueue `422 HTTPValidationError` for list, and a `500`/`detail` error for mark-all.
  Steps: load list (expect refresh `LoadState.Error`); call `markAllRead()` (expect `ApiResult.Failure`).
  Expected: 422 detail union mapped to `ApiError` and carried on the failed `LoadState`; mark-all failure returns `ApiResult.Failure` (feeds TC-05 rollback). Traces: AC-6.
- **TC-AND-085-09 — Compose UI: read/unread treatment + renders ≥2 items.**
  Type: Compose-UI / instrumented (emu test35). Target: `NotificationCenterScreen` + `NotificationRow` with a test `PagingData`. Preconditions: 1 unread + 1 read item.
  Steps: render; assert unread row shows dot/tint/semibold and read row does not.
  Expected: visual + semantics differ per read state. Traces: AC-1, AC-2.
- **TC-AND-085-10 — Compose UI: tap marks read + routes.**
  Type: Compose-UI / instrumented (emu test35). Target: screen with captured `onNavigateTarget`. Preconditions: unread item with a routable target.
  Steps: tap the row; assert dot disappears (optimistic) and `onNavigateTarget` invoked once with the resolved target; tap an `Unknown` row and assert no navigation but read flips.
  Expected: matches backlog "tap routes correctly". Traces: AC-1, AC-3.
- **TC-AND-085-11 — Compose UI: pagination append footer + second page; pull-to-refresh clears.**
  Type: Compose-UI / instrumented (emu test35). Target: screen + `LazyPagingItems`. Preconditions: paged source with ≥2 pages and a `next_cursor`.
  Steps: scroll to end → assert append-loading footer then second page renders; trigger `PullToRefreshBox` → assert indicator clears when refresh `LoadState` settles.
  Expected: append + refresh behave per §3.6/§3.7 ("renders + paginates"). Traces: AC-1, AC-5.
- **TC-AND-085-12 — Compose UI: empty / error / offline-stale / append-error states.**
  Type: Compose-UI / instrumented (emu test35). Target: shared `EmptyState`/`ErrorState`/`OfflineState` + retry footer. Preconditions: drive each `LoadState` (empty settle, refresh error, append error; offline-stale = cached items + failed refresh).
  Steps: render each; tap retry where present.
  Expected: empty shows "No notifications yet"; refresh error shows ErrorState/OfflineState with retry → `refresh()`; append error shows inline retry → `retry()`; offline-stale shows non-blocking banner above tappable rows. Traces: AC-6.
- **TC-AND-085-13 — Accessibility: merged row semantics, 48dp target, labeled actions, color-independent state.**
  Type: Compose-UI / instrumented (emu test35; spot-check device A15 for TalkBack). Target: row + mark-all action. Preconditions: 1 unread + 1 read row.
  Steps: assert single merged semantics node with read-state+title+relative-time content description, unread dot is decorative (`contentDescription = null`), row height ≥48dp, mark-all action has "Mark all notifications as read" label; verify read/unread is conveyed by dot+weight (not color alone). Optionally run TalkBack swipe on device A15.
  Expected: all semantics/label/touch-target assertions pass. Traces: AC-3, AC-4.
- **TC-AND-085-14 — Security: no PII in logs; validated deep-link keys; authenticated transport.**
  Type: integration (JVM + instrumented). Target: telemetry helper (AND-052) + resolver + OkHttp stack. Preconditions: capture emitted telemetry + a logging interceptor sink.
  Steps: exercise open/tap/mark flows; inspect emitted events and logs; pass `data` with a missing routing key.
  Expected: events contain only `type`/target-kind/counts/error codes — no `title`, `body`, `u_identifier`, `item_id`, cookies, or CSRF tokens; missing/unknown key → `Unknown` (no navigation); all requests carry the session cookie + `X-CSRF-Token`. Traces: AC-7.
- **TC-AND-085-15 — End-to-end against dev backend on physical device (flaky-host / arm64 / API 34).**
  Type: instrumented/e2e + manual (device A15 — MUST run on physical device). Target: full screen vs dev host `http://18.222.237.167:8000` (cleartext). Preconditions: authenticated session on device; arm64-v8a build installed.
  Steps: open notification center; scroll to paginate; tap a row to route; mark-all-read; toggle airplane mode mid-load to exercise timeout/offline-stale; restore network and retry.
  Expected: renders + paginates + routes against the real backend; cleartext config permits the dev host; ~20s timeout + offline banner on the flaky path, recovering on retry; behavior matches the emulator (no arm64/API-34 regressions). Traces: AC-1, AC-3, AC-4, AC-5, AC-6.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (renders + paginates from `GET /ui/notifications`) | TC-02, TC-06, TC-09, TC-10, TC-11, TC-15 |
| AC-2 (read/unread visual distinction) | TC-02, TC-09 |
| AC-3 (tap → markRead + correct route; Unknown no-nav) | TC-01, TC-02, TC-03, TC-07, TC-10, TC-13, TC-15 |
| AC-4 (mark-all-read flip/disable/rollback+snackbar) | TC-04, TC-05, TC-07, TC-13, TC-15 |
| AC-5 (pull-to-refresh clears) | TC-11, TC-15 |
| AC-6 (empty/error/offline/append-error + retry) | TC-05, TC-08, TC-12, TC-15 |
| AC-7 (no PII logged; deep-link keys validated) | TC-14 |
| AC-8 (unit + Compose UI tests green in CI) | TC-01..TC-14 (CI on JVM + emu test35) |
