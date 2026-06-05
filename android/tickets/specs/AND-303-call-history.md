---
id: AND-303
title: Call history
milestone: M7
epic: E40
priority: P1
size: M
status: draft
depends_on:
  - AND-295
blocks: []
---

# AND-303 — Call history

## 1. Overview & Goal

Provide a user-facing **Call History** surface in the native Android client that lists the
authenticated user's prior voice/video calls (incoming, outgoing, missed, declined) and lets the
user open a per-call **detail** view and **initiate a callback** to the remote party of any history
entry. This is the Android analog of the web reference `callHistory.ts` (under
`frontend/src/api/endpoints/`) plus its list and detail UI.

The web reference exposes a `callHistory.ts` endpoints module that the list + detail screens
consume; this ticket ports the equivalent screens and wires them to the call DTOs and call API
delivered by **AND-295** (`/messaging/messages/calls/*`). The goal is feature parity: history
renders from the backend, supports paging and pull-to-refresh, and a callback action that re-enters
the existing call flow.

Concretely this ticket delivers a `feature-call-history` module containing:
- A paginated list screen (`CallHistoryScreen`) backed by Paging 3.
- A detail screen (`CallHistoryDetailScreen`) for a single call record.
- A `callback` action that hands off to the call placement path defined by AND-295's call API.

Out of scope: the live call UI, signaling/heartbeat handling, and the raw call DTOs/endpoints
themselves — those are owned by **AND-295**. This ticket consumes them.

## 2. Context & References

- Repo: `spannella/testlogon`, branch `android-port`, Android app under `android/`.
- Namespace / applicationId base: `com.testlogon.android`.
- Module layering: `app -> feature-call-history -> core-* (core-network, core-model, core-data,
  core-ui, core-testing)`. New module is `:feature-call-history`.
- Web reference: `frontend/src/api/endpoints/callHistory.ts`; shared types `frontend/src/api/types.ts`.
- Backend: FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext, unreliable —
  ~20s timeouts, bounded backoff for idempotent GETs only, offline/stale states). OpenAPI at
  `/openapi.json`.
- Auth: cookie-based session (`POST /ui/session/start` -> MFA -> `POST /ui/session/finalize` ->
  `GET /ui/me`), `ui_csrf` cookie echoed as `X-CSRF-Token`, single `POST /ui/session/refresh` on
  401 then retry, persistent cookie jar. All call-history requests inherit this from `core-network`.
- **AND-295 (depends_on)** — Call API + DTOs for `/messaging/messages/calls/*`
  (invite/accept/decline/end/signal/timeout/heartbeat). This ticket reuses AND-295's `CallDto`
  family and `CallApi`/`CallService` for the callback (invite) action and, where present, the
  call-list endpoint. AND-027 (the network/auth core, transitive dep via AND-295) supplies the
  Retrofit/OkHttp/cookie infrastructure.

## 3. Functional Requirements

FR-1. **List rendering.** The Call History screen displays a reverse-chronological list of the
current user's call records. Each row shows: remote party display name (and avatar via Coil),
direction/result icon (incoming, outgoing, missed, declined), relative timestamp (e.g. "2h ago"),
and call media type (voice/video).

FR-2. **Paging.** The list is paginated using Paging 3 with cursor- or page-based loading,
appending older entries as the user scrolls. A loading footer is shown while the next page loads;
an error footer with retry is shown on append failure.

FR-3. **Pull-to-refresh.** A pull-to-refresh gesture reloads the first page and invalidates the
pager.

FR-4. **Empty / offline / error states.** Distinct, testable states for: empty history, offline
(no connectivity) with cached/stale content if available, and load failure with a retry affordance.

FR-5. **Detail view.** Tapping a row navigates to a detail screen for that call showing: remote
party, direction, result, media type, start time, end time, duration, and the underlying call id.
Missed/declined calls show no duration.

FR-6. **Callback.** Both the list row (overflow / trailing action) and the detail screen expose a
**Call back** action. Invoking it initiates a new call to the remote party of that history entry by
delegating to AND-295's call-invite API, then navigates to the live call flow (owned elsewhere).
Callback is disabled when the remote party id is unavailable.

FR-7. **Grouping (display).** List rows may be grouped by day with sticky day headers ("Today",
"Yesterday", date). Grouping is presentational and does not affect paging semantics.

## 4. Technical Design

New module `:feature-call-history` (Compose UI + ViewModel + Paging). It depends on `:core-network`,
`:core-model`, `:core-data`, `:core-ui`, and (for callback + DTOs) the call API artifacts from
AND-295. Hilt provides the repository and (AND-295's) `CallApi`.

```kotlin
// core-model (shared with AND-295 DTOs; UI-facing model derived here)
enum class CallDirection { INCOMING, OUTGOING }
enum class CallResult { COMPLETED, MISSED, DECLINED, CANCELED, FAILED }
enum class CallMedia { VOICE, VIDEO }

data class CallHistoryEntry(
    val callId: String,
    val peerUserId: String,
    val peerDisplayName: String,
    val peerAvatarUrl: String?,
    val direction: CallDirection,
    val result: CallResult,
    val media: CallMedia,
    val startedAt: Instant,
    val endedAt: Instant?,
    val durationSeconds: Long?,
)
```

```kotlin
// feature-call-history/data
interface CallHistoryRepository {
    fun pager(): Flow<PagingData<CallHistoryEntry>>
    suspend fun entry(callId: String): ApiResult<CallHistoryEntry>
    suspend fun callBack(peerUserId: String, media: CallMedia): ApiResult<CallInviteResult>
}

class CallHistoryRemoteMediator(/* api, db */) : RemoteMediator<Int, CallHistoryEntryCacheEntity>()

@Singleton
class DefaultCallHistoryRepository @Inject constructor(
    private val api: CallApi,                 // from AND-295
    private val db: CallHistoryDao,           // core-data Room cache
    private val callService: CallService,     // from AND-295 (invite)
) : CallHistoryRepository
```

```kotlin
// feature-call-history/ui
sealed interface CallHistoryUiState {
    data object Loading : CallHistoryUiState
    data class Content(val isOffline: Boolean) : CallHistoryUiState  // list itself via PagingData
    data class Error(val message: UiText, val retryable: Boolean) : CallHistoryUiState
}

@HiltViewModel
class CallHistoryViewModel @Inject constructor(
    private val repo: CallHistoryRepository,
) : ViewModel() {
    val uiState: StateFlow<CallHistoryUiState>
    val items: Flow<PagingData<CallHistoryEntry>> = repo.pager().cachedIn(viewModelScope)
    fun refresh()
    fun onCallBack(entry: CallHistoryEntry)   // emits CallNav effect on success
}

@HiltViewModel
class CallHistoryDetailViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,       // callId arg
    private val repo: CallHistoryRepository,
) : ViewModel() {
    val state: StateFlow<DetailUiState>
    fun onCallBack()
}
```

Composables:

```kotlin
@Composable fun CallHistoryScreen(onOpenDetail: (String) -> Unit, onStartCall: (CallNav) -> Unit)
@Composable fun CallHistoryDetailScreen(onBack: () -> Unit, onStartCall: (CallNav) -> Unit)
```

Navigation (single-Activity Navigation-Compose):
- Route `call_history` -> `CallHistoryScreen`.
- Route `call_history/{callId}` -> `CallHistoryDetailScreen`.
- Callback success emits a one-shot effect `CallNav(callId, peerUserId, media)` collected by the
  NavHost owner, which navigates into the live call route (owned by a downstream call-UI ticket).

ViewModels expose `StateFlow<UiState>`; all I/O returns typed `ApiResult<T>`; FastAPI `detail`
errors (`string | [{msg}] | {code,...}`) are mapped centrally in `core-network` and surfaced as
`UiText`.

## 5. API Contract

This ticket consumes endpoints owned by **AND-295** under `/messaging/messages/calls/*`. The list
read and the callback (invite) are the two calls used here. Exact paths/field names are authoritative
in AND-295 and `/openapi.json`; representative shapes:

**List history** (idempotent GET — eligible for bounded backoff retry):
```
GET /messaging/messages/calls?limit=30&cursor=<opaque>
Headers: Cookie: <session>; X-CSRF-Token: <ui_csrf>
200 OK
{
  "items": [
    {
      "call_id": "c_01H...",
      "peer_user_id": "u_123",
      "peer_display_name": "Ada Lovelace",
      "peer_avatar_url": "https://.../a.png",
      "direction": "incoming",
      "result": "missed",
      "media": "video",
      "started_at": "2026-06-04T18:22:10Z",
      "ended_at": null,
      "duration_seconds": null
    }
  ],
  "next_cursor": "eyJrIjoi..."
}
```

**Single record** (idempotent GET; if no dedicated endpoint exists, detail is hydrated from the
Room cache populated by the list — see §6):
```
GET /messaging/messages/calls/{call_id}  -> 200 { ...single item shape as above... }
```

**Callback / invite** (NON-idempotent POST — no automatic retry; reuses AND-295 invite):
```
POST /messaging/messages/calls/invite
Headers: X-CSRF-Token: <ui_csrf>
{ "peer_user_id": "u_123", "media": "video" }
201 Created
{ "call_id": "c_01H...new", "state": "ringing" }
```

Moshi DTOs (`@JsonClass(generateAdapter = true)`) for the above are provided by AND-295; this module
maps `CallDto -> CallHistoryEntry`. Error responses follow the standard FastAPI envelope:
```
{ "detail": "..." } | { "detail": [{ "msg": "...", "loc": [...] }] } | { "detail": { "code": "..." } }
```

## 6. Data & State Management

- **Paging.** `Pager(PagingConfig(pageSize = 30, prefetchDistance = 10, initialLoadSize = 30))`
  with a `CallHistoryRemoteMediator` backed by a Room cache (`core-data`) so the list is available
  offline/stale. `RemoteKeys` table stores `next_cursor` per page.
- **Room (cache).** `CallHistoryEntryCacheEntity(callId PK, peerUserId, peerDisplayName,
  peerAvatarUrl, direction, result, media, startedAtEpochMs, endedAtEpochMs?, durationSeconds?,
  cachedAtEpochMs)` plus `CallHistoryRemoteKeysEntity(callId PK, nextCursor?)`. DAO exposes
  `PagingSource<Int, CallHistoryEntryCacheEntity>`. On `LoadType.REFRESH` success the cache is
  cleared and repopulated in a single transaction.
- **DataStore (prefs).** Stores last-successful-refresh timestamp to drive the "stale since X"
  banner. No call PII beyond the timestamp is persisted in prefs.
- **Detail hydration.** Detail reads from the Room cache first (instant), then refreshes from the
  single-record endpoint if available; if the cache miss occurs (deep link) it falls back to the
  GET-by-id call.
- **UiState flow.** `uiState` reflects mediator `LoadState` (Loading/Content/Error) combined with a
  connectivity flag from `core-data`; the actual rows stream via `PagingData` collected with
  `collectAsLazyPagingItems()`. `cachedIn(viewModelScope)` survives config changes.
- **One-shot effects.** Callback navigation uses a `Channel`/`SharedFlow` effect, not state, to
  avoid re-navigation on recomposition.

## 7. Error Handling & Resilience

- **Timeouts.** All requests use the `core-network` OkHttp client (~20s call/connect/read timeout)
  given the unreliable dev host.
- **Retry policy.** The list/detail **GETs are idempotent** and use bounded exponential backoff
  (max 3 attempts, jittered, cap ~8s) on transient failures (IOException, 5xx, 408). The
  **callback POST is non-idempotent and is NOT auto-retried** — failure surfaces an inline error
  with a manual "Try again".
- **Auth 401.** On 401 the shared interceptor performs a single `POST /ui/session/refresh` then
  retries once; a second 401 routes to re-auth.
- **Offline.** When connectivity is absent, the cached Paging data renders with a persistent
  "Offline — showing saved history" banner; refresh is disabled and append loads short-circuit to
  the cache.
- **Append errors.** Paging append failures show a retry footer (`lazyItems.retry()`); refresh
  failures with an empty cache show the full-screen `Error` state.
- **Callback failures.** Mapped FastAPI `detail` -> `UiText`; e.g. peer unreachable / not-allowed
  shows a snackbar and leaves the user on the history screen (no navigation).

## 8. Security & Privacy

- Session and CSRF are handled centrally: every request carries the persistent cookie jar and the
  `X-CSRF-Token` header derived from the `ui_csrf` cookie; the callback POST must include CSRF.
- Call history is PII (who the user called and when). The Room cache is app-private storage; no
  history is written to logs, DataStore (beyond a timestamp), or `WebView`/`Intent` extras.
- Avatar URLs are loaded via Coil through the authenticated OkHttp stack; no third-party trackers.
- Cleartext: dev host is HTTP, so `usesCleartextTraffic` is gated to the dev network-security-config
  only (inherited from `core-network`); release builds disallow cleartext.
- On logout/session clear, the call-history Room tables are wiped as part of the shared cache-clear
  hook so a subsequent user cannot see the prior user's call history.

## 9. Accessibility & i18n

- All icons (direction/result/media) carry `contentDescription` via `stringResource`
  (e.g. "Missed video call from Ada Lovelace, 2 hours ago" as a row `semantics` merge).
- Callback action exposes a `Role.Button` with accessible label "Call back {name}"; minimum
  touch target 48dp.
- Relative timestamps and durations are formatted with `DateUtils`/`java.time` against the device
  locale and timezone; durations use locale-aware formatting (mm:ss / "1 min 4 sec").
- All strings live in `res/values/strings.xml` (no hardcoded UI text); supports RTL mirroring and
  Dynamic Type / large font scaling. Sticky day headers ("Today"/"Yesterday") are localized.
- Color is not the sole signal for call result (icon + text label accompany color).

## 10. Telemetry & Logging

- Events (via `core-data` analytics abstraction): `call_history_viewed`,
  `call_history_refreshed { source: pull|auto }`, `call_history_detail_opened { call_id_hash }`,
  `call_history_callback_initiated { media, result: success|error }`, `call_history_load_error
  { stage: refresh|append, http_status }`.
- Identifiers are hashed/truncated; no raw peer ids, names, or avatar URLs are logged.
- Logging uses the project logger; network-level logging is `BODY` only in debug builds and `NONE`
  in release. Paging `LoadState` transitions are logged at debug for diagnosing the unreliable host.

## 11. Testing Strategy

- **Unit (core-testing + Turbine + MockWebServer):**
  - `CallDto -> CallHistoryEntry` mapping for every `direction`/`result`/`media` combination,
    including null `ended_at`/`duration_seconds` for missed/declined (parity with AND-295 tests).
  - `CallHistoryViewModel.refresh()` state transitions Loading -> Content / -> Error.
  - `onCallBack` success emits `CallNav` effect with correct `peerUserId`/`media`; failure emits
    error and no effect.
  - Error mapping for all three FastAPI `detail` shapes.
- **Repository / Paging:** `RemoteMediator` tests with `MockWebServer` covering REFRESH/APPEND,
  `next_cursor` handling, end-of-pagination (`null next_cursor`), and cache clear-on-refresh.
  Offline test: airplane flag -> data served from Room with offline banner state.
- **Resilience:** backoff retry exercised on 503 for GET; assert callback POST is NOT retried on
  503; assert single `session/refresh` + retry on 401.
- **UI (Compose test):** list renders rows and day headers; pull-to-refresh triggers refresh;
  empty/offline/error states render; tapping a row navigates with the correct `callId`; "Call back"
  is disabled when `peerUserId` is blank and enabled otherwise; callback button click invokes VM.
- **Accessibility:** `contentDescription`/`Role` assertions and 48dp touch-target checks via
  semantics tree.

## 12. Dependencies & Sequencing

- **Depends on AND-295** (Call API + DTOs, `/messaging/messages/calls/*`) — supplies `CallDto`,
  `CallApi`, and the invite/`CallService` used by callback. This ticket must not duplicate those
  DTOs; it imports them and maps to `CallHistoryEntry`.
- Transitive: AND-027 (network/auth core via AND-295) for Retrofit/OkHttp/cookie jar/CSRF.
- **Blocks:** none recorded in the backlog. The `CallNav` effect targets the live-call UI route;
  if that route is not yet present, the effect is wired to a no-op/log sink behind a feature flag so
  this ticket can land independently and the call-UI ticket connects the route later.
- Sequencing: land `:feature-call-history` module + Paging + list/detail behind navigation, then
  enable the callback hand-off once AND-295's invite is merged.

## 13. Risks & Open Questions

- **Q1.** Does a dedicated history list endpoint exist (`GET /messaging/messages/calls`) or must
  history be derived from a messages query? Confirm against `/openapi.json` and `callHistory.ts`.
  If derived, the `RemoteMediator` mapping changes (resolution owned jointly with AND-295).
- **Q2.** Is there a single-record GET-by-id, or must detail rely solely on the cached list entry?
  Affects deep-link/detail hydration in §6.
- **Q3.** Cursor vs offset/page pagination and the cursor field name (`next_cursor` assumed).
- **Q4.** Does callback reuse `/calls/invite` directly, or is there a distinct redial endpoint?
- **Risk.** Unreliable dev host may make Paging tests flaky against the live backend — mitigate by
  testing exclusively against `MockWebServer`.
- **Risk.** PII in cache requires the logout cache-wipe hook to exist; coordinate with the auth
  module so the table is registered for clearing.

## 14. Acceptance Criteria

AC-1. (Backlog) **History renders.** Launching Call History fetches and displays the user's call
records reverse-chronologically with peer name, direction/result/media indicators, and timestamp;
verified by instrumented test against `MockWebServer`.

AC-2. (Backlog) **Callback initiates.** Invoking "Call back" on a row or detail screen issues
`POST /messaging/messages/calls/invite` with the correct `peer_user_id` and `media`, and on success
emits the `CallNav` effect into the live-call route; verified by unit + UI test.

AC-3. Paging appends older entries on scroll and stops at end-of-pagination (`next_cursor == null`).

AC-4. Pull-to-refresh invalidates the pager and repopulates the cache in one transaction.

AC-5. Empty, offline (cached + banner), append-error (retry footer), and refresh-error (full-screen
retry) states each render correctly.

AC-6. Tapping a row opens the detail screen for the correct `callId` with start/end/duration shown;
missed/declined entries show no duration.

AC-7. GET list/detail use bounded backoff retry; the callback POST is never auto-retried; a single
`session/refresh` + retry occurs on 401.

AC-8. No raw PII (peer id/name/url) appears in logs or analytics; cache cleared on logout.

AC-9. All UI strings are externalized; icons have content descriptions; touch targets >= 48dp.

## 15. Definition of Done

- `:feature-call-history` module added to settings/build with `com.testlogon.android.callhistory`
  namespace; wired into the NavHost (`call_history`, `call_history/{callId}` routes).
- List + detail screens, `CallHistoryViewModel`/`CallHistoryDetailViewModel`,
  `CallHistoryRepository` + `RemoteMediator` + Room cache implemented per §4–§6.
- Callback delegates to AND-295's invite API; success navigation effect wired (behind flag if the
  call-UI route is not yet merged).
- All §11 tests written and green in CI; lint/detekt/ktlint clean; no hardcoded strings.
- AC-1 through AC-9 demonstrably pass.
- Code reviewed and merged to `android-port`; no new cleartext permitted in release config.
