---
id: AND-303
title: Call history
milestone: M7
epic: E40
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
consume. **Correction (verified):** that module talks to a dedicated **call-history API under
`/ui/calls/*`** (`GET /ui/calls/history`, `GET /ui/calls/history/{call_id}`, `GET /ui/calls/stats`,
`DELETE /ui/calls/history/{call_id}`) — NOT `/messaging/messages/calls/*`. The
`/messaging/messages/calls/*` family owned by AND-295 is the live-call signaling API
(invite/accept/decline/end/signal/timeout/heartbeat); it does **not** expose a history list. This
ticket therefore wires the list/detail screens to `/ui/calls/*` and only reuses the invite endpoint
for callback. The goal is feature parity: history renders from the backend, supports paging and
pull-to-refresh, and a callback action that re-enters the existing call flow.

**Correction (verified):** the web reference `CallHistoryPage.tsx` does NOT implement a callback
action — it renders Caller/Callee/Type/Duration/Status/Date columns plus a per-row **delete**
(`DELETE /ui/calls/history/{call_id}`) and an aggregate stats card. "Callback" is therefore an
Android-specific addition, not a web parity feature; see the Open assumptions in §16 regarding the
`conversation_id` data gap it introduces.

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
- Web reference: `src/api/endpoints/callHistory.ts` (verified: `listCallHistory` -> `GET /ui/calls/history`,
  `getCallDetail` -> `GET /ui/calls/history/{callId}`, `deleteCallRecord` -> `DELETE /ui/calls/history/{callId}`,
  `getCallStats` -> `GET /ui/calls/stats`); list/detail UI in `src/pages/calls/CallHistoryPage.tsx`;
  shared types `src/api/types.ts` (`CallRecordOut`, `CallHistoryResponse`, `CallStatsOut`).
- Backend: FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext, unreliable —
  ~20s timeouts, bounded backoff for idempotent GETs only, offline/stale states). OpenAPI at
  `/openapi.json`.
- Auth (verified against `src/api/client.ts`): each request sends `Authorization: Bearer <accessToken>`
  (from the auth store) **and** `X-CSRF-Token` from the `ui_csrf` cookie **and** `credentials: include`
  (cookie jar). On 401 the client performs a single `POST /ui/session/refresh` then retries once; a
  second 401 logs out. (Correction: the spec previously described this as purely "cookie-based"; the
  web client is actually Bearer-token + cookie + CSRF. The OpenAPI lists an `authorization` header
  param plus `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` on these routes.) All call-history requests
  inherit this from `core-network`.
- **AND-295 (depends_on)** — live-call signaling API + DTOs for `/messaging/messages/calls/*`
  (invite/accept/decline/end/signal/timeout/heartbeat). **Correction:** AND-295 does NOT supply the
  history list/detail endpoints; those are `/ui/calls/*` and are read directly by this module's own
  `CallHistoryApi`. This ticket reuses AND-295's invite endpoint (`POST /messaging/messages/calls/invite`,
  schema `CallInviteIn`) for the callback action only. AND-027 (the network/auth core, transitive dep
  via AND-295) supplies the Retrofit/OkHttp/cookie infrastructure.

## 3. Functional Requirements

FR-1. **List rendering.** The Call History screen displays a reverse-chronological list of the
current user's call records. Each row shows: the remote party, a direction icon (incoming/outgoing),
a status indicator (completed/missed/declined/failed), relative timestamp (e.g. "2h ago"), and call
type (audio/video).

> **Correction (verified against `CallRecordOut` and `CallHistoryPage.tsx`).** The backend record
> exposes only `caller_id` and `callee_id` (string ids) — there is **no** `peer_display_name` or
> `peer_avatar_url` field. The web client renders the raw ids. The "remote party" is the
> non-current-user side: if `direction == "incoming"` the remote party is `caller_id`, else
> `callee_id`. Display-name/avatar resolution (e.g. via a profile lookup) is an Android enhancement
> and an unverified assumption (see §16); the Coil avatar in this row is best-effort and must
> degrade to an initials placeholder when no profile is available. Backend `direction` is the literal
> string `"incoming"`/`"outgoing"` (web treats any non-`"incoming"` value as outgoing); `status` is
> one of `completed | missed | declined | failed`; `call_type` is `audio | video` (NOT "voice").

FR-2. **Paging.** The list is paginated using Paging 3 with cursor- or page-based loading,
appending older entries as the user scrolls. A loading footer is shown while the next page loads;
an error footer with retry is shown on append failure.

FR-3. **Pull-to-refresh.** A pull-to-refresh gesture reloads the first page and invalidates the
pager.

FR-4. **Empty / offline / error states.** Distinct, testable states for: empty history, offline
(no connectivity) with cached/stale content if available, and load failure with a retry affordance.

FR-5. **Detail view.** Tapping a row navigates to a detail screen for that call showing: remote
party, direction, status, call type, the call timestamp, duration, and the underlying call id.
Missed/declined calls show no (or zero) duration.

> **Correction (verified against `CallRecordOut`).** The record has a single integer timestamp
> `created_at` (epoch seconds) — there is **no** separate `started_at`/`ended_at` pair and no
> server-computed end time. Detail must derive "end time" (if shown at all) as
> `created_at + duration_seconds`, and treat `duration_seconds == 0` (its default) as
> "no duration" for missed/declined/failed records.

FR-6. **Callback.** Both the list row (overflow / trailing action) and the detail screen expose a
**Call back** action. Invoking it initiates a new call to the remote party of that history entry by
delegating to AND-295's call-invite API (`POST /messaging/messages/calls/invite`), then navigates to
the live call flow (owned elsewhere). Callback is disabled when the remote party id is unavailable.

> **Correction / blocking gap (verified against `CallInviteIn`).** The invite request body **requires**
> `call_id`, `conversation_id`, and `callee_user_id`, plus optional `initial_mode` (default `"audio"`,
> NOT a `media` field), `idempotency_key`, `paid`, `rate_cents_per_min`. The history record
> (`CallRecordOut`) does **not** contain a `conversation_id`, so callback **cannot** be issued from a
> history entry alone. Resolution is an Open assumption in §16 (resolve a DM conversation for the peer,
> or have AND-295 add `conversation_id` to the record). Until resolved, callback must be guarded and
> the action disabled if no `conversation_id` can be obtained. The invite returns `200 OK` with
> `CallInviteOut` (`state`, `start_ts`, ...), NOT `201`.

FR-7. **Grouping (display).** List rows may be grouped by day with sticky day headers ("Today",
"Yesterday", date). Grouping is presentational and does not affect paging semantics.

## 4. Technical Design

New module `:feature-call-history` (Compose UI + ViewModel + Paging). It depends on `:core-network`,
`:core-model`, `:core-data`, `:core-ui`, and (for callback + DTOs) the call API artifacts from
AND-295. Hilt provides the repository and (AND-295's) `CallApi`.

```kotlin
// core-model (shared with AND-295 DTOs; UI-facing model derived here)
enum class CallDirection { INCOMING, OUTGOING }
// Corrected: backend `status` enum is completed|missed|declined|failed (no CANCELED).
enum class CallResult { COMPLETED, MISSED, DECLINED, FAILED }
// Corrected: backend `call_type` is audio|video (not "voice").
enum class CallMedia { AUDIO, VIDEO }

data class CallHistoryEntry(
    val callId: String,          // <- CallRecordOut.call_id
    val callerId: String,        // <- CallRecordOut.caller_id
    val calleeId: String,        // <- CallRecordOut.callee_id
    val peerUserId: String,      // derived: incoming -> callerId, else calleeId
    val peerDisplayName: String?,// NOT in API; resolved via profile lookup (assumption) or null
    val peerAvatarUrl: String?,  // NOT in API; resolved via profile lookup (assumption) or null
    val direction: CallDirection,// <- CallRecordOut.direction ("incoming"/"outgoing")
    val result: CallResult,      // <- CallRecordOut.status
    val media: CallMedia,        // <- CallRecordOut.call_type
    val createdAt: Instant,      // <- CallRecordOut.created_at (epoch SECONDS)
    val durationSeconds: Long,   // <- CallRecordOut.duration_seconds (default 0)
    val conversationId: String?, // NOT in CallRecordOut; needed for callback (see §16 open assumption)
)
```

> **Correction.** The previous model assumed API fields `peer_*`, `started_at`, `ended_at`, and a
> `CANCELED`/`VOICE` enum value; none exist in `CallRecordOut`. The model above maps to the real
> fields and marks display-name/avatar/`conversationId` as locally derived/unverified.

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

> **Corrected (verified against `openapi.index.txt`, `openapi.pretty.json`, and
> `src/api/endpoints/callHistory.ts`).** The list and detail reads are this module's own calls against
> `/ui/calls/*` — they are NOT owned by AND-295 and are NOT under `/messaging/messages/calls/*`. Only
> the callback (invite) reuses AND-295's `/messaging/messages/calls/invite`.

**List history** (idempotent GET — eligible for bounded backoff retry):
```
GET /ui/calls/history?limit=30&cursor=<opaque>          // op=ui_list_call_history; resp 200:CallHistoryResponse
Headers: Authorization: Bearer <token>; Cookie: <session>; X-CSRF-Token: <ui_csrf>
200 OK   // CallHistoryResponse
{
  "items": [
    {
      "call_id": "c_01H...",     // required
      "caller_id": "u_123",      // required
      "callee_id": "u_456",      // required
      "call_type": "video",      // required; "audio" | "video"
      "duration_seconds": 0,     // default 0
      "status": "missed",        // default "completed"; completed|missed|declined|failed
      "direction": "incoming",   // default "outgoing"; "incoming" | "outgoing"
      "created_at": 1749061330    // epoch SECONDS, default 0
    }
  ],
  "next_cursor": "eyJrIjoi..."   // string | null
}
```
> Query params per OpenAPI: `cursor`, `limit` (plus server-side `user_sub`/`X-SESSION-ID`/
> `X-IMPERSONATION-TOKEN`). The only documented error response is `422:HTTPValidationError`
> (validation); transport/auth errors (401/403/5xx) are handled by the shared client.

**Single record** (idempotent GET — dedicated endpoint EXISTS, contrary to the prior "if no
endpoint" hedge):
```
GET /ui/calls/history/{call_id}     // op=ui_get_call_detail; resp 200:CallRecordOut, 422:HTTPValidationError
-> 200 { ...single CallRecordOut, same shape as a list item... }
```

**(Web also exposes, not required by this ticket but available):**
```
DELETE /ui/calls/history/{call_id}  // op=ui_delete_call_record
GET    /ui/calls/stats              // op=ui_get_call_stats; resp 200:CallStatsOut
```

**Callback / invite** (NON-idempotent POST — no automatic retry; reuses AND-295 invite):
```
POST /messaging/messages/calls/invite   // op=create_call_invite; resp 200:CallInviteOut, 422:HTTPValidationError
Headers: Authorization: Bearer <token>; X-CSRF-Token: <ui_csrf>
{
  "call_id": "c_new...",          // required (client-generated id)
  "conversation_id": "conv_...",  // required  <-- NOT present in CallRecordOut; see §16
  "callee_user_id": "u_456",      // required
  "initial_mode": "video",        // optional, default "audio" (NOT "media")
  "idempotency_key": "..."        // optional
  // optional: "paid": false, "rate_cents_per_min": null
}
200 OK   // CallInviteOut (NOT 201)
{
  "call_id": "c_new...", "conversation_id": "conv_...",
  "caller_user_id": "u_123", "callee_user_id": "u_456",
  "state": "ringing", "initial_mode": "video", "start_ts": 1749061400,
  "paid": false, "rate_cents_per_minute": null
}
```
> **Note (verified `src/api/endpoints/messaging.ts`):** the web client posts invite to
> `/messages/calls/invite` while OpenAPI documents `/messaging/messages/calls/invite` — likely a
> base-path/router-prefix difference. Use the OpenAPI path `/messaging/messages/calls/invite` as
> authoritative for the Android client and confirm the deployed prefix during integration.

Moshi DTOs (`@JsonClass(generateAdapter = true)`): `CallRecordDto`/`CallHistoryResponseDto` are
defined in THIS module (mapping `CallRecordDto -> CallHistoryEntry`); the invite request/response
DTOs (`CallInviteIn`/`CallInviteOut`) are provided by AND-295. Error responses use the standard
FastAPI/ErrorEnvelope shapes:
```
// 422 validation: { "detail": [{ "msg": "...", "loc": [...], "type": "..." }] }   (HTTPValidationError)
// app errors:     { "error": { "code": "...", "message": "...", "details": {...}? } }  (ErrorEnvelope/ErrorDetail)
// legacy detail:  { "detail": "..." } | { "detail": { "code": "..." } }            (normalized by client)
```

## 6. Data & State Management

- **Paging.** `Pager(PagingConfig(pageSize = 30, prefetchDistance = 10, initialLoadSize = 30))`
  with a `CallHistoryRemoteMediator` backed by a Room cache (`core-data`) so the list is available
  offline/stale. `RemoteKeys` table stores `next_cursor` per page.
- **Room (cache).** `CallHistoryEntryCacheEntity(callId PK, callerId, calleeId, direction, status,
  callType, createdAtEpochSec, durationSeconds, conversationId?, peerDisplayName?, peerAvatarUrl?,
  cachedAtEpochMs)` plus `CallHistoryRemoteKeysEntity(callId PK, nextCursor?)`. (Corrected from the
  prior `peerUserId/result/media/startedAt/endedAt` columns, which did not match `CallRecordOut`;
  `peerUserId` is derived at map time, not stored.) DAO exposes
  `PagingSource<Int, CallHistoryEntryCacheEntity>`. On `LoadType.REFRESH` success the cache is
  cleared and repopulated in a single transaction.
- **DataStore (prefs).** Stores last-successful-refresh timestamp to drive the "stale since X"
  banner. No call PII beyond the timestamp is persisted in prefs.
- **Detail hydration.** Detail reads from the Room cache first (instant), then refreshes from the
  single-record endpoint `GET /ui/calls/history/{call_id}` (verified to exist); on a cache miss
  (deep link) it falls back to that same GET-by-id call.
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

- **Q1. RESOLVED (verified).** A dedicated list endpoint exists: `GET /ui/calls/history` ->
  `CallHistoryResponse`. It is NOT `/messaging/messages/calls` and history is NOT derived from a
  messages query. The `RemoteMediator` maps `CallRecordOut` directly.
- **Q2. RESOLVED (verified).** A single-record GET-by-id exists: `GET /ui/calls/history/{call_id}`
  -> `CallRecordOut`. Deep-link detail hydrates from it.
- **Q3. RESOLVED (verified).** Cursor pagination via `cursor` query param and `next_cursor` response
  field (string | null); confirmed in OpenAPI and `callHistory.ts`/`CallHistoryPage.tsx`.
- **Q4. PARTIALLY RESOLVED.** Callback reuses `POST /messaging/messages/calls/invite` (no distinct
  redial endpoint exists). OPEN: `CallInviteIn` requires `conversation_id`, which is absent from
  `CallRecordOut` — see §16 Open assumptions for the resolution path.
- **Risk.** Unreliable dev host may make Paging tests flaky against the live backend — mitigate by
  testing exclusively against `MockWebServer`.
- **Risk.** PII in cache requires the logout cache-wipe hook to exist; coordinate with the auth
  module so the table is registered for clearing.

## 14. Acceptance Criteria

AC-1. (Backlog) **History renders.** Launching Call History fetches and displays the user's call
records reverse-chronologically with peer name, direction/result/media indicators, and timestamp;
verified by instrumented test against `MockWebServer`.

AC-2. (Backlog) **Callback initiates.** Invoking "Call back" on a row or detail screen issues
`POST /messaging/messages/calls/invite` with the correct `callee_user_id`, `conversation_id`, and
`initial_mode` (corrected from `peer_user_id`/`media`), receives `200 CallInviteOut`, and on success
emits the `CallNav` effect into the live-call route; verified by unit + UI test. When no
`conversation_id` is resolvable, the action is disabled (no request issued).

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Call-history list endpoint is `GET /ui/calls/history` returning `CallHistoryResponse`.**
   VERDICT: Corrected (spec said `GET /messaging/messages/calls`).
   SOURCE: OpenAPI `GET /ui/calls/history` (op=ui_list_call_history, resp=200:CallHistoryResponse, params=cursor,limit);
   frontend `src/api/endpoints/callHistory.ts: listCallHistory` (`/ui/calls/history`).

2. **Single-record detail endpoint is `GET /ui/calls/history/{call_id}` returning `CallRecordOut` and definitely exists.**
   VERDICT: Corrected (spec hedged "if no dedicated endpoint exists").
   SOURCE: OpenAPI `GET /ui/calls/history/{call_id}` (op=ui_get_call_detail, resp=200:CallRecordOut);
   `src/api/endpoints/callHistory.ts: getCallDetail`.

3. **`CallRecordOut` fields are `call_id, caller_id, callee_id, call_type, duration_seconds, status, direction, created_at` — no `peer_*`, `media`, `result`, `started_at`, `ended_at`.**
   VERDICT: Corrected.
   SOURCE: OpenAPI `components.schemas.CallRecordOut`; frontend `src/api/types.ts: CallRecordOut`.

4. **`call_type` values are `audio | video` (not "voice"); `status` is `completed | missed | declined | failed`; `direction` is `incoming | outgoing`.**
   VERDICT: Corrected (spec used "voice" and a CANCELED status).
   SOURCE: `src/api/types.ts: CallRecordIn` (status/call_type unions);
   `src/pages/calls/CallHistoryPage.tsx` (direction `incoming` vs else; call_type `video` vs else).

5. **`created_at` is an integer epoch (seconds), and there is no server `ended_at`.**
   VERDICT: Corrected (spec assumed ISO `started_at`/`ended_at`).
   SOURCE: OpenAPI `CallRecordOut.created_at` (type integer, default 0); `src/api/types.ts: CallRecordOut` (`created_at: number`).

6. **`CallHistoryResponse` = `{ items: CallRecordOut[], next_cursor: string | null }`; pagination is cursor-based via `cursor`/`limit` query params.**
   VERDICT: Verified.
   SOURCE: OpenAPI `components.schemas.CallHistoryResponse` + params on `GET /ui/calls/history`;
   `src/api/types.ts: CallHistoryResponse`; `src/api/endpoints/callHistory.ts` (query build).

7. **Callback uses the invite endpoint `POST /messaging/messages/calls/invite`, request `CallInviteIn`, response `CallInviteOut` with HTTP 200 (not 201).**
   VERDICT: Corrected (spec said 201 Created, body `{peer_user_id, media}`).
   SOURCE: OpenAPI `POST /messaging/messages/calls/invite` (op=create_call_invite, req=CallInviteIn, resp=200:CallInviteOut).

8. **`CallInviteIn` requires `call_id`, `conversation_id`, `callee_user_id`; optional `initial_mode` (default "audio"), `idempotency_key`, `paid`, `rate_cents_per_min`. There is no `peer_user_id` or `media` field.**
   VERDICT: Corrected.
   SOURCE: OpenAPI `components.schemas.CallInviteIn` (required: call_id, conversation_id, callee_user_id).

9. **`CallInviteOut` includes `state`, `start_ts` (integer), `caller_user_id`, `callee_user_id`, `conversation_id`, `initial_mode`, `paid`, `rate_cents_per_minute`.**
   VERDICT: Verified.
   SOURCE: OpenAPI `components.schemas.CallInviteOut`.

10. **The web `CallHistoryPage` does NOT implement callback; it provides delete + stats only.**
    VERDICT: Verified.
    SOURCE: `src/pages/calls/CallHistoryPage.tsx` (uses listCallHistory/deleteCallRecord/getCallStats; columns Caller/Callee/Type/Duration/Status/Date + Delete; no invite import).

11. **Auth/transport: `Authorization: Bearer <accessToken>` + `X-CSRF-Token` from `ui_csrf` cookie + `credentials: include`; single `POST /ui/session/refresh` on 401 then one retry, logout on second 401.**
    VERDICT: Corrected (spec described it as purely cookie-based; it is Bearer + cookie + CSRF).
    SOURCE: `src/api/client.ts` (header build lines for Authorization/X-CSRF-Token; `refreshSession` + 401 retry block).

12. **Error shapes: 422 `HTTPValidationError` (`detail: [{msg, loc, type}]`); app errors `ErrorEnvelope` (`{error:{code, message, details?}}`); client normalizes `detail` as string | array-of-{msg} | object-with-code.**
    VERDICT: Verified.
    SOURCE: OpenAPI `components.schemas.HTTPValidationError`, `ErrorEnvelope`, `ErrorDetail`;
    `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`.

13. **The web client posts invite to `/messages/calls/invite` while OpenAPI documents `/messaging/messages/calls/invite`.**
    VERDICT: Verified (discrepancy noted; OpenAPI path treated as authoritative for Android).
    SOURCE: `src/api/endpoints/messaging.ts: createCallInvite` (`/messages/calls/invite`) vs OpenAPI `POST /messaging/messages/calls/invite`.

14. **Additional available endpoints: `DELETE /ui/calls/history/{call_id}`, `GET /ui/calls/stats` (CallStatsOut).**
    VERDICT: Verified (informational; delete is out of scope here).
    SOURCE: OpenAPI `DELETE /ui/calls/history/{call_id}` (op=ui_delete_call_record), `GET /ui/calls/stats` (op=ui_get_call_stats, resp=200:CallStatsOut).

15. **Framework choices: Paging 3 with `RemoteMediator` + Room cache; pull-to-refresh; Compose UI; Hilt DI; Coil avatars.**
    VERDICT: Unverified-assumption (Android implementation choice, not derivable from backend/web).
    SOURCE: framework ref — https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data ;
    https://developer.android.com/jetpack/compose .
    Note: web uses simple `useQuery` + a single `cursor` state (not infinite Paging) — `src/pages/calls/CallHistoryPage.tsx`.

16. **Accessibility: 48dp minimum touch target; non-color status signaling.**
    VERDICT: Unverified-assumption (sound Android practice; not from sources).
    SOURCE: framework ref — https://developer.android.com/guide/topics/ui/accessibility/principles (touch target / labels).

### Corrections made

- §1/§2/§5/§13: list/detail endpoints moved from `/messaging/messages/calls*` to `/ui/calls/history`
  and `/ui/calls/history/{call_id}`; clarified AND-295 owns only live-call signaling + invite.
- §3 FR-1/FR-5, §4 model, §6 Room schema: field names corrected to real `CallRecordOut`
  (`caller_id`/`callee_id`/`call_type`/`status`/`direction`/`created_at`); removed nonexistent
  `peer_*`/`media`/`started_at`/`ended_at`; `created_at` is epoch seconds; enums corrected
  (`audio|video`, drop `CANCELED`/`VOICE`).
- §3 FR-6, §5, §14 AC-2: invite request corrected to `CallInviteIn` (`call_id`, `conversation_id`,
  `callee_user_id`, `initial_mode`) returning `200 CallInviteOut` (was `{peer_user_id, media}` -> 201).
- §2 auth: corrected "cookie-based" to Bearer + cookie + CSRF.
- §1/§3: noted the web app has no callback feature (Android-only addition) and renders raw ids.

### Open assumptions

- **Callback `conversation_id` gap (blocking for callback).** `CallInviteIn` requires
  `conversation_id`, but `CallRecordOut` does not provide one. Resolution is unverifiable from the
  sources: either (a) resolve/create a DM conversation for the peer before invite, or (b) have
  AND-295 add `conversation_id` to the call record. Until resolved, callback is guarded/disabled.
- **Peer display name & avatar.** Not present in `CallRecordOut`; resolving them requires a profile
  lookup not specified by these sources. Assumed best-effort with id/initials fallback.
- **Remote-party derivation** (incoming -> caller_id, else callee_id) assumes `direction` reflects the
  current user's perspective; consistent with web rendering but not formally documented server-side.
- **Offline/stale Paging via Room + connectivity banner.** No backend contract dictates this;
  Android-side resilience choice given the unreliable dev host.
- **`next_cursor` opacity / cursor encoding.** Treated as an opaque token; its internal format is not
  documented and must not be parsed client-side.

## 17. Test Plan

Test targets: **JVM** (local JVM/Robolectric, no device), **emu35** (headless AVD `test35`,
x86_64, Android 15 / API 35), **deviceA15** (physical Samsung Galaxy A15 5G, SM-A156U, serial
R5CX821TA9R, Android 14 / API 34, arm64-v8a). MockWebServer is used for all network contract tests
to avoid the flaky dev host.

- **TC-AND-303-01** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer enqueues a `CallHistoryResponse` with 2 items and a non-null
  `next_cursor`. Steps: call `CallHistoryApi.listHistory(limit=30, cursor=null)`; map to
  `CallHistoryEntry`. Expected: request path is `/ui/calls/history?limit=30` (no cursor param);
  parsed fields map exactly (`call_id->callId`, `caller_id`/`callee_id`, `call_type->media`,
  `status->result`, `direction`, `created_at` parsed as epoch seconds); `next_cursor` captured.
  Traces: AC-1, AC-3.

- **TC-AND-303-02** — Type: unit (JVM). Target: JVM.
  Preconditions: sample `CallRecordOut` instances for every `direction` x `status` x `call_type`
  combination, incl. `duration_seconds=0`. Steps: run `CallRecordDto -> CallHistoryEntry` mapper.
  Expected: enums map (`audio/video`, `completed/missed/declined/failed`, `incoming/outgoing`);
  `peerUserId` = caller_id when incoming else callee_id; `durationSeconds==0` for missed/declined/
  failed yields "no duration" in formatting; unknown status/type falls back safely (no crash).
  Traces: AC-1, AC-6.

- **TC-AND-303-03** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: page 1 returns `next_cursor="C2"`; page 2 returns `next_cursor=null`.
  Steps: drive `RemoteMediator` REFRESH then APPEND twice. Expected: APPEND sends
  `?limit=30&cursor=C2`; end-of-pagination reached when `next_cursor==null`
  (`MediatorResult.Success(endOfPaginationReached=true)`); RemoteKeys persisted per page.
  Traces: AC-3.

- **TC-AND-303-04** — Type: integration/Room+Paging (emu35). Target: emu35.
  Preconditions: Room in-memory DB; MockWebServer serving 2 pages. Steps: REFRESH success then
  pull-to-refresh. Expected: on REFRESH the cache is cleared and repopulated in a single Room
  transaction; `PagingSource` invalidated; rows reflect newest-first order. Traces: AC-4.

- **TC-AND-303-05** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: empty list `{items:[], next_cursor:null}`. Steps: REFRESH. Expected: empty cache ->
  ViewModel surfaces the **empty** state (not error); no append issued. Traces: AC-5.

- **TC-AND-303-06** — Type: integration/offline (deviceA15). Target: deviceA15 (MUST be physical:
  exercises real radio airplane-mode/connectivity transitions).
  Preconditions: cache pre-populated from a prior successful refresh; device set to airplane mode.
  Steps: open Call History; attempt pull-to-refresh. Expected: cached rows render with a persistent
  "Offline — showing saved history" banner; refresh disabled/short-circuited; no crash; restoring
  connectivity clears the banner on next successful refresh. Traces: AC-5.

- **TC-AND-303-07** — Type: contract/MockWebServer resilience (JVM). Target: JVM.
  Preconditions: `GET /ui/calls/history` returns 503 twice then 200; invite returns 503 once.
  Steps: trigger list load; separately trigger callback. Expected: GET retried with bounded
  jittered backoff (<=3 attempts) and eventually succeeds; the invite POST is **NOT** auto-retried
  (single attempt, surfaces inline error). Traces: AC-7.

- **TC-AND-303-08** — Type: contract/MockWebServer auth (JVM). Target: JVM.
  Preconditions: first `GET /ui/calls/history` -> 401; `POST /ui/session/refresh` -> 200; retried
  GET -> 200. Steps: load list. Expected: exactly one `session/refresh` then one retry of the
  original GET; success returned. Second-401 variant: refresh ok but retry still 401 -> logout/
  re-auth path, no infinite loop. Traces: AC-7.

- **TC-AND-303-09** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: callback with a known `conversation_id`; invite -> `200 CallInviteOut{state:"ringing"}`.
  Steps: invoke `repo.callBack(...)`. Expected: POST `/messaging/messages/calls/invite` body contains
  `callee_user_id`, `conversation_id`, `initial_mode` (mapped from media) and `call_id`; `X-CSRF-Token`
  header present; success parses `CallInviteOut`. Error variant: 422 `HTTPValidationError` ->
  normalized message surfaced, no navigation. Traces: AC-2, AC-7.

- **TC-AND-303-10** — Type: Compose-UI (emu35). Target: emu35.
  Preconditions: VM seeded with fake `PagingData` incl. multiple days. Steps: render
  `CallHistoryScreen`. Expected: rows show direction/status/type indicators + relative timestamp;
  sticky day headers ("Today"/"Yesterday"/date) render; tapping a row invokes `onOpenDetail` with the
  correct `callId`; pull-to-refresh invokes `refresh()`. Traces: AC-1, AC-6.

- **TC-AND-303-11** — Type: Compose-UI (emu35). Target: emu35.
  Preconditions: one entry with a resolvable `conversationId`, one with `conversationId==null`.
  Steps: render row/detail "Call back" actions. Expected: button enabled when a `conversation_id`
  (and peer id) is available and invokes the VM; disabled when not resolvable (no request).
  Traces: AC-2.

- **TC-AND-303-12** — Type: Compose-UI states (emu35). Target: emu35.
  Steps: drive VM into append-error and refresh-error. Expected: append failure shows a retry footer
  wired to `lazyItems.retry()`; refresh failure with empty cache shows the full-screen Error state
  with retry. Traces: AC-5.

- **TC-AND-303-13** — Type: instrumented accessibility (emu35). Target: emu35.
  Steps: run accessibility assertions over the list + detail semantics tree. Expected: every
  direction/status/type icon has a non-empty `contentDescription` from `stringResource`; the
  "Call back" control has `Role.Button` and label "Call back {name}"; status is conveyed by icon+text
  (not color alone); touch targets >= 48dp. Traces: AC-9.

- **TC-AND-303-14** — Type: unit (JVM). Target: JVM.
  Preconditions: a logger/analytics spy; entries with real ids/names. Steps: view history, open a
  detail, initiate callback, force a load error. Expected: emitted events
  (`call_history_viewed`/`..._detail_opened`/`..._callback_initiated`/`..._load_error`) contain only
  hashed/truncated ids — no raw `caller_id`/`callee_id`/name/avatar URL; verify the logout cache-wipe
  hook clears the call-history Room tables. Traces: AC-8.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 History renders | TC-01, TC-02, TC-10 |
| AC-2 Callback initiates | TC-09, TC-11 (AC-2 inline disable: TC-09, TC-11) |
| AC-3 Paging append + end-of-pagination | TC-01, TC-03 |
| AC-4 Pull-to-refresh single-transaction repopulate | TC-04 |
| AC-5 Empty / offline / append-error / refresh-error states | TC-05, TC-06, TC-12 |
| AC-6 Detail correctness; no duration for missed/declined | TC-02, TC-10 |
| AC-7 GET backoff; POST never retried; single 401 refresh | TC-07, TC-08, TC-09 |
| AC-8 No raw PII in logs/analytics; cache cleared on logout | TC-14 |
| AC-9 Externalized strings; content descriptions; >=48dp | TC-13 |
