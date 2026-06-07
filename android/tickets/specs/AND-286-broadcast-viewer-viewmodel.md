---
id: AND-286
title: Broadcast viewer ViewModel
milestone: M6
epic: E38
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-278]
blocks: [AND-287]
---

# AND-286 — Broadcast viewer ViewModel

## 1. Overview & Goal

This ticket delivers `BroadcastViewerViewModel`, the single orchestration point for the live broadcast viewing experience. The ViewModel owns a **session state machine** that drives a viewer through the full lifecycle of watching a broadcast — resolving session detail, joining as a viewer, starting HLS playback, attaching the live chat stream, and tearing everything down cleanly — and it performs the **chat merge** that combines server-pushed chat events with locally-sent (optimistic) messages into a single ordered, deduplicated, bounded list exposed to Compose.

The ViewModel does **not** render UI, own the ExoPlayer instance, or open the SSE connection itself; those concerns belong to the player surface (AND-280), the chat transport (AND-281), and the presence/heartbeat loop (AND-285). AND-286 wires those collaborators together behind a `StateFlow<ViewerUiState>` and a small set of intent functions, so that the screen composable (and the AND-287 tests) can drive the whole experience deterministically.

Goal: a fully unit-tested ViewModel that (a) implements a correct, observable `ViewerSessionState` machine; (b) merges chat from N sources without duplicates, out-of-order flicker, or unbounded memory growth; and (c) survives the unreliable dev backend with timeouts, single-shot 401 refresh, and stale/offline UI states.

## 2. Context & References

- **Module:** `feature-broadcast` (consumer of `core-network`, `core-model`, `core-data`, `core-ui`, `core-testing`).
- **Package:** `com.testlogon.android.feature.broadcast.viewer`.
- **Depends on (AND-278 — Broadcast API + DTOs):** `BroadcastApi`, session detail / playback / chat DTOs, and the typed `ApiResult<T>` mapping for FastAPI `detail` errors. This ticket consumes those types; it does not redefine them.
- **Sibling features this VM coordinates (interfaces only — implementations land in their own tickets):**
  - AND-280 Viewer playback (HLS): supplies `PlaybackController` + `playback-url` / `playback/verify`.
  - AND-281 Live chat: supplies `ChatStream` (SSE) + send/reaction calls.
  - AND-282 Tips & goals: supplies goal progress events on the chat stream.
  - AND-283 Products shelf: supplies product events on the chat stream.
  - AND-285 Viewer join/leave/heartbeat: supplies `PresenceController` + viewer count.
- **Blocks:** AND-287 (Broadcast viewer tests) asserts against this ViewModel's state machine and merge.
- **Web reference:** `frontend/src/api/endpoints/broadcast.ts`, `frontend/src/api/types.ts`; viewer page state handling under `frontend/src/`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI at `/openapi.json`.

## 3. Functional Requirements

FR-1. Given a `broadcastId`, the ViewModel resolves session detail, transitions through `Joining → Live`, and starts playback for a broadcast in `live` status.
FR-2. For a `scheduled` (also `draft`/`provisioning`/`ready`) broadcast it transitions to `Scheduled(startsAt)` using `scheduled_at` (epoch int) and does not start playback. (Correction: the backend status enum has no `upcoming` session status — `upcoming` is only a separate list endpoint.)
FR-3. For a terminal broadcast (`stopped`; also `cancelled`/`error`) it transitions to `Ended`. (Correction: there is no `ended` status; the live-finished terminal state is `stopped`.) VOD playback is out of scope here; URL may still be surfaced for AND-280.
FR-4. The chat list merges (a) historical messages from the chat-history endpoint, (b) live SSE chat events, and (c) optimistic locally-sent messages, into one chronological, deduplicated list. (Correction: history comes from `GET /chat`, not from session detail.)
FR-5. Optimistic send: a `sendMessage(text)` intent inserts a `Pending` message immediately, then reconciles to `Sent`/`Failed`. **Reconciliation cannot use a server-echoed `nonce`** — the API neither accepts nor returns a client nonce (verified; see §16). The VM tracks the locally-generated `nonce` only as a stable *client-side* key for the optimistic entry; reconciliation to the server `BroadcastChatMessageOut` is by the **HTTP 201 response** of `POST /chat` (which returns the authoritative `message_id`), with the matching SSE `chat:message` deduplicated by `message_id`. `Failed` on error, with retry.
FR-6. The list is bounded to the most recent `MAX_CHAT_MESSAGES` (default 500) to cap memory. (Matches the web client `.slice(-500)`.)
FR-7. Viewer count arrives on the **session event stream** (`GET /broadcast/sessions/{id}/stream`, event `viewer_count`) and from `viewers/join`/`heartbeat` responses — NOT from the chat stream. Goals (`GET /goals`) and products (`GET /products`) are REST reads; tips appear inline on `chat:message` (`tip_amount_cents`). These update their respective slices of `ViewerUiState` (display only; submission flows are owned by AND-282/AND-283).
FR-8. Network drops on the chat stream surface a non-fatal `chatConnected = false` banner and auto-reconnect with bounded backoff; the player and session state are unaffected. (Web client reconnects the chat `EventSource` with exponential backoff capped at 15s.)
FR-9. `leave()` (and `onCleared`) stop the chat stream, stop the heartbeat, release the player, and POST viewer leave — idempotently and exactly once.
FR-10. All transitions are observable via a single `StateFlow<ViewerUiState>`; transient one-shot effects (toasts, navigation) flow through a separate `SharedFlow<ViewerEffect>`.

## 4. Technical Design

The ViewModel is a Hilt `@HiltViewModel` reading `broadcastId` from `SavedStateHandle`. It composes three injected collaborators behind interfaces so AND-287 can supply fakes.

```kotlin
@HiltViewModel
class BroadcastViewerViewModel @Inject constructor(
    private val repo: BroadcastRepository,        // AND-278 surface
    private val playback: PlaybackController,      // AND-280
    private val chat: ChatStream,                  // AND-281
    private val presence: PresenceController,      // AND-285
    savedState: SavedStateHandle,
    @IoDispatcher private val io: CoroutineDispatcher,
) : ViewModel() {

    private val broadcastId: String = checkNotNull(savedState["broadcastId"])

    private val _uiState = MutableStateFlow(ViewerUiState(state = ViewerSessionState.Idle))
    val uiState: StateFlow<ViewerUiState> = _uiState.asStateFlow()

    private val _effects = MutableSharedFlow<ViewerEffect>(extraBufferCapacity = 8)
    val effects: SharedFlow<ViewerEffect> = _effects.asSharedFlow()

    fun start()                                  // idempotent; enter Joining
    fun retry()                                  // re-run failed transition
    fun sendMessage(text: String)
    fun retryMessage(nonce: String)
    fun sendReaction(kind: ReactionKind)
    fun leave()                                  // idempotent teardown

    override fun onCleared() { teardown(); super.onCleared() }
}
```

**Session state machine.** A sealed hierarchy is the single source of truth for lifecycle; `ViewerUiState` wraps it plus the data slices.

```kotlin
sealed interface ViewerSessionState {
    data object Idle : ViewerSessionState
    data object Joining : ViewerSessionState
    data class Scheduled(val startsAt: Instant) : ViewerSessionState
    data class Live(val playbackUrl: String) : ViewerSessionState
    data class Reconnecting(val since: Instant) : ViewerSessionState   // transport blip
    data object Ended : ViewerSessionState
    data class Error(val reason: ViewerError, val retryable: Boolean) : ViewerSessionState
}
```

Legal transitions (enforced by a private `transitionTo` guard that logs+drops illegal moves):

```
Idle → Joining
Joining → Live | Scheduled | Ended | Error
Live → Reconnecting | Ended | Error
Reconnecting → Live | Ended | Error
Scheduled → Joining            (countdown elapses / refresh)
Error → Joining                (retry)
* → Ended                      (leave())
```

Note: `Reconnecting` reflects the *session/playback* transport, distinct from `chatConnected` which is a flag inside `ViewerUiState` — chat blips never change the session state (FR-8).

**Join sequence (inside `start()`):**
1. `transitionTo(Joining)`.
2. `repo.getSessionDetail(broadcastId)` → on `status == "live"` go to step 3; on `scheduled`/`draft`/`provisioning`/`ready` → `Scheduled(scheduled_at)`; on `stopped`/`cancelled`/`error` → `Ended`; on error → `Error`. (Status is the `BroadcastSessionOut.status` string; see §5 enum.)
3. `presence.join(broadcastId)` (best-effort; failure is non-fatal, logged, surfaces a banner). **Capture the returned `viewer_id` from `ViewerJoinOut`** and hand it to the presence controller — it is a required query param for `viewers/heartbeat` and `viewers/leave`.
4. `repo.getPlaybackUrl(broadcastId)` — **POST** `/playback-url`, returns `BroadcastPlaybackUrlOut.playback_url` — then `playback.prepare(url)`; on success `transitionTo(Live(url))`.
5. Launch child coroutines in `viewModelScope` under a `SupervisorJob`: chat-stream collection, the session-event stream (viewer-count/status), presence heartbeat, and goal/product side-channel routing.
6. Seed chat from the chat-history endpoint (`GET /chat` → `BroadcastChatHistoryOut.messages`).

**Chat merge.** A `ChatMerger` keeps an in-memory ordered map keyed by the server `message_id`, with optimistic entries keyed by a client `nonce` until their `POST /chat` 201 response yields the authoritative `message_id`.

```kotlin
internal class ChatMerger(private val max: Int = MAX_CHAT_MESSAGES) {
    fun seed(history: List<ChatMessage>)
    fun applyServer(event: ChatEvent): List<ChatMessageUi>     // dedupe by id; reconcile nonce
    fun applyOptimistic(msg: ChatMessageUi): List<ChatMessageUi>
    fun markFailed(nonce: String): List<ChatMessageUi>
    fun snapshot(): List<ChatMessageUi>                        // sorted by (serverTs ?: localTs, id)
}
```

Ordering key: `(serverCreatedAt ?: localTimestamp, message_id ?: nonce)`. Note `BroadcastChatMessageOut.created_at` is an **epoch integer** (seconds/millis from the server), not an ISO-8601 string — the merger converts it to `Instant` for the UI. A `Pending` message uses `localTimestamp` and sorts last until its `POST /chat` **201 response** supplies the real `message_id` (and `created_at`), at which point the optimistic entry is upgraded in place; the corresponding SSE `chat:message` is then deduplicated by `message_id` (no flicker, no duplicate). Because the server provides **no nonce echo**, the optimistic→confirmed link is the POST response, and the SSE-vs-confirmed dedup is purely by `message_id`. When size exceeds `max`, the oldest entries are dropped. The merged list is pushed into `_uiState` via `copy(chat = ...)`.

## 5. API Contract

This ViewModel calls into the AND-278 `BroadcastRepository`/`BroadcastApi`; the canonical wire shapes are owned there. The endpoints exercised (corrected against `openapi.index.txt` / `openapi.pretty.json` and the web client `src/api/endpoints/broadcast*.ts`):

- `GET /broadcast/sessions/{session_id}` → **`BroadcastSessionOut`**. **Correction:** this DTO carries `id`, **`name`** (NOT `title`), `description`, `status` (string), `scheduled_at` (epoch int), `started_at`/`stopped_at`, `thumbnail_url`, tip config, ad config, etc. It does **NOT** embed `chat_history`, `goals`, `products`, `host`, or `viewer_count`. Those are fetched from **separate** endpoints (below). Status enum is `draft|scheduled|provisioning|ready|live|stopping|stopped|cancelled|error` — there is **no `upcoming` or `ended` status** (`upcoming` is only a list endpoint; the terminal state is `stopped`).
- `GET /broadcast/sessions/{session_id}/chat?limit&before` → **`BroadcastChatHistoryOut`** `{ messages: BroadcastChatMessageOut[], has_more, oldest_sort_key }` — historical chat seed (NOT embedded in session detail).
- `POST /broadcast/sessions/{session_id}/playback-url` → **`BroadcastPlaybackUrlOut`** `{ "session_id": "...", "playback_url": "https://.../index.m3u8", "expires_at": <epoch int> }`. **Corrections:** the method is **POST** (was GET); the URL field is **`playback_url`** (was `url`); `expires_at` is an **epoch integer** (was an ISO string). Optional `invite_token` query param for private sessions.
- `GET /broadcast/playback/verify?path&cf_token&cf_expires` → **`BroadcastPlaybackTokenVerifyOut`** `{ "valid": bool }`. **Corrections:** the path is **`/broadcast/playback/verify`** (NOT `/broadcast/sessions/{id}/playback/verify`) and the method is **GET** (was POST). Owned by AND-280; VM only triggers re-verify on player auth error.
- `GET /broadcast/sessions/{session_id}/chat/stream?poll_ms=500` (SSE / `EventSource`; owned by AND-281; VM consumes a decoded event flow). The web client opens this with `EventSource(..., { withCredentials:true })`; `poll_ms` tunes the server's internal poll cadence. **Named SSE events** (NOT a `type`-tagged union): `chat:message`, `chat:delete`, `chat:reaction`, `chat:unlock`, `chat:lottery` (see below).
- `POST /broadcast/sessions/{session_id}/chat` body **`BroadcastChatSendIn` = `{ "text": "..." }`** (required, `maxLength 280`; optional `reply_to_message_id`, `expires_in_seconds`, `lock_price_cents`, `lock_description`) → **201 `BroadcastChatMessageOut`**. **Correction:** there is **NO `nonce` field** on the request and **none on the response** — the server does not accept or echo a client nonce (verified in both OpenAPI and `broadcast-chat.ts: sendChatMessage`). See the §16 audit re: optimistic-send reconciliation.
- `POST /broadcast/sessions/{session_id}/viewers/join?invite_token` → **`ViewerJoinOut`** `{ viewer_id, session_id, viewer_count }`. **The returned `viewer_id` must be captured** — it is a required query param for heartbeat and leave.
- `POST /broadcast/sessions/{session_id}/viewers/heartbeat?viewer_id` → `ViewerHeartbeatOut` `{ ok, viewer_count }` (owned by AND-285).
- `POST /broadcast/sessions/{session_id}/viewers/leave?viewer_id` → `{ ok, viewer_count }` (owned by AND-285).
- `GET /broadcast/sessions/{session_id}/viewers/count` → `ViewerCountOut` `{ session_id, viewer_count }` (poll fallback for viewer count).
- `GET /broadcast/sessions/{session_id}/stream` (SEPARATE session/event SSE; owned by AND-285) — emits `viewer_count`, `health_update`, `session_status`, `ad_break:start`, `ad_break:end`. **Correction:** viewer-count updates arrive on **this** stream, not the chat stream.

**Chat SSE events** consumed by the merger — these are **named EventSource events**, each carrying JSON. **Correction:** the prior `type`-discriminated union with `id`/`nonce`/`ts`/`tip`/`goal`/`product`/`viewers` members was inaccurate. Verified shapes (`src/pages/broadcast/BroadcastChat.tsx`, `BroadcastChatMessageOut`):

```
event: chat:message   data: BroadcastChatMessageOut  # { message_id, session_id, sender_id, sender_display_name, text, kind, created_at(epoch int), reactions_counts, ... }  — NO nonce, NO `id`/`ts`
event: chat:delete    data: { message_id }
event: chat:reaction  data: { message_id, counts: { "<emoji>": <int> } }   # per-message counts, NOT a global {kind,count}
event: chat:unlock    data: { message_id, text }
event: chat:lottery   data: BroadcastChatMessageOut
```

Tips appear inline as a `chat:message` whose `BroadcastChatMessageOut` carries `tip_amount_cents`/`tip_currency`/`tip_total_cents` (no standalone `tip` event). Goals are read via `GET /broadcast/sessions/{id}/goals` → `BroadcastTipGoalsListOut`; products via `GET /broadcast/sessions/{id}/products` → `BroadcastShelfListOut`. Reactions to a chat *message* are submitted via `POST /broadcast/sessions/{id}/chat/{message_id}/react` body `BroadcastChatReactIn = { emoji, action: "add"|"remove" }` — there is **no `ReactionKind` enum**; reactions are arbitrary emoji strings.

Errors follow the project's FastAPI `detail` mapping (validation errors return **422 `HTTPValidationError`** `{ detail: [{ loc, msg, type }] }`; auth is **401**) and are surfaced as `ViewerError`. No new endpoints are introduced by this ticket.

## 6. Data & State Management

```kotlin
data class ViewerUiState(
    val state: ViewerSessionState,
    val title: String = "",
    val host: HostSummary? = null,
    val chat: List<ChatMessageUi> = emptyList(),
    val chatConnected: Boolean = false,
    val viewerCount: Int = 0,
    val goals: List<GoalUi> = emptyList(),
    val products: List<ProductPin> = emptyList(),
    val reactions: Map<ReactionKind, Int> = emptyMap(),
    val isStale: Boolean = false,          // showing cached/last-known data
    val banner: ViewerBanner? = null,      // transient non-fatal notice
)

data class ChatMessageUi(
    val id: String?,            // server `message_id`; null until POST 201 / SSE confirms
    val nonce: String,          // client-generated key for the optimistic entry (NOT sent to server)
    val author: String,         // from `sender_display_name`
    val text: String,
    val serverTs: Instant?,     // derived from `created_at` (epoch int); null while Pending
    val localTs: Instant,
    val status: SendStatus,     // Pending | Sent | Failed
)

sealed interface ViewerEffect {
    data class ShowToast(val msg: String) : ViewerEffect
    data object ScrollChatToBottom : ViewerEffect
}
```

State is held in `viewModelScope`; the merger and reaction/goal/product slices are plain in-memory state (not persisted). The last successful session detail may be cached via `core-data` (Room) by AND-278; when join fails but a cache hit exists, the VM sets `isStale = true` and still renders metadata while retrying. No DataStore writes originate here except deferring to AND-285 for any "remind me" state (out of scope). Chat is intentionally **not** persisted across process death — on restore from `SavedStateHandle`, the VM re-runs `start()` from `Idle`.

## 7. Error Handling & Resilience

- **Timeouts:** all repo GETs use the project-wide ~20s OkHttp timeout. A join GET timeout → `Error(NETWORK, retryable=true)`.
- **Idempotent retries:** session detail and playback-url GETs are retried with bounded exponential backoff (max 3 attempts, jittered) per the GET-only retry policy; POSTs (send, join/leave/heartbeat) are **not** auto-retried at the network layer (send retry is an explicit user/optimistic action).
- **401 handling:** delegated to the `core-network` authenticator (single `POST /ui/session/refresh` then retry once); if refresh fails the VM emits `Error(AUTH, retryable=false)` and an effect prompting re-login.
- **Chat transport drop (FR-8):** `chat.events` failure → `chatConnected=false`, banner, reconnect with bounded backoff (1s,2s,4s,8s capped, jitter). Session `state` stays `Live`. Buffered optimistic sends remain `Pending`/`Failed`.
- **Playback transport drop:** player error callback → `transitionTo(Reconnecting)`; on recovery → `Live`. Repeated failure past cap → `Error(PLAYBACK, retryable=true)`.
- **Send failures:** mark `Failed`, keep in list, expose `retryMessage(nonce)`.
- **Teardown safety:** `teardown()` guarded by an `AtomicBoolean` so leave/heartbeat-stop/player-release run exactly once even if both `leave()` and `onCleared()` fire.

## 8. Security & Privacy

- Playback URLs and chat are gated by the cookie-based session; the VM never reads or logs cookies, the `ui_csrf` token, or the `X-CSRF-Token` header (managed entirely in `core-network`).
- All mutating calls (send, reactions, join/leave) go through the shared OkHttp client that attaches the CSRF header; the VM does not construct headers.
- Chat text is treated as untrusted display data; no HTML/markup rendering decisions are made here (UI layer escapes). The VM trims and length-caps outgoing text (`MAX_CHAT_LEN = 280`) before send. (Correction: `BroadcastChatSendIn.text` has `maxLength 280`, not 500; sending >280 would be rejected with 422.)
- No PII is persisted; chat is memory-only and bounded. Effects/logs reference broadcastId and message ids, never message bodies at non-verbose levels.
- Cleartext HTTP is dev-only and confined to the network module's config (`usesCleartextTraffic` dev flavor); not a concern of this ViewModel.

## 9. Accessibility & i18n

No direct UI is produced by this ticket, but the ViewModel shapes content for accessible rendering:
- All user-facing strings (banners, error reasons, send-failure copy) are emitted as string resource ids or typed enums (`ViewerError`, `ViewerBanner`), never hardcoded English — the screen (AND-280/281) resolves them via `stringResource`, enabling translation and RTL.
- Timestamps and viewer counts are exposed as raw values (`Instant`, `Int`) so the UI can apply locale-aware formatting (`NumberFormat`, relative-time).
- The `ScrollChatToBottom` effect supports the UI in keeping new messages reachable for screen-reader/live-region announcements; the VM does not assume sighted scrolling.

## 10. Telemetry & Logging

- Structured logs (via `core-data` logger) at INFO for each session transition: `viewer_transition { from, to, broadcastId }`.
- Metrics events: `viewer_join_attempt`, `viewer_join_success { ttfp_ms }` (time-to-first-playback), `viewer_join_fail { reason }`, `chat_reconnect { attempt }`, `chat_send { status }`.
- WARN on illegal transition attempts (guard drop) and on chat reconnect exhaustion.
- No chat message bodies, usernames, or tokens in logs below VERBOSE. Counts and ids only.
- All telemetry goes through an injected `ViewerAnalytics` interface so AND-287 can assert events were emitted with fakes.

## 11. Testing Strategy

This ViewModel is the primary unit-test target; AND-287 adds repo + UI/instrumented coverage on top.

- **Harness:** `kotlinx-coroutines-test` `runTest` + `StandardTestDispatcher`; `core-testing` `MainDispatcherRule`; Turbine for `StateFlow`/`SharedFlow` assertions. Collaborators (`BroadcastRepository`, `PlaybackController`, `ChatStream`, `PresenceController`, `ViewerAnalytics`) replaced by fakes exposing controllable flows.
- **State machine tests:** live → Joining→Live; scheduled → Scheduled (no playback prepared); ended → Ended; each error path → `Error(retryable)`; `retry()` re-enters Joining; illegal transitions are dropped (assert state unchanged + WARN).
- **Chat merge tests:** seed + live events ordered correctly; duplicate server id ignored; optimistic send appears immediately as `Pending`, reconciles to `Sent` via the `POST /chat` **201 response** `message_id` (NOT a server nonce echo — the API has no nonce field; verified §16), with the matching SSE `chat:message` deduplicated by `message_id` (no dupe), `Failed` on error, `retryMessage` re-sends; bound enforced at `MAX_CHAT_MESSAGES` (oldest dropped); out-of-order server timestamps sort stably.
- **Resilience tests:** chat stream error keeps `state=Live`, flips `chatConnected=false`, schedules reconnect (advance virtual time, assert backoff); playback error → Reconnecting → Live; 401 path surfaces `Error(AUTH)` after refresh failure.
- **Teardown tests:** `leave()` then `onCleared()` invokes presence.leave/player.release/heartbeat-stop exactly once.
- **Coverage target:** ≥ 90% line coverage on `BroadcastViewerViewModel`, `ChatMerger`, and the transition guard. Acceptance bullet "Unit-tested" is met when these pass in CI.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-278 (Broadcast API + DTOs) must land first — provides `BroadcastRepository`, DTOs, and `ApiResult` mapping.
- **Interface contracts needed:** `PlaybackController` (AND-280), `ChatStream` (AND-281), `PresenceController` (AND-285). These can be defined as interfaces in `feature-broadcast` and stubbed so AND-286 can land and be tested **before** those features are fully implemented; the concrete bindings are provided when those tickets complete. AND-282/AND-283 only add event routing into existing state slices.
- **Blocks:** AND-287 (viewer tests) consumes this ViewModel directly.
- **Recommended order:** AND-278 → AND-286 (this) with stubbed collaborators → AND-280/281/285 wire concrete impls → AND-282/283 add slices → AND-287 broad tests.

## 13. Risks & Open Questions

- **R1 (chat ordering):** server `ts` granularity may collide; mitigated by `(ts, id)` composite sort. Open: does the backend guarantee monotonically increasing chat ids? If not, keep timestamp-primary ordering.
- **R2 (nonce echo) — RESOLVED:** the API has **no** client `nonce` field (verified against `openapi.pretty.json: BroadcastChatSendIn`/`BroadcastChatMessageOut` and `src/api/endpoints/broadcast-chat.ts: sendChatMessage`; see §16). Reconciliation is therefore by the `POST /chat` **201 response** `message_id`, with the matching SSE `chat:message` deduplicated by `message_id`. No heuristic (author+text+near-timestamp) fallback is needed because the synchronous 201 already yields the authoritative id before the SSE echo arrives.
- **R3 (SSE on dev host):** the unreliable plaintext host may drop SSE frequently; reconnect storms mitigated by jittered backoff + cap. Open: max session duration before forced playback-url re-verify.
- **R4 (count source of truth):** viewer count arrives both via session detail and `viewers` chat events; VM treats the latest `viewers` event as authoritative once Live. Confirm no double-counting on join.
- **R5:** scheduled→live auto-transition timing (poll vs. push) — currently a manual `retry()`/countdown; push-based promotion deferred.

## 14. Acceptance Criteria

- AC-1. `BroadcastViewerViewModel` exposes `StateFlow<ViewerUiState>` and `SharedFlow<ViewerEffect>` and implements the `ViewerSessionState` machine with exactly the legal transitions in §4; illegal transitions are dropped and logged.
- AC-2. A `live` broadcast drives `Idle→Joining→Live` and prepares playback; `scheduled`→`Scheduled` (no playback); `ended`→`Ended`.
- AC-3. Chat merge produces one ordered, deduplicated list across history + SSE + optimistic sends; optimistic messages reconcile to `Sent`/`Failed` via the `POST /chat` 201 `message_id` (the `nonce` is only a client-side optimistic key — the API has no nonce field), with the matching SSE `chat:message` deduplicated by `message_id`; list bounded to `MAX_CHAT_MESSAGES`.
- AC-4. Chat transport failure sets `chatConnected=false`, shows a banner, reconnects with bounded backoff, and leaves `state=Live` untouched.
- AC-5. `leave()`/`onCleared()` tears down chat, heartbeat, presence-leave, and player release exactly once.
- AC-6. 401 results in a single refresh-then-retry via `core-network`; persistent auth failure → `Error(AUTH, retryable=false)`.
- AC-7. All of the above are covered by passing unit tests (≥90% coverage on VM + merger + guard), satisfying the source ticket's "Unit-tested" acceptance.

## 15. Definition of Done

- Code merged to `android-port` under `feature-broadcast/.../viewer/` in package `com.testlogon.android.feature.broadcast.viewer`, building on JDK 17 / Gradle 8.9 / AGP 8.7.3 with KSP-generated Hilt bindings.
- `BroadcastViewerViewModel`, `ViewerUiState`/`ViewerSessionState`/`ChatMessageUi`, `ChatMerger`, and collaborator interfaces (`PlaybackController`, `ChatStream`, `PresenceController`, `ViewerAnalytics`) implemented; no UI in this ticket.
- Unit test suite passes in CI with the coverage target met; ktlint/detekt clean; no new lint regressions.
- Public types documented with KDoc; collaborator interfaces stubbed so the module compiles ahead of AND-280/281/285.
- Telemetry events emitted via the injected analytics interface and asserted in tests.
- PR reviewed; AND-287 unblocked (interfaces and state contract frozen).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec (`reference/openapi.pretty.json` → `components.schemas.<Name>`), and frontend (`reference/src/...`).

1. **Session detail is `GET /broadcast/sessions/{session_id}` → `BroadcastSessionOut`.** — **Verified.** OpenAPI `GET /broadcast/sessions/{session_id}` (op `get_session_route...`, resp `200:BroadcastSessionOut`).
2. **`BroadcastSessionOut` uses `name` (nullable), not `title`; carries `id`, `description`, `status` (string), `scheduled_at` (epoch int), `started_at`/`stopped_at` (ISO strings), `thumbnail_url`/ad/tip config; does NOT embed `chat_history`, `goals`, `products`, `host`, or `viewer_count`.** — **Verified / Corrected.** `components.schemas.BroadcastSessionOut`: has `name` (anyOf string|null), `id`, `description`, `status` (plain string), `scheduled_at` (integer|null), `started_at`/`stopped_at` (string|null). No `title`, `chat_history`, `goals`, `products`, `host`, or `viewer_count` properties. (Note: `started_at`/`stopped_at` are ISO **strings**, while `scheduled_at` is an **epoch integer** — the spec's join sequence correctly uses `scheduled_at` as the epoch int.)
3. **Status enum is `draft|scheduled|provisioning|ready|live|stopping|stopped|cancelled|error`; no `upcoming` or `ended` status; terminal live-finished state is `stopped`.** — **Verified (string), enum values Unverified-assumption.** `BroadcastSessionOut.status` is typed only as `type: string` (no `enum` constraint in the schema), so the exact member set cannot be confirmed from OpenAPI. The absence of `upcoming`/`ended` as *session* statuses is corroborated indirectly: `upcoming` exists only as a list route (`GET /broadcast/sessions/upcoming`), and the frontend chat/stream code uses no `ended` status. Treat the precise member list as an assumption pending backend enum docs (see Open assumptions).
4. **Chat history: `GET /broadcast/sessions/{session_id}/chat?limit&before` → `BroadcastChatHistoryOut { messages, has_more, oldest_sort_key }` (NOT embedded in session detail).** — **Verified.** OpenAPI `GET .../chat` (params `limit,before`, resp `200:BroadcastChatHistoryOut`); `schemas.BroadcastChatHistoryOut` = `messages: BroadcastChatMessageOut[]`, `has_more: bool`, `oldest_sort_key: string|null`. Frontend `src/api/endpoints/broadcast-chat.ts: getChatHistory` confirms path and `ChatHistoryResponse` shape.
5. **Playback URL: `POST /broadcast/sessions/{session_id}/playback-url` → `BroadcastPlaybackUrlOut { session_id, playback_url, expires_at(epoch int) }`; method POST; field is `playback_url`; `expires_at` integer; optional `invite_token` query param.** — **Verified / Corrected.** OpenAPI `POST .../playback-url` (op `mint_playback_url...`, resp `200:BroadcastPlaybackUrlOut`, params include `invite_token`). `schemas.BroadcastPlaybackUrlOut`: `session_id` (str), `playback_url` (str), `expires_at` (integer) — all required. Frontend `src/api/endpoints/broadcast.ts:192` uses `api.post(.../playback-url)`. (Note: response code is **200**, not 201 — the spec does not claim 201.)
6. **Playback verify: `GET /broadcast/playback/verify?path&cf_token&cf_expires` → `BroadcastPlaybackTokenVerifyOut { valid: bool }`; path is `/broadcast/playback/verify` (NOT under `/sessions/{id}`); method GET.** — **Verified / Corrected.** OpenAPI `GET /broadcast/playback/verify` (op `verify_playback_token...`, params `path,cf_token,cf_expires`, resp `200:BroadcastPlaybackTokenVerifyOut`). `schemas.BroadcastPlaybackTokenVerifyOut` = `{ valid: boolean }` (required).
7. **Chat send: `POST /broadcast/sessions/{session_id}/chat` body `BroadcastChatSendIn = { text }` (required, `maxLength 280`, `minLength 1`; optional `reply_to_message_id`, `expires_in_seconds`, `lock_price_cents`, `lock_description`) → 201 `BroadcastChatMessageOut`. No `nonce` on request or response.** — **Verified / Corrected.** OpenAPI `POST .../chat` (req `BroadcastChatSendIn`, resp `201:BroadcastChatMessageOut`). `schemas.BroadcastChatSendIn`: `text` (maxLength 280, minLength 1, required) + the four optional fields; **no `nonce`**. `schemas.BroadcastChatMessageOut`: required `message_id, session_id, sender_id, sender_display_name, created_at`; **no `nonce`**. Frontend `src/api/endpoints/broadcast-chat.ts: sendChatMessage` posts `{ text, ...options }` — no nonce.
8. **`BroadcastChatMessageOut.created_at` is an epoch integer, not ISO-8601.** — **Verified.** `schemas.BroadcastChatMessageOut.created_at` = `type: integer`. Frontend `ChatMessage.created_at: number` (broadcast-chat.ts:13).
9. **Optimistic-send reconciliation is by the `POST /chat` 201 `message_id` (no server nonce echo); the matching SSE `chat:message` is deduplicated by `message_id`.** — **Verified (design follows from the contract).** Direct consequence of citations 7–8: server returns the authoritative `message_id` synchronously on 201, and the only stable cross-source key is `message_id`. Frontend dedups `chat:lottery` by `message_id` (BroadcastChat.tsx:119) — same key strategy.
10. **Chat list is bounded to the most recent 500 (`MAX_CHAT_MESSAGES` default 500), matching the web `.slice(-500)`.** — **Verified.** Frontend `src/pages/broadcast/BroadcastChat.tsx:83,120` `[...prev, msg].slice(-500)`.
11. **Chat stream: `GET /broadcast/sessions/{session_id}/chat/stream?poll_ms=500` (SSE/EventSource, `withCredentials:true`); named events `chat:message`, `chat:delete`, `chat:reaction`, `chat:unlock`, `chat:lottery` (NOT a `type`-tagged union).** — **Verified / Corrected.** OpenAPI `GET .../chat/stream` (params `session_id, after, poll_ms`; resp `200:` SSE, no body schema). Frontend `BroadcastChat.tsx:73` opens `...chat/stream?poll_ms=500`; lines 81–122 register exactly those five named events via `addEventListener`. (Note: an `after` query param also exists for cursor resume — owned by AND-281.)
12. **Chat SSE payload shapes: `chat:message`/`chat:lottery` = `BroadcastChatMessageOut`; `chat:delete` = `{ message_id }`; `chat:reaction` = `{ message_id, counts:{<emoji>:int} }` (per-message, not global `{kind,count}`); `chat:unlock` = `{ message_id, text }`.** — **Verified / Corrected.** Frontend `BroadcastChat.tsx`: 82 (`ChatMessage`), 87 (`{ message_id }`), 93–97 (`data.message_id`, `data.counts`), 105–109 (`data.message_id`, `data.text`), 117 (`ChatMessage`).
13. **Tips appear inline on `chat:message` via `tip_amount_cents`/`tip_currency`/`tip_total_cents` (no standalone `tip` event).** — **Verified.** `schemas.BroadcastChatMessageOut` has `tip_amount_cents`, `tip_currency`, `tip_total_cents`, `tip_payment_id` (all nullable). No `tip` SSE event is registered in `BroadcastChat.tsx`.
14. **Reactions to a message: `POST /broadcast/sessions/{session_id}/chat/{message_id}/react` body `BroadcastChatReactIn = { emoji, action:"add"|"remove" }`; emoji is an arbitrary string (no `ReactionKind` enum).** — **Verified / Corrected.** OpenAPI `POST .../chat/{message_id}/react` (req `BroadcastChatReactIn`). `schemas.BroadcastChatReactIn`: `emoji` (maxLength 32, minLength 1, required) + `action` (default `add`, pattern `^(add|remove)$`). Frontend `broadcast-chat.ts: reactToChatMessage` posts `{ emoji, action }`. (Caveat: the `reactions: Map<ReactionKind, Int>` field in §6 `ViewerUiState` and AC mentions of `ReactionKind` are an Android-side modeling choice — see Corrections/Open assumptions.)
15. **Goals: `GET /broadcast/sessions/{session_id}/goals` → `BroadcastTipGoalsListOut`; Products: `GET .../products` → `BroadcastShelfListOut` (REST reads, not chat-stream events).** — **Verified.** OpenAPI `GET .../goals` (resp `200:BroadcastTipGoalsListOut`) and `GET .../products` (resp `200:BroadcastShelfListOut`).
16. **Viewer count arrives on the session event stream `GET /broadcast/sessions/{session_id}/stream` (events `viewer_count`, `health_update`, `session_status`, `ad_break:start`, `ad_break:end`) — NOT on the chat stream.** — **Verified / Corrected.** OpenAPI `GET .../stream` (op `broadcast_event_stream_route...`). Frontend `src/hooks/useBroadcastStream.ts:49` opens `/broadcast/sessions/${sessionId}/stream` and registers `viewer_count` (57), `health_update` (62), `session_status` (68), `ad_break:start` (76), `ad_break:end` (90). The chat stream registers none of these.
17. **Viewer join/heartbeat/leave/count: `POST .../viewers/join?invite_token` → `ViewerJoinOut { viewer_id, session_id, viewer_count }`; the returned `viewer_id` is a required query param for `POST .../viewers/heartbeat?viewer_id` (`ViewerHeartbeatOut { ok, viewer_count }`) and `POST .../viewers/leave?viewer_id`; `GET .../viewers/count` → `ViewerCountOut { session_id, viewer_count }`.** — **Verified.** OpenAPI: join (params `invite_token`, resp `200:ViewerJoinOut`), heartbeat (params `viewer_id`, resp `200:ViewerHeartbeatOut`), leave (params `viewer_id`, resp `200:`), count (resp `200:ViewerCountOut`). Schemas `ViewerJoinOut`/`ViewerHeartbeatOut`/`ViewerCountOut` match field-for-field. Frontend `src/hooks/useViewerHeartbeat.ts:20` posts join and reads `{ viewer_id, session_id, viewer_count }`; `broadcast.ts:222,229` pass `viewer_id` as a query param to heartbeat/leave.
18. **Auth is cookie-session based with CSRF: `ui_csrf` cookie sent as `X-CSRF-Token` header; requests use `credentials: "include"`; the VM never constructs headers (owned by `core-network`).** — **Verified.** Frontend `src/api/client.ts:168–170` reads `ui_csrf` cookie → sets `X-CSRF-Token`; `credentials:"include"` at 183/220.
19. **401 handling: single `POST /ui/session/refresh` then retry once; persistent failure → logout / `Error(AUTH, retryable=false)`.** — **Verified.** OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh...`, resp `200:`). Frontend `client.ts:122` refreshes via `/ui/session/refresh`; 194–233 implements single deduped refresh (`refreshPromise`) + one retry, then `logout("session_expired")` on persistent 401.
20. **Errors: validation → 422 `HTTPValidationError { detail:[{loc,msg,type}] }`; auth → 401.** — **Verified.** Every broadcast route in the index lists `422:HTTPValidationError`; `client.ts` maps 401 explicitly and `normalizeErrorDetail` parses FastAPI `detail`.
21. **Chat-stream reconnect uses exponential backoff capped at 15s; session/event-stream backoff is capped at 30s.** — **Verified.** Chat: `BroadcastChat.tsx:128` `Math.min(1000 * 2 ** retryCount, 15000)`. Session stream: `useBroadcastStream.ts:97` `Math.min(1000 * Math.pow(2, retryCount.current), 30_000)`. The VM's chat-reconnect schedule (§7: 1s,2s,4s,8s capped) matches the chat 15s cap.
22. **Outgoing chat text length cap is 280 (not 500); over-length is rejected 422.** — **Verified / Corrected.** `schemas.BroadcastChatSendIn.text.maxLength = 280` (minLength 1). `MAX_CHAT_LEN = 280` in §8 is correct.
23. **Framework choices: `@HiltViewModel` + `SavedStateHandle`; `StateFlow`/`SharedFlow`; `viewModelScope` + `SupervisorJob`; tests via `kotlinx-coroutines-test` `runTest`/`StandardTestDispatcher` + Turbine.** — **Verified (framework ref).** Android docs: Hilt ViewModel injection (developer.android.com/training/dependency-injection/hilt-jetpack#viewmodels), StateFlow/SharedFlow (developer.android.com/kotlin/flow/stateflow-and-sharedflow), `viewModelScope` (developer.android.com/topic/libraries/architecture/coroutines#viewmodelscope), coroutines test (developer.android.com/kotlin/coroutines/test). Turbine is a standard 3rd-party Flow test lib (cashapp/turbine). These are framework conventions, not backend-contract claims.

### Corrections made

- §11 "Chat merge tests" and AC-3 previously said optimistic messages **reconcile by `nonce`** (implying a server nonce echo). Corrected to reconcile by the `POST /chat` **201 `message_id`** with SSE dedup by `message_id` — consistent with FR-5/§4/§5 and citations 7–9. The `nonce` is purely a client-side optimistic key.
- R2 (Risks) previously framed the server-nonce echo as an *open* question with a heuristic fallback. Marked **RESOLVED** (no nonce field exists; reconcile by 201 `message_id`), removing the speculative author+text+timestamp fallback.
- (Pre-existing inline corrections in §2–§8 were re-verified and confirmed accurate: POST playback-url, `playback_url` field, epoch `expires_at`, GET `/broadcast/playback/verify`, `name` not `title`, history from `GET /chat`, named SSE events, per-message reaction counts, viewer count on the session stream, `maxLength 280`.)

### Open assumptions

- **Status enum membership (citation 3):** `BroadcastSessionOut.status` is an unconstrained `string` in OpenAPI — the exact set `draft|scheduled|provisioning|ready|live|stopping|stopped|cancelled|error` cannot be confirmed from the sources and is an assumption pending backend enum documentation. Mitigation: the VM maps any *unknown* status defensively (treat as `Error`/non-live) rather than crashing, and the precise live/scheduled/terminal partitions are the load-bearing distinctions (all corroborated by route names and frontend usage).
- **`ReactionKind` enum (citation 14):** the backend accepts arbitrary emoji strings, so the §6 `reactions: Map<ReactionKind, Int>` and `sendReaction(kind: ReactionKind)` are an Android-side ergonomic wrapper, not a wire contract. If product wants free-form emoji, `ReactionKind` should become a `String` (or a sealed set with an `Other(String)` fallback). Flagged for AND-281/AND-282 alignment.
- **`stopping`/`stopped` ordering window:** whether a session briefly reports `stopping` before `stopped`, and whether the VM should treat `stopping` as still-`Live` or as terminal, is not derivable from the sources. Current design routes both non-`live`/non-scheduled statuses to `Ended`; confirm with backend.
- **Time-to-promote scheduled→live (R5):** push vs poll promotion is a product/backend timing question, not answerable from the contract; left as manual `retry()`/countdown.
- **Server chat-id monotonicity (R1):** not specified; timestamp-primary `(created_at, message_id)` ordering is retained as the safe default.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **Emulator** = headless AVD `test35` (x86_64, API 35); **Device** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This ticket is a pure-Kotlin ViewModel with no UI and no hardware dependency, so the core suite is JVM unit tests; a few contract/instrumented cases are noted for the broader AND-287 effort. Cases needing the real SSE/cleartext dev host or ABI/API-level differences call out Device explicitly.

- **TC-AND-286-01 — Happy path: live broadcast → Joining → Live, playback prepared.**
  Type: unit (JVM). Target: JVM. Preconditions: fake `BroadcastRepository` returns `BroadcastSessionOut(status="live")`; fake `PresenceController.join` returns `ViewerJoinOut(viewer_id="v1", viewer_count=1)`; fake repo `getPlaybackUrl` returns `playback_url="https://h/index.m3u8"`; `PlaybackController.prepare` succeeds. Steps: collect `uiState` via Turbine; call `start()`; advance dispatcher. Expected: states emit `Idle → Joining → Live(playbackUrl="https://h/index.m3u8")`; `playback.prepare` called once with that URL; `viewer_id` "v1" handed to presence controller; `viewerCount=1`. Traces: AC-1, AC-2.

- **TC-AND-286-02 — Scheduled broadcast → Scheduled(startsAt), no playback.**
  Type: unit (JVM). Target: JVM. Preconditions: repo returns `status="scheduled"`, `scheduled_at=<epoch>`. Steps: `start()`; advance. Expected: `Idle → Joining → Scheduled(startsAt=Instant.ofEpochSecond(scheduled_at))`; `playback.prepare` **never** called; same for `draft`/`provisioning`/`ready` (parameterized). Traces: AC-2.

- **TC-AND-286-03 — Terminal broadcast → Ended.**
  Type: unit (JVM). Target: JVM. Preconditions: repo returns `status="stopped"` (parameterized over `cancelled`, `error`). Steps: `start()`; advance. Expected: `Joining → Ended`; no playback; no presence heartbeat loop started. Traces: AC-2.

- **TC-AND-286-04 — Unknown/garbage status routes defensively (not Live).**
  Type: unit (JVM). Target: JVM. Preconditions: repo returns `status="frobnicate"`. Steps: `start()`. Expected: VM does not enter `Live`; transitions to `Ended` or `Error` (per defensive mapping) without crashing or starting playback. Traces: AC-2 (covers the §16 open-assumption on unconstrained status enum).

- **TC-AND-286-05 — Illegal transitions are dropped and logged.**
  Type: unit (JVM). Target: JVM. Preconditions: VM driven to `Ended`. Steps: invoke an internal transition attempt `Ended → Live` (via a forced event / exposed test seam). Expected: state stays `Ended`; a WARN telemetry/log entry recorded via the injected `ViewerAnalytics`/logger; no exception. Traces: AC-1.

- **TC-AND-286-06 — Chat merge: history + SSE ordered, deduped by message_id.**
  Type: unit (JVM). Target: JVM. Preconditions: seed history `[m1@t1, m2@t2]`; then SSE `chat:message` m3@t3 and a duplicate m2@t2. Steps: seed, then apply events. Expected: list = `[m1, m2, m3]` ordered by `(created_at, message_id)`; duplicate m2 ignored (size stays 3). Traces: AC-3.

- **TC-AND-286-07 — Optimistic send reconciles via POST 201 message_id; SSE echo deduped.**
  Type: unit (JVM). Target: JVM. Preconditions: fake repo `sendChatMessage` returns 201 `BroadcastChatMessageOut(message_id="s9", created_at=t9)`. Steps: `sendMessage("hi")` → assert immediate `Pending` entry keyed by client `nonce` (no server id); let the 201 resolve → entry upgrades in place to `Sent` with `id="s9"`; then deliver SSE `chat:message` for "s9". Expected: exactly **one** entry for the message (status `Sent`, id `s9`); no duplicate from the SSE echo; **no** nonce is sent on the request body. Traces: AC-3.

- **TC-AND-286-08 — Send failure → Failed, retryMessage re-sends.**
  Type: unit (JVM). Target: JVM. Preconditions: `sendChatMessage` first throws (network), then succeeds 201 on retry. Steps: `sendMessage("x")` → assert `Pending` then `Failed` (entry retained); call `retryMessage(nonce)` → resolves to `Sent`. Expected: status sequence `Pending → Failed → Pending → Sent`; single entry throughout. Traces: AC-3.

- **TC-AND-286-09 — Outgoing text validation (length cap 280).**
  Type: contract/MockWebServer. Target: JVM (MockWebServer). Preconditions: MockWebServer enqueues a real FastAPI **422** `HTTPValidationError { detail:[{loc:["body","text"],msg,type}] }` for an over-length body. Steps: `sendMessage(<281-char string>)`; assert the VM trims/caps to ≤280 before send **and** that a server 422 (if it slips through) marks the entry `Failed` with the mapped `ViewerError`. Expected: request body `text.length ≤ 280`; 422 surfaces as `Failed`, not a crash. Traces: AC-3, AC-6.

- **TC-AND-286-10 — Chat bound at MAX_CHAT_MESSAGES (500), oldest dropped.**
  Type: unit (JVM). Target: JVM. Preconditions: merger seeded/fed 600 messages. Steps: apply all. Expected: `snapshot().size == 500`; the 100 oldest (lowest `(created_at, id)`) dropped; newest retained. Traces: AC-3.

- **TC-AND-286-11 — Chat transport drop: chatConnected=false, banner, bounded reconnect, state stays Live.**
  Type: unit (JVM, virtual time). Target: JVM. Preconditions: VM in `Live`; fake `ChatStream.events` emits an error. Steps: trigger error; advance virtual time; assert reconnect schedule 1s,2s,4s,8s… capped at 15s. Expected: `chatConnected=false`, non-null `banner`, session `state` remains `Live(...)`; on stream recovery `chatConnected=true`, banner cleared; pending optimistic sends stay `Pending`/`Failed`. Traces: AC-4.

- **TC-AND-286-12 — Playback transport drop → Reconnecting → Live.**
  Type: unit (JVM). Target: JVM. Preconditions: VM in `Live`; `PlaybackController` raises an error callback, then recovers. Steps: emit player error; emit recovery. Expected: `Live → Reconnecting(since) → Live`; chat slice untouched; repeated failure past cap → `Error(PLAYBACK, retryable=true)`. Traces: AC-1, AC-4.

- **TC-AND-286-13 — 401 single refresh-then-retry; persistent auth failure → Error(AUTH, non-retryable).**
  Type: contract/MockWebServer. Target: JVM (MockWebServer + real `core-network` client). Preconditions: MockWebServer returns 401 on `getSessionDetail`, 200 on `POST /ui/session/refresh`, then 200 on the retried detail; a second scenario returns 401 again after refresh. Steps: `start()`. Expected: scenario A → exactly one refresh call, one retry, then `Live`/`Scheduled`; scenario B → `Error(AUTH, retryable=false)` and a re-login `ViewerEffect`/effect emitted; refresh attempted at most once (deduped). Traces: AC-6.

- **TC-AND-286-14 — Teardown exactly once across leave() + onCleared().**
  Type: unit (JVM). Target: JVM. Preconditions: VM in `Live` with running heartbeat/chat. Steps: call `leave()` then trigger `onCleared()`. Expected: `presence.leave` (POST `viewers/leave?viewer_id`), heartbeat-stop, `playback.release`, and chat-stop each invoked **exactly once** (AtomicBoolean guard); state → `Ended`. Traces: AC-5.

- **TC-AND-286-15 — Viewer count comes from the session event stream, not chat.**
  Type: unit (JVM). Target: JVM. Preconditions: VM in `Live`; session-event fake emits `viewer_count=42`; chat fake emits only `chat:message`. Steps: emit both. Expected: `uiState.viewerCount==42`; chat messages do not alter `viewerCount`; `viewers/join`/`heartbeat` responses also update it. Traces: AC-1 (state slice routing), AC-4.

- **TC-AND-286-16 — Flaky dev-host / offline: timeout on join → Error(NETWORK, retryable), stale cache rendered.**
  Type: contract/MockWebServer + Device. Target: JVM (MockWebServer with throttled/no response) for the deterministic case; **Device** (physical A15, cleartext dev host `http://18.222.237.167:8000`) for a real-network smoke of SSE drop + reconnect over the unreliable plaintext host. Preconditions: detail GET times out (~20s) with no cache → `Error(NETWORK, retryable=true)`; with a `core-data` cache hit → `isStale=true` and metadata rendered while retrying. Steps: simulate timeout; then offline. Expected: correct `Error`/stale behavior; `retry()` re-enters `Joining`; on Device, chat `EventSource` reconnects with capped backoff after real frame drops without changing session `state`. Note: the cleartext-host real-SSE leg **must run on the physical Device** (cleartext + real flaky transport); the deterministic legs run on JVM. Traces: AC-4, AC-6.

- **TC-AND-286-17 — Security: VM never reads/logs cookies, `ui_csrf`, or `X-CSRF-Token`; mutating calls go through the shared client.**
  Type: unit (JVM) + contract. Target: JVM. Preconditions: spy on logger/analytics; MockWebServer captures outgoing requests. Steps: run a full send + join + leave flow at non-verbose log level. Expected: no log/telemetry line contains a cookie value, `ui_csrf`, `X-CSRF-Token`, or message bodies (only ids/counts/broadcastId); the VM constructs **no** auth/CSRF headers itself (the client attaches `X-CSRF-Token` from the `ui_csrf` cookie). Traces: AC-1, AC-6 (security posture supporting the auth ACs).

### Coverage matrix

| AC (section 14) | Covered by |
| --- | --- |
| AC-1 (StateFlow/SharedFlow + state machine + illegal-transition drop) | TC-01, TC-05, TC-12, TC-15, TC-17 |
| AC-2 (live→Live+playback; scheduled→Scheduled; terminal→Ended) | TC-01, TC-02, TC-03, TC-04 |
| AC-3 (chat merge: ordered/deduped/optimistic/bounded) | TC-06, TC-07, TC-08, TC-09, TC-10 |
| AC-4 (chat drop: chatConnected=false, banner, bounded reconnect, state stays Live) | TC-11, TC-12, TC-15, TC-16 |
| AC-5 (leave()/onCleared teardown exactly once) | TC-14 |
| AC-6 (401 single refresh-then-retry; persistent → Error(AUTH)) | TC-09, TC-13, TC-16, TC-17 |
| AC-7 (all covered by passing unit tests, ≥90% on VM+merger+guard) | TC-01–TC-17 collectively (TC-01–TC-15, TC-17 JVM unit/contract; coverage gate enforced in CI) |
