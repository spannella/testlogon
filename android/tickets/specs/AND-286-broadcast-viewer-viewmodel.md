---
id: AND-286
title: Broadcast viewer ViewModel
milestone: M6
epic: E38
priority: P0
size: L
status: draft
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
FR-2. For a `scheduled`/`upcoming` broadcast it transitions to `Scheduled(startsAt)` and does not start playback.
FR-3. For an `ended` broadcast it transitions to `Ended` (VOD playback is out of scope here; URL may still be surfaced for AND-280).
FR-4. The chat list merges (a) historical messages from session detail, (b) live SSE chat events, and (c) optimistic locally-sent messages, into one chronological, deduplicated list.
FR-5. Optimistic send: a `sendMessage(text)` intent inserts a `Pending` message immediately, then reconciles to `Sent` when the server echoes it (matched by client `nonce`) or to `Failed` on error, with retry.
FR-6. The list is bounded to the most recent `MAX_CHAT_MESSAGES` (default 500) to cap memory.
FR-7. Viewer count and goal/product/tip side-events from the same chat stream update their respective slices of `ViewerUiState` (display only; submission flows are owned by AND-282/AND-283).
FR-8. Network drops on the chat stream surface a non-fatal `chatConnected = false` banner and auto-reconnect with bounded backoff; the player and session state are unaffected.
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
2. `repo.getSessionDetail(broadcastId)` → on `live` go to step 3; on `scheduled/upcoming` → `Scheduled`; on `ended` → `Ended`; on error → `Error`.
3. `presence.join(broadcastId)` (best-effort; failure is non-fatal, logged, surfaces a banner).
4. `repo.getPlaybackUrl(broadcastId)` then `playback.prepare(url)`; on success `transitionTo(Live(url))`.
5. Launch three child coroutines in `viewModelScope` under a `SupervisorJob`: chat collection, presence heartbeat, and goal/product side-channel routing.
6. Seed chat from session-detail history.

**Chat merge.** A `ChatMerger` keeps an in-memory ordered map keyed by stable id with `nonce` reconciliation.

```kotlin
internal class ChatMerger(private val max: Int = MAX_CHAT_MESSAGES) {
    fun seed(history: List<ChatMessage>)
    fun applyServer(event: ChatEvent): List<ChatMessageUi>     // dedupe by id; reconcile nonce
    fun applyOptimistic(msg: ChatMessageUi): List<ChatMessageUi>
    fun markFailed(nonce: String): List<ChatMessageUi>
    fun snapshot(): List<ChatMessageUi>                        // sorted by (serverTs ?: localTs, id)
}
```

Ordering key: `(serverTimestamp ?: localTimestamp, id)`; a `Pending` message uses `localTimestamp` and sorts last until the server echo replaces it (matched by `nonce`), at which point the entry is updated in place (no flicker, no duplicate). When size exceeds `max`, the oldest entries are dropped. The merged list is pushed into `_uiState` via `copy(chat = ...)`.

## 5. API Contract

This ViewModel calls into the AND-278 `BroadcastRepository`/`BroadcastApi`; the canonical wire shapes are owned there. The endpoints exercised:

- `GET /broadcast/sessions/{id}` → session detail (status, title, host, `chat_history`, `goals`, `products`, `viewer_count`).
- `GET /broadcast/sessions/{id}/playback-url` → `{ "url": "https://.../index.m3u8", "expires_at": "..." }`.
- `POST /broadcast/sessions/{id}/playback/verify` (owned by AND-280; VM only triggers re-verify on player auth error).
- `GET /broadcast/sessions/{id}/chat/stream` (SSE; owned by AND-281; VM consumes the decoded `ChatEvent` flow).
- `POST /broadcast/sessions/{id}/chat` body `{ "text": "...", "nonce": "<uuid>" }` → echoed message including server `id` + `nonce`.
- `POST /broadcast/sessions/{id}/viewers/{join|leave|heartbeat}` (owned by AND-285).

`ChatEvent` discriminated union consumed by the merger (status quo from AND-278 DTOs):

```json
{ "type": "message",  "id": "m_123", "nonce": "c-uuid", "user": {"id":"u1","name":"a"}, "text": "hi", "ts": "2026-06-05T12:00:00Z" }
{ "type": "reaction", "kind": "heart", "count": 42 }
{ "type": "tip",      "amount": 500, "currency": "usd", "from": "u1" }
{ "type": "goal",     "goal_id": "g1", "current": 1200, "target": 5000 }
{ "type": "product",  "product_id": "p1", "action": "pin" }
{ "type": "viewers",  "count": 318 }
```

Errors follow the project's FastAPI `detail` mapping (`string | [{msg}] | {code,...}`) and are surfaced as `ViewerError`. No new endpoints are introduced by this ticket.

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
    val id: String?,            // null until server-confirmed
    val nonce: String,          // client-generated, stable across reconcile
    val author: String,
    val text: String,
    val serverTs: Instant?,
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
- Chat text is treated as untrusted display data; no HTML/markup rendering decisions are made here (UI layer escapes). The VM trims and length-caps outgoing text (`MAX_CHAT_LEN = 500`) before send.
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
- **Chat merge tests:** seed + live events ordered correctly; duplicate server id ignored; optimistic send appears immediately as `Pending`, reconciles to `Sent` on echo by nonce (no dupe), `Failed` on error, `retryMessage` re-sends; bound enforced at `MAX_CHAT_MESSAGES` (oldest dropped); out-of-order server timestamps sort stably.
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
- **R2 (nonce echo):** reconciliation assumes the server echoes the client `nonce` on `POST /chat`. Confirm against `/openapi.json`; if absent, fall back to (author+text+near-timestamp) heuristic matching (riskier — flagged for AND-281).
- **R3 (SSE on dev host):** the unreliable plaintext host may drop SSE frequently; reconnect storms mitigated by jittered backoff + cap. Open: max session duration before forced playback-url re-verify.
- **R4 (count source of truth):** viewer count arrives both via session detail and `viewers` chat events; VM treats the latest `viewers` event as authoritative once Live. Confirm no double-counting on join.
- **R5:** scheduled→live auto-transition timing (poll vs. push) — currently a manual `retry()`/countdown; push-based promotion deferred.

## 14. Acceptance Criteria

- AC-1. `BroadcastViewerViewModel` exposes `StateFlow<ViewerUiState>` and `SharedFlow<ViewerEffect>` and implements the `ViewerSessionState` machine with exactly the legal transitions in §4; illegal transitions are dropped and logged.
- AC-2. A `live` broadcast drives `Idle→Joining→Live` and prepares playback; `scheduled`→`Scheduled` (no playback); `ended`→`Ended`.
- AC-3. Chat merge produces one ordered, deduplicated list across history + SSE + optimistic sends; optimistic messages reconcile by `nonce` to `Sent`/`Failed`; list bounded to `MAX_CHAT_MESSAGES`.
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
