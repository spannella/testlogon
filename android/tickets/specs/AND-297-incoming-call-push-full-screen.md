---
id: AND-297
title: Incoming call (push + full-screen)
milestone: M7
epic: E40
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-296, AND-108]
blocks: [AND-298, AND-299]
---

# AND-297 — Incoming call (push + full-screen)

## 1. Overview & Goal

Deliver the **incoming-call experience** for the TestLogon Android client: a high-priority FCM
data message carrying a call invite must wake the device, ring, and present a **full-screen
incoming-call UI** with **Accept** and **Decline** affordances — even when the app is
backgrounded, swiped away, or the screen is locked. On **Accept**, the call must connect by
handing the established signaling session to the in-call surface (AND-298). On **Decline** or
**ringer timeout**, the client must notify the backend, dismiss the UI, and release all
resources.

This ticket owns the *receive-side* terminal-state machine: payload ingestion → ringing →
{accept | decline | timeout | caller-cancel}. It does **not** own the in-call media/controls UI
(AND-298), the outgoing leg (AND-296), the FCM SDK wiring (AND-105/106), the signaling
transport (AND-290), or the call REST/DTO layer (AND-295) — it consumes all of them. Success is
measured by a single, hard acceptance gate: *an incoming call rings even when backgrounded and
connects on accept.*

## 2. Context & References

- **Module placement.** Code lands in a new `feature-call` module (shared with AND-296/298),
  package `com.testlogon.android.feature.call`. The FCM receiver lives in
  `com.testlogon.android.feature.call.incoming`. Layering: `feature-call -> core-data ->
  core-network -> core-model`; UI uses `core-ui`.
- **Dependencies (from backlog).**
  - **AND-296 — Outgoing call flow** (P0): provides the shared `CallSession`/signaling
    connect-and-hold primitives, the `CallRepository`, and the call-state model this ticket
    reuses for the *answer* path.
  - **AND-108 — Deep-link routing from taps**: provides the central deep-link/notification-tap
    router. The full-screen notification's content `PendingIntent` and the accept/decline
    actions route through the AND-108 destination map.
- **Transitive (already shipped, consumed not modified).** AND-105 (FCM + `google-services`),
  AND-106 (push-token registration), AND-107 (notification channels), AND-290 (signaling
  transport), AND-295 (call API + DTOs).
- **Backend.** FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable). Cookie +
  `ui_csrf`/`X-CSRF-Token` session; persistent cookie jar; 401 → single
  `POST /ui/session/refresh` then retry. OpenAPI at `/openapi.json`; web reference
  `frontend/src/api/endpoints/messaging.ts` (the direct-call helpers `createCallInvite`,
  `acceptCallInvite`, `declineCallInvite`, `timeoutCall`) + `frontend/src/api/client.ts`
  (CSRF/refresh transport). *Note (corrected during review): there is no `calls.ts`; the 1:1
  call helpers live in `messaging.ts`. The web app has no separate `types.ts` DTOs for calls —
  the request/response shapes are the OpenAPI `Call*` schemas (see §5).*
- **Platform.** minSdk 24, targetSdk 35, Kotlin 2.0.21, Compose + Material 3, Hilt (KSP),
  Coroutines/Flow.

## 3. Functional Requirements

1. **FCM invite ingestion.** A data message with `type == "call.invite"` is parsed into a
   `CallInvite` and handed to the incoming-call orchestrator regardless of process state
   (foreground, background, killed-but-restartable).
2. **Wake + ring while backgrounded.** Within the FCM `onMessageReceived` window the client
   must post a **full-screen-intent notification** on the high-importance `calls` channel
   (AND-107), with a looping ringtone and vibration, so the device rings and shows the
   full-screen UI from a locked/asleep state.
3. **Full-screen incoming UI.** Shows caller display name, avatar (Coil), call kind
   (audio/video), and large **Accept** / **Decline** buttons. Renders over the lock screen.
4. **Accept.** Confirms acceptance to the backend
   (`POST /messaging/messages/calls/{call_id}/accept`, body `CallAcceptIn`), fetches ICE servers
   (`POST /messaging/messages/calls/{call_id}/turn-credentials` → `TurnCredentialsOut`), connects
   the signaling session (AND-290/296), and navigates to the in-call screen (AND-298),
   cancelling the notification and stopping the ringer. *(Corrected: the path is
   `/messaging/messages/calls/{id}/accept`, not `/ui/calls/{id}/answer`; ICE servers come from a
   separate `turn-credentials` call, not embedded in the accept response.)*
5. **Decline.** Posts `POST /messaging/messages/calls/{call_id}/decline` (body `CallDeclineIn`,
   `reason` default `"declined"`), stops ringer, dismisses UI.
6. **Ringer timeout.** If neither action occurs within the invite's `expires_at` (or a hard
   default of **45 s**), notify the backend via `POST /messaging/messages/calls/{call_id}/timeout`
   (body `CallTimeoutIn`, `reason` default `"no_answer"`), stop ringing, dismiss. *(Corrected:
   timeout is a dedicated endpoint, not a `decline` with `reason="timeout"`. CallDeclineIn does
   not document a `timeout` reason value.)*
7. **Caller cancel / superseding state.** A `call.end`/`call.decline`/`call.missed` data message
   for the active invite must immediately stop ringing and dismiss. *(Corrected: the backend
   emits `call.end`/`call.missed`, not `call.cancel`/`call.ended`; see §13 Open Q1.)*
8. **Single-call invariant.** Only one incoming-call surface at a time. A second invite while
   one is ringing is auto-declined with `reason="busy"` (a documented `CallDeclineIn` value used
   by the web client).
9. **De-duplication.** Repeated FCM deliveries of the same `call_id` are idempotent (ring once).
10. **Runtime gating.** Honor `POST_NOTIFICATIONS` (API 33+) and `RECORD_AUDIO`/`CAMERA`
    permission state; on accept without media permission, request inline before connecting.

## 4. Technical Design

### 4.1 Components

```kotlin
// feature-call/incoming
// FCM entry point. Registered in app manifest, delegates to orchestrator.
@AndroidEntryPoint
class CallFcmService : FirebaseMessagingService() {
    @Inject lateinit var router: IncomingCallRouter
    override fun onMessageReceived(message: RemoteMessage) {
        router.onPushMessage(message.data)   // returns fast; heavy work off-thread
    }
    override fun onNewToken(token: String) { router.onNewToken(token) } // delegates to AND-106
}
```

```kotlin
@Singleton
class IncomingCallRouter @Inject constructor(
    private val parser: CallPushParser,
    private val controller: IncomingCallController,
) {
    fun onPushMessage(data: Map<String, String>) {
        when (val ev = parser.parse(data)) {
            is CallPushEvent.Invite -> controller.onInvite(ev.invite)
            is CallPushEvent.Cancel -> controller.onRemoteCancel(ev.callId, ev.reason)
            is CallPushEvent.Ignore -> Unit
        }
    }
}
```

```kotlin
@Singleton
class IncomingCallController @Inject constructor(
    private val repo: CallRepository,                 // AND-295/296
    private val ringer: Ringer,                       // ringtone + vibration + audio focus
    private val notifier: IncomingCallNotifier,       // full-screen-intent notification
    private val session: CallSessionManager,          // AND-290/296 signaling
    @ApplicationScope private val scope: CoroutineScope,
    private val clock: Clock,
) {
    private val _state = MutableStateFlow<IncomingCallState>(IncomingCallState.Idle)
    val state: StateFlow<IncomingCallState> = _state.asStateFlow()

    fun onInvite(invite: CallInvite)                  // dedupe, busy-check, ring, arm timeout
    fun accept()                                      // answer → connect → navigate
    fun decline(reason: DeclineReason = USER)
    fun onRemoteCancel(callId: String, reason: String)
}
```

- **`IncomingCallController` is a process-singleton** (Hilt `@Singleton`) holding the single
  active invite. It is intentionally *not* a ViewModel so it survives Activity recreation and is
  reachable from the FCM service before any UI exists. The full-screen `Activity` (or
  Compose destination) observes `controller.state`.

### 4.2 Full-screen presentation

A dedicated, lock-screen-capable Activity hosts the Compose UI and is launched by the
notification's `fullScreenIntent`:

```kotlin
@AndroidEntryPoint
class IncomingCallActivity : ComponentActivity() {
    @Inject lateinit var controller: IncomingCallController
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)            // API 27+
        setTurnScreenOn(true)
        (getSystemService(KeyguardManager::class.java))
            .requestDismissKeyguard(this, null)
        setContent { IncomingCallScreen(controller) }
    }
}
```

```kotlin
@Composable
fun IncomingCallScreen(
    controller: IncomingCallController,
    onConnected: (callId: String) -> Unit,   // -> AND-298 in-call route
) {
    val state by controller.state.collectAsStateWithLifecycle()
    when (val s = state) {
        is IncomingCallState.Ringing -> RingingContent(
            invite = s.invite,
            onAccept = controller::accept,
            onDecline = { controller.decline() },
        )
        is IncomingCallState.Connecting -> ConnectingContent(s.invite)
        is IncomingCallState.Connected -> LaunchedEffect(s.callId) { onConnected(s.callId) }
        is IncomingCallState.Dismissed, IncomingCallState.Idle ->
            LaunchedEffect(Unit) { /* finish() */ }
        is IncomingCallState.Failed -> ErrorContent(s.message, controller::dismiss)
    }
}
```

### 4.3 Notification (rings while backgrounded)

```kotlin
class IncomingCallNotifier @Inject constructor(@ApplicationContext ctx: Context) {
    fun showRinging(invite: CallInvite): Notification = NotificationCompat.Builder(ctx, CHANNEL_CALLS)
        .setSmallIcon(R.drawable.ic_call)
        .setCategory(NotificationCompat.CATEGORY_CALL)
        .setPriority(NotificationCompat.PRIORITY_MAX)
        .setOngoing(true)
        .setFullScreenIntent(fullScreenPendingIntent(invite), /* highPriority */ true)
        .setStyle(CallStyle.forIncomingCall(person(invite), declineIntent(invite), answerIntent(invite)))
        .build()
}
```

- Uses `NotificationCompat.CallStyle.forIncomingCall` (API 31+) for the rich call layout, with a
  `CallStyle` fallback to explicit action buttons on older OEM skins.
- The notification is posted **synchronously inside `onMessageReceived`** so the system grants
  the full-screen-intent privilege; the ringtone/audio-focus and the slower `repo.answer()` run
  on `@ApplicationScope` coroutines.
- `Ringer` requests `AUDIOFOCUS_GAIN_TRANSIENT`, plays `RingtoneManager.TYPE_RINGTONE` looped,
  and vibrates with a repeating pattern; honors ringer/DND mode.

## 5. API Contract

Consumes the AND-295 call endpoints (cookie-authed, `X-CSRF-Token` required on mutations).

> **Review correction.** The original draft referenced `/ui/calls/{id}/answer|decline` and a
> `GET /ui/calls/{id}` state endpoint. **None of those exist.** The authoritative 1:1 call
> endpoints (OpenAPI index lines 399–406) are mounted under `/messaging/messages/calls/...`. The
> answer verb is **`accept`** (not `answer`); there is **no** single-call `GET` resync endpoint;
> ICE servers come from a dedicated `turn-credentials` POST. Shapes below are taken verbatim from
> `components.schemas.*` in `openapi.pretty.json`.

**Invite payload (FCM `data`, strings only).** *Unverified-assumption — Android-only.* The
backend's web client receives invites over the SSE messaging stream as a `call.invite` event
(`src/hooks/useMessagingStream.ts`), **not** over FCM; OpenAPI does not document any FCM
data-message schema. The field set below is this ticket's proposed Android push contract and must
be confirmed with the backend push producer before GA. Where possible field names mirror
`CallInviteOut` (`call_id`, `conversation_id`, `caller_user_id`, `callee_user_id`, `initial_mode`).
```json
{
  "type": "call.invite",
  "call_id": "c_01HYZ...",
  "conversation_id": "conv_42",      // CallInviteOut.conversation_id (was wrongly "thread_id")
  "caller_user_id": "u_7",           // CallInviteOut.caller_user_id (was "caller_id")
  "caller_name": "Jordan Vega",      // display-only; not in OpenAPI, push-augmented
  "caller_avatar_url": "https://.../u_7.png", // display-only; not in OpenAPI, push-augmented
  "initial_mode": "video",           // CallInviteIn/Out.initial_mode: "audio" | "video"
  "expires_at": "2026-06-05T17:04:30Z" // not in OpenAPI; see §13 Open Q2
}
```

**Accept:** `POST /messaging/messages/calls/{call_id}/accept`  (req `CallAcceptIn`, resp `CallActionOut`)
```json
// request — CallAcceptIn (all optional)
{ "idempotency_key": "..." }
// 200 — CallActionOut
{ "call_id": "c_01HYZ...", "conversation_id": "conv_42", "state": "accepted",
  "event_ts": 1749142000, "from_state": "ringing", "reason": null, "voicemail_eligible": false }
```
*(Note: no `signaling`/`ice_servers` block in the response — that was invented. There is no
`media:{audio,video}` request field; media kind is carried by `initial_mode` on the invite.)*

**TURN/ICE (separate call, do this before connecting):**
`POST /messaging/messages/calls/{call_id}/turn-credentials` (no body) → `TurnCredentialsOut`
```json
{ "ttl_seconds": 3600, "expires_at": 1749145600,
  "ice_servers": [ { "urls": ["turn:..."], "username": "...", "credential": "..." } ] }
```

**Decline:** `POST /messaging/messages/calls/{call_id}/decline`  (req `CallDeclineIn`, resp `CallActionOut`)
```json
{ "reason": "declined" }   // CallDeclineIn.reason default "declined"; web client also sends "busy"
// 200 CallActionOut: { "call_id": "...", "conversation_id": "...", "state": "declined", "event_ts": ... }
```

**Timeout (no-answer):** `POST /messaging/messages/calls/{call_id}/timeout`  (req `CallTimeoutIn`, resp `CallActionOut`)
```json
{ "reason": "no_answer" }   // CallTimeoutIn.reason default "no_answer"; optional idempotency_key
```

**Resync after cold start / stale push.** *No 1:1 single-call `GET` endpoint exists.* For group
calls there is `GET /ui/calls/group/{call_id}`, but it does not apply to direct calls. Options
(see §7/§13): rely on FCM redelivery + a subsequent `call.end`/`call.missed` event, or query
billing/heartbeat side-channels (`GET /messaging/messages/calls/{call_id}/billing`). This ticket
**drops the GET-based resync**; treat absence of a terminal event within the ring window as the
authority for the local timeout.

**Retrofit signatures (in `CallApi`, AND-295):**
```kotlin
@POST("messaging/messages/calls/{id}/accept")
suspend fun accept(@Path("id") id: String, @Body b: CallAcceptIn): Response<CallActionOut>
@POST("messaging/messages/calls/{id}/decline")
suspend fun decline(@Path("id") id: String, @Body b: CallDeclineIn): Response<CallActionOut>
@POST("messaging/messages/calls/{id}/timeout")
suspend fun timeout(@Path("id") id: String, @Body b: CallTimeoutIn): Response<CallActionOut>
@POST("messaging/messages/calls/{id}/turn-credentials")
suspend fun turnCredentials(@Path("id") id: String): Response<TurnCredentialsOut>
```

Error `detail` follows the project mapping (`string | [{msg}] | {code,...}`) via the shared
`ApiResult<T>` decoder — **verified** against `src/api/client.ts: normalizeErrorDetail`, which
handles all three shapes; 422 bodies are `HTTPValidationError` (`detail: [ValidationError]`, each
with `msg`/`loc`/`type`). `accept`/`decline`/`timeout` are **not** retried automatically
(`decline`/`timeout` carry an optional `idempotency_key`, so a single network-failure retry is
safe; see §7). All `CallAcceptIn`/`CallDeclineIn`/`CallTimeoutIn` accept an `idempotency_key`,
which the de-dup layer should populate (derive from `call_id`).

## 6. Data & State Management

```kotlin
@JsonClass(generateAdapter = true)
data class CallInvite(
    // Corrected field names to mirror CallInviteOut: conversationId (not threadId),
    // callerUserId (not callerId). kind maps to CallInviteIn/Out.initial_mode ("audio"|"video").
    val callId: String, val conversationId: String, val callerUserId: String,
    val callerName: String, val callerAvatarUrl: String?,
    val kind: CallKind /* AUDIO, VIDEO -> initial_mode */, val expiresAt: Instant?,
)

sealed interface IncomingCallState {
    data object Idle : IncomingCallState
    data class Ringing(val invite: CallInvite, val deadline: Instant) : IncomingCallState
    data class Connecting(val invite: CallInvite) : IncomingCallState
    data class Connected(val callId: String, val signaling: SignalingHandle) : IncomingCallState
    data class Failed(val invite: CallInvite, val message: String) : IncomingCallState
    data object Dismissed : IncomingCallState
}

// Corrected to match CallDeclineIn (web sends "declined" | "busy"); TIMEOUT is routed to the
// /timeout endpoint (CallTimeoutIn, wire "no_answer"), NOT to /decline.
enum class DeclineReason(val wire: String) { USER("declined"), BUSY("busy") }
enum class TimeoutReason(val wire: String) { NO_ANSWER("no_answer") }
```

- **Single source of truth:** `IncomingCallController._state` (a `MutableStateFlow`). The
  Activity, the notification updater, and any foreground app screen all observe it.
- **Persistence:** none required across process death *during* ringing — a relaunched process
  recovers state from the next FCM redelivery or via `GET /ui/calls/{id}`. The set of
  recently-handled `call_id`s is held in an in-memory LRU (size 32) for de-dup; a short TTL copy
  is mirrored to DataStore (`incoming_call_seen`) so a fast process restart still de-dups.
- **Timeout:** armed via `scope.launch { delay(until(deadline)); timeout(NO_ANSWER) }` (calls the
  `/timeout` endpoint, not `/decline`), cancelled on any terminal transition.
  `deadline = invite.expiresAt?.coerceAtMost(now + 45s) ?: now + 45s` — `expires_at` is
  unverified/optional (see §13 Open Q2), so the 45 s client default is the authority when absent.
- **Handoff to AND-298:** on `Connected`, the `SignalingHandle` is published into
  `CallSessionManager` (AND-290/296) and navigation passes only `call_id`; the in-call screen
  rebinds to the live session rather than re-establishing it.

## 7. Error Handling & Resilience

- **Plaintext/unreliable backend:** all call HTTP uses the shared OkHttp client with **20 s**
  call timeout. *(Corrected: the bounded-backoff `GET /ui/calls/{id}` resync was removed — no such
  endpoint exists; see §5.)* `accept`/`decline`/`timeout` do not auto-retry beyond one
  network-failure retry for `decline`/`timeout`, made safe to repeat via the `idempotency_key` on
  `CallDeclineIn`/`CallTimeoutIn` (`accept` likewise carries an `idempotency_key`).
- **Accept failure (timeout / 5xx / signaling fail / turn-credentials fail):** transition to
  `Failed`, keep the user on the incoming screen with a brief inline error and a **Retry** that
  re-issues `accept` (reusing the same `idempotency_key`); if the call has since terminated
  (e.g. a `call.end`/`call.missed` event arrives, or `accept` returns a non-2xx terminal `state`
  such as `ended` in `CallActionOut.state`), dismiss with a toast. *(Note: 409 handling is an
  assumption — the OpenAPI for `/accept` documents only 200 and 422; backend may instead signal
  terminal state via `CallActionOut.state`/`from_state`.)*
- **401 during accept/decline/timeout:** the OkHttp authenticator performs one
  `POST /ui/session/refresh` then retries; persistent failure → `Failed` ("Sign in to take
  calls"). *(Verified against `src/api/client.ts`: 401 → single `refreshSession()` →
  `POST /ui/session/refresh` with `credentials: include` → one retry.)* The FCM service itself
  never blocks on auth — it always rings first.
- **Race conditions:** `onRemoteCancel` and the timeout both funnel through a single
  `transitionToTerminal()` guarded so the first terminal cause wins; subsequent causes are
  no-ops. Accept-after-cancel surfaces "Call ended".
- **Notification denial (API 33 `POST_NOTIFICATIONS` revoked):** full-screen intent may not
  fire; fall back to launching `IncomingCallActivity` directly when the app process is alive,
  and always still play the ringer. Log a telemetry warning.
- **OEM full-screen-intent restrictions (API 34 `USE_FULL_SCREEN_INTENT` policy):** declare the
  permission; if `NotificationManager.canUseFullScreenIntent()` is false, degrade to a
  high-priority heads-up call notification with action buttons.
- **De-dup / busy:** duplicate `call_id` → ignored; concurrent distinct call → auto-decline
  `busy`.

## 8. Security & Privacy

- All call mutations send `X-CSRF-Token` (echo of `ui_csrf` cookie) via the shared interceptor;
  the persistent cookie jar carries the session into the FCM-triggered background path.
- FCM payloads are **untrusted input**: every field is length-bounded and validated by
  `CallPushParser`; unknown/malformed payloads are dropped silently (no crash, telemetry only).
  Caller name/avatar are treated as display-only and never used to build privileged routes.
- The full-screen UI renders over the lock screen; it exposes **only** caller display name,
  avatar, and call kind — no thread contents, message previews, or PII beyond the caller
  identity. Avatar loads through Coil over the existing authed image pipeline.
- No call payload, ringtone state, or session token is written to plaintext logs (see §10).
- `RECORD_AUDIO`/`CAMERA` are requested *just-in-time* on accept, not at install.

## 9. Accessibility & i18n

- Accept/Decline buttons: min 48×48 dp touch targets, `contentDescription`
  ("Accept call from {name}", "Decline call from {name}"), and a logical focus order placing
  Accept first for TalkBack.
- Incoming screen announces caller + call kind via an `accessibilityLiveRegion`/`liveRegion`
  semantic when it appears.
- Ringtone/vibration are independent of visual ringing so non-visual users are alerted; vibration
  pattern still fires when the device is muted-but-vibrate.
- All strings (caller-kind labels, error/retry copy, notification title/actions, a11y
  descriptions) live in `feature-call` `strings.xml`; no concatenated/hard-coded user text.
  Timestamps/durations use locale-aware formatting. Layout supports RTL mirroring and Dynamic
  Type / large-font scaling (Compose `sp`).

## 10. Telemetry & Logging

- Structured events (via the app analytics sink): `call_invite_received` (push→render latency
  ms, app_state), `call_ring_started`, `call_accepted`, `call_declined` (reason),
  `call_invite_timeout`, `call_invite_failed` (cause), `call_invite_dropped` (parse/dedupe).
- Key latency metric: **invite-to-ring** (FCM receipt → notification posted) — alert if p95
  > 1.5 s — and **accept-to-connected**.
- Logs use the project tag scheme at `Log.i/w`; `call_id` is logged but caller PII, tokens,
  cookies, and CSRF values are **never** logged. Crash-free: parser and controller wrap all
  push-path work in guarded try/catch that downgrades to telemetry.

## 11. Testing Strategy

- **Unit (`core-testing` + Turbine + MockWebServer):**
  - `CallPushParser`: valid invite, missing/extra fields, wrong `type`, bad `expires_at`,
    oversized strings → expected `CallPushEvent`.
  - `IncomingCallController` state machine: invite→ring→accept→connected; →decline; →timeout
    (virtual `TestScope` clock); remote-cancel during ring; busy second invite; duplicate
    `call_id` de-dup; accept-after-cancel race resolves to `Failed`/dismiss.
  - HTTP: `accept`/`decline`/`timeout`/`turn-credentials` success (CallActionOut/TurnCredentialsOut),
    401→`/ui/session/refresh`→retry, terminal-state handling, 20 s timeout, `detail` error-shape
    decoding (string | [{msg}] | {code}); idempotency-key reuse on retry. *(The `get` backoff case
    was removed — no single-call GET endpoint exists.)*
- **Instrumented / UI (Compose test + JUnit4):** `IncomingCallScreen` renders caller + buttons;
  Accept/Decline invoke controller; a11y semantics present; `IncomingCallActivity` sets
  show-when-locked flags.
- **Notification:** Robolectric/`NotificationManagerShadow` asserts `CATEGORY_CALL`,
  full-screen-intent set, ongoing, `CallStyle` actions; fallback path when
  `canUseFullScreenIntent()==false`.
- **End-to-end (manual + scripted) — the acceptance gate:** with the app **backgrounded and
  swiped away** and **screen locked**, an injected `call.invite` (via Firebase console / `adb`
  data message) must ring and show the full-screen UI; tapping Accept connects to an AND-296
  outgoing peer and audio flows; Decline and 45 s timeout both notify backend and dismiss.
- **Matrix:** API 24 (no full-screen-intent policy), API 31 (`CallStyle`), API 33
  (`POST_NOTIFICATIONS`), API 34 (`USE_FULL_SCREEN_INTENT` gating); one OEM device with
  aggressive battery/notification restrictions.

## 12. Dependencies & Sequencing

- **Hard prerequisites:** **AND-296** (shared `CallSession`/`CallRepository`/signaling connect)
  and **AND-108** (notification-tap → in-app routing). Both must merge first.
- **Transitive prerequisites (assumed done):** AND-105 (FCM), AND-106 (token registration),
  AND-107 (`calls` channel), AND-290 (signaling transport), AND-295 (call API/DTOs).
- **This ticket blocks:** **AND-298** (in-call 1:1 UI consumes the connected session handed off
  here) and **AND-299** (group calls reuse the incoming surface).
- **Sequencing within ticket:** (1) `CallPushParser` + `CallInvite`; (2) `IncomingCallNotifier`
  + `Ringer`; (3) `IncomingCallController` state machine + timeout; (4) `IncomingCallActivity` +
  Compose UI; (5) answer/decline wiring + handoff to AND-298 route; (6) permission/OEM fallbacks.
- **Manifest:** register `CallFcmService` (`com.google.firebase.MESSAGING_EVENT`),
  `IncomingCallActivity` (`showWhenLocked`, `turnScreenOn`, `excludeFromRecents`), and declare
  `USE_FULL_SCREEN_INTENT` (+ runtime `POST_NOTIFICATIONS`).

## 13. Risks & Open Questions

- **R1 — OEM full-screen-intent suppression** (Xiaomi/Oppo/Samsung battery managers may drop the
  intent). Mitigation: `CallStyle` heads-up fallback + ringer always; document OEM
  whitelisting. *Residual risk: medium.*
- **R2 — API 34 `USE_FULL_SCREEN_INTENT` policy** auto-revokes for non-call apps. We declare
  `CATEGORY_CALL`, which qualifies, but must verify `canUseFullScreenIntent()` at runtime.
- **R3 — Process-killed cold start latency:** restarting the process + Hilt graph before ringing
  may exceed the p95 budget on low-end devices. Mitigation: keep the push path allocation-light;
  post the notification before any DI-heavy work.
- **R4 — Stale push after caller cancel:** dedupe + treat any `call.end`/`call.missed`/
  `call.decline` event for the active `call_id` as terminal. *(Updated: the previously-proposed
  `GET /ui/calls/{id}` resync is removed — no such endpoint exists; see §5.)*
- **Open Q1 — RESOLVED (web stream).** The backend does **not** emit `call.cancel` or
  `call.ended`. The web SSE stream (`src/hooks/useMessagingStream.ts` `EVENT_TYPES`) lists
  `call.invite`, `call.accept`, `call.decline`, `call.end`, `call.missed`. The parser must treat
  `call.end`/`call.missed`/`call.decline` (for the active call) as cancel/terminal. **Remaining
  unknown:** the exact FCM data-message `type` strings (the push transport is not in OpenAPI);
  assume they mirror the SSE event names. File a backend confirmation before GA.
- **Open Q2 — PARTIALLY RESOLVED.** There is **no** server-authoritative `expires_at` in any
  documented call schema (`CallInviteOut`, `CallActionOut`); none carries an expiry. The client
  must own the 45 s default. If `expires_at` appears in the FCM payload it is an undocumented
  push-only augmentation; treat it as advisory and clamp to the 45 s ceiling.
- **Open Q3:** Should a missed/declined call leave a persistent "missed call" notification
  (likely a follow-up ticket, not in this scope)?

## 14. Acceptance Criteria

1. **(Backlog gate)** With the app backgrounded **and** swiped from recents **and** the screen
   locked, an FCM `call.invite` causes the device to **ring** (ringtone + vibration) and display
   the **full-screen incoming UI** within p95 ≤ 1.5 s of receipt.
2. Tapping **Accept** calls `POST /messaging/messages/calls/{id}/accept`, obtains ICE servers via
   `POST /messaging/messages/calls/{id}/turn-credentials`, connects the signaling session, and
   navigates to the in-call screen (AND-298) with live audio/video for the negotiated `initial_mode`.
3. Tapping **Decline** calls `POST /messaging/messages/calls/{id}/decline` with `reason="declined"`,
   stops the ringer, and dismisses the UI.
4. With no user action, the client calls `POST /messaging/messages/calls/{id}/timeout`
   (`reason="no_answer"`) at `expires_at?.coerceAtMost(+45s) ?: +45s`, stops the ringer, and dismisses.
5. A `call.end`/`call.missed`/`call.decline` event for the ringing call stops ringing and
   dismisses immediately.
6. Duplicate deliveries of the same `call_id` ring exactly once; a second concurrent invite is
   auto-declined `busy`.
7. `401` during answer/decline triggers one `POST /ui/session/refresh` + retry; a 20 s timeout
   surfaces a retryable error without crashing.
8. Full-screen UI exposes only caller name/avatar/kind over the lock screen; no message content.
9. Accept/Decline have correct `contentDescription`s and ≥48 dp targets; TalkBack announces the
   incoming call.
10. Behavior verified on API 24, 31, 33, 34 and one restrictive-OEM device.

## 15. Definition of Done

- All §14 criteria pass, including the manual backgrounded/locked end-to-end ring-and-connect
  against the dev backend and an AND-296 outgoing peer.
- `feature-call.incoming` code merged to `android-port` under
  `com.testlogon.android.feature.call`, layering respected, no new lint/Detekt violations.
- Unit + Compose + Robolectric notification tests green in CI; state-machine coverage includes
  accept/decline/timeout/cancel/busy/dedup/401 paths.
- Manifest entries (`CallFcmService`, `IncomingCallActivity`, `USE_FULL_SCREEN_INTENT`,
  `POST_NOTIFICATIONS` runtime request) present; uses the AND-107 `calls` channel.
- Telemetry events (§10) emitted and verified; no PII/token/cookie/CSRF in logs.
- Handoff contract to AND-298 (publish `SignalingHandle` to `CallSessionManager`, navigate by
  `call_id`) documented and unblocked.
- Open questions Q1–Q2 resolved against `/openapi.json` + web reference or filed as follow-ups
  before release (see §16); spec status moved `draft → approved` after review.

## 16. Citations & Assumption Audit

Each key technical claim, its review VERDICT, and the exact source pointer.

1. **1:1 call endpoints are `POST /messaging/messages/calls/{id}/{accept|decline|timeout}`.**
   VERDICT: **Corrected** (draft said `/ui/calls/{id}/answer|decline`). SOURCE: OpenAPI index
   `POST /messaging/messages/calls/{call_id}/accept` (op `accept_call_invite_...`),
   `.../decline` (op `decline_call_invite_...`), `.../timeout` (op `timeout_call_endpoint_...`).
2. **Answer verb is `accept`, not `answer`.** VERDICT: **Corrected.** SOURCE: OpenAPI
   `POST /messaging/messages/calls/{call_id}/accept`; frontend `src/api/endpoints/messaging.ts:
   acceptCallInvite`.
3. **Accept request body = `CallAcceptIn` (only optional `idempotency_key`); no
   `media:{audio,video}` field.** VERDICT: **Corrected** (draft invented a media block). SOURCE:
   `components.schemas.CallAcceptIn`.
4. **Accept response = `CallActionOut` (`call_id`, `conversation_id`, `state`, `event_ts`,
   `from_state?`, `reason?`, `voicemail_eligible`); no embedded `signaling`/`ice_servers`.**
   VERDICT: **Corrected.** SOURCE: `components.schemas.CallActionOut`; OpenAPI
   `resp=200:CallActionOut` on `/accept`.
5. **ICE servers come from `POST /messaging/messages/calls/{id}/turn-credentials` →
   `TurnCredentialsOut` (`ttl_seconds`, `expires_at`, `ice_servers[].{urls,username,credential}`).**
   VERDICT: **Corrected** (draft embedded them in the answer response). SOURCE:
   `components.schemas.TurnCredentialsOut` + `TurnIceServerOut`; OpenAPI
   `POST /messaging/messages/calls/{call_id}/turn-credentials`; frontend
   `src/api/endpoints/messaging.ts` (`/messaging/messages/calls/${callId}/turn-credentials`).
6. **Decline body = `CallDeclineIn` (`reason` default `"declined"`); web client sends
   `"declined" | "busy"`; `"user"` is not a valid value.** VERDICT: **Corrected** (draft used
   `reason="user"` and `"timeout"`). SOURCE: `components.schemas.CallDeclineIn`; frontend
   `src/api/endpoints/messaging.ts: declineCallInvite` (`reason?: "declined" | "busy"`).
7. **Timeout is a dedicated endpoint `/timeout` with `CallTimeoutIn` (`reason` default
   `"no_answer"`), not a `decline` variant.** VERDICT: **Corrected.** SOURCE:
   `components.schemas.CallTimeoutIn`; OpenAPI `POST /messaging/messages/calls/{call_id}/timeout`;
   frontend `src/api/endpoints/messaging.ts: timeoutCall`.
8. **There is no single-call state-fetch `GET` endpoint (`GET /ui/calls/{id}` does not exist).**
   VERDICT: **Corrected** (resync via GET removed). SOURCE: OpenAPI index — the only `/messaging/
   messages/calls/{call_id}/...` reads are `/billing` and (POST) `/signal`; group calls have
   `GET /ui/calls/group/{call_id}` but that is not the 1:1 path.
9. **Backend emits `call.end`/`call.missed`/`call.decline`, not `call.cancel`/`call.ended`.**
   VERDICT: **Corrected.** SOURCE: frontend `src/hooks/useMessagingStream.ts` `EVENT_TYPES`
   (lines ~188–192: `call.invite`, `call.accept`, `call.decline`, `call.end`, `call.missed`).
10. **Auth/CSRF: cookie session + `X-CSRF-Token` echo of `ui_csrf` cookie on mutations;
    `credentials: include`.** VERDICT: **Verified.** SOURCE: `src/api/client.ts` (`getCookie
    ("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `credentials: "include"`).
11. **401 → single `POST /ui/session/refresh` then one retry.** VERDICT: **Verified.** SOURCE:
    `src/api/client.ts: refreshSession()` → `fetch(withApiBase("/ui/session/refresh"))`; 401 path
    calls it once (guarded by `refreshPromise`) then retries.
12. **Error `detail` decodes as `string | [{msg,...}] | {code,...}`; 422 = `HTTPValidationError`.**
    VERDICT: **Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail`;
    `components.schemas.HTTPValidationError` (`detail: [ValidationError]`).
13. **Invite carries `conversation_id` + `caller_user_id` + `initial_mode` (`audio|video`), not
    `thread_id`/`caller_id`/`kind`.** VERDICT: **Corrected** (field names aligned to schemas).
    SOURCE: `components.schemas.CallInviteIn`/`CallInviteOut` (`conversation_id`, `callee_user_id`,
    `caller_user_id`, `initial_mode` default `"audio"`); frontend `DirectCallMode = "audio"|"video"`.
14. **FCM data-message transport + payload (the whole receive trigger).** VERDICT:
    **Unverified-assumption.** SOURCE: none — OpenAPI documents no FCM/push schema; the web client
    receives invites over SSE (`src/hooks/useMessagingStream.ts`), which does not apply to a
    backgrounded mobile app. The payload in §5 is this ticket's proposed contract.
15. **Server-authoritative `expires_at` on the invite.** VERDICT: **Unverified-assumption** (and
    not present in any documented schema). SOURCE: `CallInviteOut`/`CallActionOut` carry no
    expiry field; client owns the 45 s default.
16. **`signal` uses typed errors `CallSignalingErrorOut` (`code`/`message`) with 4xx/5xx codes.**
    VERDICT: **Verified** (informational; signaling is AND-290's surface). SOURCE: OpenAPI
    `POST /messaging/messages/calls/{call_id}/signal` (`resp=...400:CallSignalingErrorOut;...`);
    `components.schemas.CallSignalingErrorOut`.
17. **Full-screen-intent / lock-screen framework choices.** VERDICT: **Verified (framework ref).**
    SOURCES: `CallStyle.forIncomingCall` requires API 31+
    (https://developer.android.com/reference/androidx/core/app/NotificationCompat.CallStyle);
    `setShowWhenLocked`/`setTurnScreenOn` API 27+
    (https://developer.android.com/reference/android/app/Activity#setShowWhenLocked(boolean));
    `USE_FULL_SCREEN_INTENT` + `NotificationManager.canUseFullScreenIntent()` gating on API 34+
    (https://developer.android.com/reference/android/app/NotificationManager#canUseFullScreenIntent());
    `POST_NOTIFICATIONS` runtime permission API 33+
    (https://developer.android.com/develop/ui/views/notifications/notification-permission).

### Corrections made

- §2/§5: replaced non-existent `frontend/.../calls.ts` + `calls.ts`-DTO references with
  `messaging.ts`/`client.ts`; removed the claimed `types.ts` call DTOs.
- §3/§5/§6/§7/§14: changed all call paths from `/ui/calls/{id}/answer|decline` and
  `GET /ui/calls/{id}` to the real `/messaging/messages/calls/{id}/{accept|decline|timeout}` and
  `/turn-credentials`; removed the non-existent single-call GET resync.
- §5: corrected accept request (`CallAcceptIn`, no media block) and response (`CallActionOut`, no
  embedded `signaling`/`ice_servers`); added the separate `turn-credentials` step.
- §6/§3/§14: decline `reason` `"user"`→`"declined"`; timeout moved to the `/timeout` endpoint with
  `"no_answer"`; split `DeclineReason`/`TimeoutReason`.
- §6: `CallInvite` field names → `conversationId`/`callerUserId`/`initial_mode`; `expiresAt` made
  nullable.
- §3/§7/§13/§14: cancel events `call.cancel`/`call.ended` → `call.end`/`call.missed`/`call.decline`.
- §11: dropped the `get` backoff test; updated HTTP cases to the real endpoints/DTOs.

### Open assumptions

- **A1 — FCM push transport & exact `data` keys/`type` strings.** Unverifiable from OpenAPI (no
  push schema) or the web app (uses SSE). Must be confirmed with the backend push producer.
- **A2 — `expires_at` in the invite.** Not in any documented schema; treated as advisory, clamped
  to a 45 s client ceiling.
- **A3 — Conflict/terminal signalling on `accept` (e.g. HTTP 409).** OpenAPI documents only
  200/422 for `/accept`; whether a late accept returns 409 vs. a terminal `CallActionOut.state`
  is unconfirmed — handle both defensively.
- **A4 — `voicemail_eligible` in `CallActionOut`.** Present in the schema but out of scope for
  this ticket; not consumed here (possible follow-up, cf. §13 Open Q3 missed-call UX).

## 17. Test Plan

IDs `TC-AND-297-NN`. "Traces" link to §14 Acceptance Criteria (AC-1…AC-10). Target legend matches
the available CI/dev targets; hardware-dependent cases call out the **physical device**
(Samsung Galaxy A15 5G, SM-A156U, API 34, arm64) vs the **emulator** (AVD `test35`, API 35,
x86_64) vs **JVM/Robolectric**.

- **TC-AND-297-01 — Push parse: valid invite → `CallInvite`.** Type: unit (JVM). Target:
  JVM/Robolectric. Preconditions: `CallPushParser` instantiated. Steps: feed a `data` map with
  `type=call.invite`, `call_id`, `conversation_id`, `caller_user_id`, `caller_name`,
  `initial_mode=video`, `expires_at`. Expected: `CallPushEvent.Invite` with correctly mapped
  fields (`conversationId`, `callerUserId`, `kind=VIDEO`, nullable `expiresAt` parsed). Traces:
  AC-1.
- **TC-AND-297-02 — Push parse: malformed/oversized/wrong-type dropped.** Type: unit (JVM).
  Target: JVM. Preconditions: parser. Steps: feed (a) wrong `type`, (b) missing `call_id`,
  (c) oversized strings, (d) bad `expires_at`. Expected: `CallPushEvent.Ignore` (or dropped),
  no throw, telemetry `call_invite_dropped`. Traces: AC-1, AC-8.
- **TC-AND-297-03 — Controller state machine: invite→ring→accept→connected.** Type: unit (JVM,
  `TestScope` virtual clock + Turbine). Target: JVM. Preconditions: fakes for repo/ringer/
  notifier/session. Steps: `onInvite()`, then `accept()`. Expected: state Ringing→Connecting→
  Connected; ringer started then stopped; `accept` + `turn-credentials` invoked once each.
  Traces: AC-2.
- **TC-AND-297-04 — Contract: accept happy path (MockWebServer).** Type: contract/MockWebServer.
  Target: JVM. Preconditions: MockWebServer enqueues 200 `CallActionOut` then 200
  `TurnCredentialsOut`. Steps: call `CallApi.accept()` then `turnCredentials()`. Expected: POST to
  `/messaging/messages/calls/{id}/accept` with `X-CSRF-Token` header and `CallAcceptIn` body;
  parsed `state`/`event_ts`; ICE servers parsed from `TurnCredentialsOut`. Traces: AC-2.
- **TC-AND-297-05 — Contract: decline / timeout endpoints & reasons.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: MWS returns 200 `CallActionOut`. Steps: invoke `decline(USER)` and
  `timeout(NO_ANSWER)`. Expected: POST `/decline` with `{"reason":"declined"}` and POST `/timeout`
  with `{"reason":"no_answer"}`; both carry `idempotency_key`. Traces: AC-3, AC-4.
- **TC-AND-297-06 — Contract: 401 → refresh → retry; error `detail` shapes.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: MWS returns 401 once, then 200; separately a
  422 `HTTPValidationError` and a `{code,...}` body. Steps: call `accept()`. Expected: a single
  `POST /ui/session/refresh` then one retry succeeds; `detail` decoded for string/`[{msg}]`/
  `{code}` shapes without crash. Traces: AC-7.
- **TC-AND-297-07 — Controller: timeout auto-fires at deadline.** Type: unit (JVM, virtual clock).
  Target: JVM. Preconditions: invite with no `expires_at`. Steps: `onInvite()`, advance virtual
  time 45 s with no action. Expected: `/timeout` (`no_answer`) called once, ringer stopped, state
  Dismissed; with `expires_at < 45 s` the earlier deadline wins. Traces: AC-4.
- **TC-AND-297-08 — Controller: remote terminal + dedupe + busy.** Type: unit (JVM). Target: JVM.
  Steps: (a) `onRemoteCancel(call.end)` during ring → immediate stop/dismiss; (b) duplicate
  `call_id` invite → ring exactly once (LRU/DataStore de-dup); (c) second distinct invite while
  ringing → auto-decline `busy`; (d) accept-after-cancel race → first terminal cause wins →
  Failed/dismiss. Expected: as stated; `transitionToTerminal()` idempotent. Traces: AC-5, AC-6.
- **TC-AND-297-09 — Notification: CallStyle full-screen-intent built correctly.** Type:
  Robolectric (shadow NotificationManager). Target: JVM/Robolectric. Preconditions: API 31+
  shadow. Steps: `IncomingCallNotifier.showRinging()`. Expected: `CATEGORY_CALL`, `PRIORITY_MAX`,
  ongoing, `setFullScreenIntent(..., highPriority=true)`, `CallStyle.forIncomingCall` actions on
  the `calls` channel. Traces: AC-1, AC-8.
- **TC-AND-297-10 — Notification fallback when `canUseFullScreenIntent()==false`.** Type:
  Robolectric. Target: JVM/Robolectric. Preconditions: shadow returns false (simulating API 34
  policy). Steps: post ringing notification. Expected: degrade to high-priority heads-up call
  notification with action buttons; ringer still starts; telemetry warning. Traces: AC-1, AC-10.
- **TC-AND-297-11 — Compose UI: incoming screen + accessibility.** Type: Compose-UI test. Target:
  emulator `test35` (or Robolectric Compose). Preconditions: controller stub in Ringing. Steps:
  render `IncomingCallScreen`; assert caller name/avatar/kind shown; Accept/Decline have
  `contentDescription` "Accept call from {name}"/"Decline call from {name}", ≥48 dp targets,
  Accept first in focus order, `liveRegion` announcement; clicking invokes
  `controller.accept()`/`decline()`. Traces: AC-3, AC-9.
- **TC-AND-297-12 — Instrumented: Activity lock-screen flags.** Type: instrumented. Target:
  emulator `test35`. Preconditions: launch `IncomingCallActivity` via its PendingIntent. Steps:
  inspect window flags. Expected: `setShowWhenLocked(true)`, `setTurnScreenOn(true)`,
  `requestDismissKeyguard` invoked; `excludeFromRecents`. Traces: AC-1, AC-8.
- **TC-AND-297-13 — Security: untrusted payload + lock-screen privacy + CSRF.** Type: integration
  (MockWebServer + Robolectric). Target: JVM/Robolectric. Steps: (a) inject hostile fields
  (script in `caller_name`, huge avatar URL, attacker `conversation_id`) → display-only, never
  used to build privileged routes, length-bounded; (b) assert lock-screen UI shows only
  name/avatar/kind (no message/thread content); (c) assert every mutation carries `X-CSRF-Token`
  and no token/cookie/CSRF/PII appears in logs. Traces: AC-7, AC-8.
- **TC-AND-297-14 — E2E acceptance gate: backgrounded + swiped + locked rings & connects.**
  Type: instrumented/e2e (manual + scripted). Target: **PHYSICAL DEVICE (SM-A156U, API 34)** —
  required: real FCM delivery, real ringtone/vibration/audio-focus, lock-screen full-screen-intent
  behavior, and live WebRTC audio to an AND-296 peer. Preconditions: app installed, signed in,
  `calls` channel + `POST_NOTIFICATIONS` granted, app swiped from recents, screen locked.
  Steps: deliver a real `call.invite` FCM to the device; observe ring + full-screen UI; tap
  Accept; verify audio flows; in a second run, tap Decline; in a third, let it time out at 45 s.
  Expected: rings within p95 ≤ 1.5 s; Accept connects with live media; Decline → `/decline`
  (`declined`) + dismiss; timeout → `/timeout` (`no_answer`) + dismiss. (Emulator `test35` cannot
  validate real FCM push + ringer/lock-screen hardware behavior; use it only for the UI subset.)
  Traces: AC-1, AC-2, AC-3, AC-4.
- **TC-AND-297-15 — OEM / API matrix + restrictive battery manager.** Type: instrumented/manual.
  Target: emulator `test35` (API 35) for API-35 path; **physical device** (API 34, arm64) for the
  `USE_FULL_SCREEN_INTENT` API-34 gating and ABI/API-34-vs-35 differences; one restrictive-OEM
  device for battery/notification suppression of the full-screen intent. Steps: repeat the ring +
  accept flow per target. Expected: ring + full-screen (or documented heads-up fallback) on each;
  document OEM whitelisting needs. Traces: AC-10, AC-1.

### Coverage matrix

| §14 AC | Covered by |
| ------ | ---------- |
| AC-1 (rings backgrounded/locked ≤1.5 s p95) | TC-01, TC-02, TC-09, TC-10, TC-12, TC-14, TC-15 |
| AC-2 (Accept → accept+turn-credentials → connect) | TC-03, TC-04, TC-14 |
| AC-3 (Decline → `/decline` `declined`) | TC-05, TC-11, TC-14 |
| AC-4 (timeout → `/timeout` `no_answer`) | TC-05, TC-07, TC-14 |
| AC-5 (remote terminal stops/dismisses) | TC-08 |
| AC-6 (dedupe once / busy second) | TC-08 |
| AC-7 (401→refresh→retry; 20 s timeout no crash) | TC-06, TC-13 |
| AC-8 (lock-screen shows only name/avatar/kind) | TC-02, TC-09, TC-12, TC-13 |
| AC-9 (a11y: contentDescription, ≥48 dp, TalkBack) | TC-11 |
| AC-10 (API 24/31/33/34 + restrictive OEM) | TC-10, TC-15 |
