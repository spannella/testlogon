---
id: AND-297
title: Incoming call (push + full-screen)
milestone: M7
epic: E40
priority: P0
size: L
status: draft
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
  `frontend/src/api/endpoints/calls.ts` + `frontend/src/api/types.ts`.
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
4. **Accept.** Confirms acceptance to the backend (`POST /ui/calls/{call_id}/answer`), connects
   the signaling session (AND-290/296), and navigates to the in-call screen (AND-298),
   cancelling the notification and stopping the ringer.
5. **Decline.** Posts `POST /ui/calls/{call_id}/decline`, stops ringer, dismisses UI.
6. **Ringer timeout.** If neither action occurs within the invite's `expires_at` (or a hard
   default of **45 s**), auto-decline locally with `reason="timeout"`, stop ringing, dismiss.
7. **Caller cancel / superseding state.** A `call.cancel`/`call.ended` data message (or a state
   poll showing the call already terminal) for the active invite must immediately stop ringing
   and dismiss.
8. **Single-call invariant.** Only one incoming-call surface at a time. A second invite while
   one is ringing is auto-declined with `reason="busy"`.
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

**Invite payload (FCM `data`, strings only):**
```json
{
  "type": "call.invite",
  "call_id": "c_01HYZ...",
  "thread_id": "t_42",
  "caller_id": "u_7",
  "caller_name": "Jordan Vega",
  "caller_avatar_url": "https://.../u_7.png",
  "kind": "video",
  "expires_at": "2026-06-05T17:04:30Z"
}
```

**Answer:** `POST /ui/calls/{call_id}/answer`
```json
// request
{ "client": "android", "media": { "audio": true, "video": true } }
// 200
{ "call_id": "c_01HYZ...", "state": "connecting", "signaling": { "session_id": "s_9", "ice_servers": [ ... ] } }
```

**Decline:** `POST /ui/calls/{call_id}/decline`
```json
{ "reason": "user" }   // user | timeout | busy
// 200 { "call_id": "c_01HYZ...", "state": "declined" }
```

**State fetch (resync after cold start / stale push):** `GET /ui/calls/{call_id}`
```json
{ "call_id": "c_01HYZ...", "state": "ringing", "expires_at": "2026-06-05T17:04:30Z" }
```

**Retrofit signatures (in `CallApi`, AND-295):**
```kotlin
@POST("ui/calls/{id}/answer")  suspend fun answer(@Path("id") id: String, @Body b: AnswerRequest): Response<AnswerResponse>
@POST("ui/calls/{id}/decline") suspend fun decline(@Path("id") id: String, @Body b: DeclineRequest): Response<CallStateDto>
@GET("ui/calls/{id}")          suspend fun get(@Path("id") id: String): Response<CallStateDto>
```

Error `detail` follows the project mapping (`string | [{msg}] | {code,...}`) via the shared
`ApiResult<T>` decoder. `GET /ui/calls/{id}` is idempotent → eligible for bounded backoff retry;
`answer`/`decline` are **not** retried automatically (decline is retried only on idempotent-safe
network failure, see §7).

## 6. Data & State Management

```kotlin
@JsonClass(generateAdapter = true)
data class CallInvite(
    val callId: String, val threadId: String?, val callerId: String,
    val callerName: String, val callerAvatarUrl: String?,
    val kind: CallKind /* AUDIO, VIDEO */, val expiresAt: Instant,
)

sealed interface IncomingCallState {
    data object Idle : IncomingCallState
    data class Ringing(val invite: CallInvite, val deadline: Instant) : IncomingCallState
    data class Connecting(val invite: CallInvite) : IncomingCallState
    data class Connected(val callId: String, val signaling: SignalingHandle) : IncomingCallState
    data class Failed(val invite: CallInvite, val message: String) : IncomingCallState
    data object Dismissed : IncomingCallState
}

enum class DeclineReason(val wire: String) { USER("user"), TIMEOUT("timeout"), BUSY("busy") }
```

- **Single source of truth:** `IncomingCallController._state` (a `MutableStateFlow`). The
  Activity, the notification updater, and any foreground app screen all observe it.
- **Persistence:** none required across process death *during* ringing — a relaunched process
  recovers state from the next FCM redelivery or via `GET /ui/calls/{id}`. The set of
  recently-handled `call_id`s is held in an in-memory LRU (size 32) for de-dup; a short TTL copy
  is mirrored to DataStore (`incoming_call_seen`) so a fast process restart still de-dups.
- **Timeout:** armed via `scope.launch { delay(until(deadline)); decline(TIMEOUT) }`, cancelled
  on any terminal transition. `deadline = min(invite.expiresAt, now + 45s)`.
- **Handoff to AND-298:** on `Connected`, the `SignalingHandle` is published into
  `CallSessionManager` (AND-290/296) and navigation passes only `call_id`; the in-call screen
  rebinds to the live session rather than re-establishing it.

## 7. Error Handling & Resilience

- **Plaintext/unreliable backend:** all call HTTP uses the shared OkHttp client with **20 s**
  call timeout. `GET /ui/calls/{id}` uses bounded exponential backoff (3 attempts,
  250 ms→1 s, jitter). `answer`/`decline` do not auto-retry beyond one network-failure retry
  for `decline` (safe to repeat).
- **Answer failure (timeout / 5xx / signaling fail):** transition to `Failed`, keep the user on
  the incoming screen with a brief inline error and a **Retry** that re-issues `answer`; if the
  call has since expired (`409`/state `ended`), dismiss with a toast.
- **401 during answer/decline:** the OkHttp authenticator performs one
  `POST /ui/session/refresh` then retries; persistent failure → `Failed` ("Sign in to take
  calls"). The FCM service itself never blocks on auth — it always rings first.
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
  - HTTP: `answer`/`decline` success, 401→refresh→retry, 409 expired, 20 s timeout, `detail`
    error-shape decoding; `get` backoff retry count.
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
- **R4 — Stale push after caller cancel:** dedupe + `GET /ui/calls/{id}` resync on render.
- **Open Q1:** Does the backend emit a distinct `call.cancel` data message, or only
  `call.ended`? (Confirm against `/openapi.json` + `frontend/src/api/endpoints/calls.ts`;
  parser currently treats both as cancel.)
- **Open Q2:** Is there a server-authoritative `expires_at`, or must the client own the 45 s
  default? (Spec assumes `expires_at` when present, client default otherwise.)
- **Open Q3:** Should a missed/declined call leave a persistent "missed call" notification
  (likely a follow-up ticket, not in this scope)?

## 14. Acceptance Criteria

1. **(Backlog gate)** With the app backgrounded **and** swiped from recents **and** the screen
   locked, an FCM `call.invite` causes the device to **ring** (ringtone + vibration) and display
   the **full-screen incoming UI** within p95 ≤ 1.5 s of receipt.
2. Tapping **Accept** calls `POST /ui/calls/{id}/answer`, connects the signaling session, and
   navigates to the in-call screen (AND-298) with live audio/video for the negotiated `kind`.
3. Tapping **Decline** calls `POST /ui/calls/{id}/decline` with `reason="user"`, stops the
   ringer, and dismisses the UI.
4. With no user action, the call auto-declines with `reason="timeout"` at
   `min(expires_at, +45s)`, notifies backend, and dismisses.
5. A `call.cancel`/`call.ended` for the ringing call stops ringing and dismisses immediately.
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
- Open questions Q1–Q2 resolved against `/openapi.json` or filed as follow-ups before release;
  spec status moved `draft → approved` after review.
