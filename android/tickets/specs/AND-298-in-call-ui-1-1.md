---
id: AND-298
title: In-call UI (1:1)
milestone: M7
epic: E40
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-296, AND-293]
blocks: [AND-299]
---

# AND-298 — In-call UI (1:1)

## 1. Overview & Goal

Deliver the on-screen experience for an active one-to-one audio/video call: the
composable surface that hosts the local and remote video renderers, the floating
control bar (mute microphone, toggle camera, speaker/audio-route, flip camera,
end call), the live connection-quality indicator, and the elapsed-duration timer.

AND-296 (Outgoing call flow) and AND-297 (Incoming call) establish *how* a call
is created, signaled, connected, and torn down. AND-293 supplies the
`SurfaceViewRenderer` Compose wrappers. This ticket is responsible for *what the
user sees and touches once a `PeerConnection` reaches the connected state*, and
for wiring control taps to the underlying WebRTC `RtpSender`/audio-device/camera
APIs that AND-296 already manages.

Goal (single acceptance bullet from backlog): **every control functions during a
live call.** Concretely: tapping mute silences the outgoing audio track within
one frame; camera toggle stops/starts the outgoing video track and updates the
local renderer; speaker routes audio to the loudspeaker; flip switches between
front/back cameras without dropping the track; end terminates the call and
returns to the prior screen. Connection quality and duration update live.

This screen lives in `feature-calls` and renders entirely from a
`StateFlow<InCallUiState>`; it owns no signaling or session logic of its own.

## 2. Context & References

- Repo `spannella/testlogon`, branch `android-port`, Android app in `android/`.
- Module: `feature-calls` (consumes `core-ui`, `core-model`, `core-data`).
- Package root: `com.testlogon.android.feature.calls.incall`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow.
  WebRTC via the `org.webrtc` native bindings introduced in AND-288/AND-290.
- Upstream tickets:
  - **AND-296 — Outgoing call flow**: owns `CallSessionController`, the
    `PeerConnection`, `RtpSender`s for audio/video, camera capturer, signaling
    over `/ui/calls/*`, and the call lifecycle state machine. This ticket reads
    its `StateFlow` and invokes its control methods.
  - **AND-293 — Video renderer composables**: provides
    `LocalVideoRenderer(track, modifier, scaling)` and
    `RemoteVideoRenderer(track, modifier, scaling)` Compose wrappers over
    `SurfaceViewRenderer`. This ticket composes them into the layout.
- Downstream: **AND-299 — Group calls** reuses this control bar and quality
  model for N>2 participants; keep control/state contracts grid-friendly.
- Web reference: 1:1 call lifecycle calls live in `src/api/endpoints/messaging.ts`
  (`createCallInvite`, `acceptCallInvite`, `declineCallInvite`, `endCall`,
  `sendSignalingEvent`, `fetchTurnCredentials`); the connected-call UI is
  `src/pages/messages/CallSessionOverlay.tsx`; the lifecycle reducer is
  `src/pages/messages/callStateMachine.ts`; the quality heuristic is
  `src/hooks/useConnectionQuality.ts`. **Correction:** there is no
  `src/api/endpoints/calls.ts` in the reference app (see §16).
- Backend FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable);
  OpenAPI at `/openapi.json`. Transport (verified against `src/api/client.ts`):
  `credentials: include` cookie session **plus** a `Bearer` access-token
  `Authorization` header **plus** an `X-CSRF-Token` header sourced from the
  `ui_csrf` cookie. (The spec's earlier "cookie-based session + X-CSRF-Token"
  was incomplete — the Bearer token is also sent; see §16.)

## 3. Functional Requirements

FR-1 **Render surfaces.** Display the remote video full-bleed; overlay the local
video as a draggable picture-in-picture tile (default top-right, ~96x128dp,
snapping to the nearest corner). When either side has no video track (audio-only
or camera off), show an avatar + display name placeholder for that surface.

FR-2 **Control bar** (bottom, auto-hiding after 4s of inactivity in video mode,
always visible in audio-only mode; reappears on tap anywhere):
- **Mute** — toggles the outgoing audio track `enabled`. Stateful icon.
- **Camera** — toggles the outgoing video track `enabled`; when off, stops the
  capturer and shows the local placeholder. Disabled (greyed) for audio-only.
- **Speaker / audio route** — cycles/sets earpiece ↔ loudspeaker (and reflects
  Bluetooth/wired headset when present). Stateful icon reflecting active route.
- **Flip camera** — switches front/back; debounced (ignore taps while a switch
  is in flight); no-op + disabled when only one camera exists or camera is off.
- **End** — terminates the call (red, prominent, centered or trailing).

FR-3 **Connection quality indicator.** Show a 4-level signal glyph
(Excellent / Good / Poor / Lost) driven by WebRTC stats sampled every 2s. On
`Poor`, surface a transient "Weak connection" banner. On `Lost`
(ICE disconnected) show a reconnecting spinner over the remote surface; clear it
when ICE returns to `connected`.

FR-4 **Duration timer.** Display `mm:ss` (rolling to `h:mm:ss` past one hour),
starting from the instant the call reaches `Connected`, ticking once per second,
pausing display while in `Reconnecting` but not resetting the count.

FR-5 **Lifecycle behavior.** On call ending (local end, remote hangup, or fatal
error) the screen shows a brief terminal state ("Call ended", duration) for
~1.5s then pops back to the originating screen. Pressing system Back during an
active call does **not** end the call; it triggers PiP/minimize behavior if
available, otherwise shows an end-call confirmation only on a long-press of End.

FR-6 **System integration.** Keep the screen awake and orientation-locked to the
parent activity policy; integrate with the existing `ConnectionService`/foreground
call notification owned by AND-296/AND-297 (this ticket does not create it, but
its mute/end actions must stay in sync with notification actions via shared
controller state).

## 4. Technical Design

Single-Activity + Navigation-Compose. Route registered by AND-296:
`calls/incall/{callId}`.

```kotlin
@Composable
fun InCallRoute(
    onCallEnded: () -> Unit,
    viewModel: InCallViewModel = hiltViewModel(),
)

@Composable
fun InCallScreen(
    state: InCallUiState,
    onAction: (InCallAction) -> Unit,
)
```

ViewModel is a thin adapter: it does not own the `PeerConnection`. It reads the
shared `CallSessionController` (singleton, provided by AND-296) and maps the
session/stats streams into `InCallUiState`, and forwards `InCallAction`s to
controller methods.

```kotlin
@HiltViewModel
class InCallViewModel @Inject constructor(
    private val controller: CallSessionController,   // from feature-calls (AND-296)
    private val stats: CallStatsSampler,             // this ticket
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<InCallUiState>
    fun onAction(action: InCallAction)
}
```

Control surface contract this ticket *consumes* from `CallSessionController`
(method signatures defined by AND-296; listed here as the integration contract):

```kotlin
interface CallSessionController {
    val session: StateFlow<CallSession>           // lifecycle + tracks + media flags
    fun setMicEnabled(enabled: Boolean)
    fun setCameraEnabled(enabled: Boolean)
    fun switchCamera()                            // suspends/callbacks internally
    fun setAudioRoute(route: AudioRoute)          // EARPIECE | SPEAKER | BLUETOOTH | WIRED
    fun endCall(reason: EndReason = EndReason.LOCAL_HANGUP)
    fun peerConnectionStats(): Flow<RTCStatsReport>
}
```

Actions:

```kotlin
sealed interface InCallAction {
    data object ToggleMic : InCallAction
    data object ToggleCamera : InCallAction
    data object FlipCamera : InCallAction
    data class SetRoute(val route: AudioRoute) : InCallAction
    data object CycleRoute : InCallAction
    data object EndCall : InCallAction
    data class MoveLocalTile(val corner: PipCorner) : InCallAction
    data object ToggleControls : InCallAction
}
```

`CallStatsSampler` polls `peerConnectionStats()` on a 2s tick (coroutine on
`Dispatchers.Default`), extracts the inbound/outbound RTP and candidate-pair
stats, derives a `ConnectionQuality`, and exposes `Flow<QualitySample>`:

```kotlin
class CallStatsSampler @Inject constructor(private val controller: CallSessionController) {
    fun quality(): Flow<QualitySample> // sampleEvery(2.seconds)
}
data class QualitySample(
    val level: ConnectionQuality,   // EXCELLENT, GOOD, POOR, LOST
    val rttMs: Long?,
    val packetLossPct: Double?,
    val jitterMs: Double?,
)
```

Quality heuristic (from candidate-pair RTT + inbound packetsLost/packetsReceived
over the interval): EXCELLENT rtt<150 & loss<2%; GOOD rtt<300 & loss<5%; POOR
otherwise; LOST when ICE state is `DISCONNECTED`/`FAILED` or no stats for >6s.

Duration: a `tickerFlow(1.second)` started when `session.lifecycle == Connected`,
combined with a stored `connectedAtElapsedRealtime` so it survives recomposition
and config changes via `SavedStateHandle`.

Renderers (AND-293) are placed by `InCallScreen`:
```kotlin
RemoteVideoRenderer(track = state.remoteVideo, scaling = SCALE_ASPECT_FILL,
    modifier = Modifier.fillMaxSize())
if (state.localVideo != null && state.cameraEnabled)
    LocalVideoRenderer(track = state.localVideo, scaling = SCALE_ASPECT_FILL,
        modifier = Modifier.size(96.dp, 128.dp).align(state.localTileCorner.alignment))
```

Audio routing uses an `AudioSwitchManager` wrapping `AudioManager`
(`setMode(MODE_IN_COMMUNICATION)`, `setCommunicationDevice` on API 31+, legacy
`isSpeakerphoneOn` below). Owned by the controller; this screen only requests
routes and renders the active one.

## 5. API Contract

This ticket is predominantly client-side UI over an already-established WebRTC
media session; the **call create/answer/end/signaling endpoints are owned by
AND-296**. **Correction:** the endpoint paths the spec previously listed
(`POST /ui/calls/start`, `/ui/calls/{id}/answer`, `/ui/calls/{id}/ice`,
`/ui/calls/{id}/end`) **do not exist** in the backend. The `/ui/calls/*`
namespace is for *group* calls (`/ui/calls/group/*`) plus history/rates/aggregate
stats. The 1:1 ("direct") call lifecycle endpoints (verified in
`openapi.index.txt`) are:
```
POST  /messaging/messages/calls/invite                 req=CallInviteIn  → CallInviteOut
POST  /messaging/messages/calls/{call_id}/accept       req=CallAcceptIn  → CallActionOut
POST  /messaging/messages/calls/{call_id}/decline      req=CallDeclineIn → CallActionOut
POST  /messaging/messages/calls/{call_id}/end          req=CallEndIn     → CallActionOut
POST  /messaging/messages/calls/{call_id}/timeout      req=CallTimeoutIn → CallActionOut
POST  /messaging/messages/calls/{call_id}/signal       req=CallSignalingIn → CallSignalingOut (offer/answer/ICE)
POST  /messaging/messages/calls/{call_id}/turn-credentials → TurnCredentialsOut
PATCH /messaging/messages/calls/{call_id}/heartbeat    req=HeartbeatIn   → HeartbeatOut
```
(Note: the reference web client's `endCall()` helper calls the path
`/messages/calls/{id}/end`, but the only `/messages/calls/*` paths the OpenAPI
actually defines are call *recording* routes — the authoritative server route for
ending a call is `/messaging/messages/calls/{call_id}/end`. Use the OpenAPI path.)

Two contract touch-points are relevant to this screen:

**End call** — triggered by the End control; the request is issued by the
controller, but this screen guarantees it fires exactly once. Verified shapes
(`CallEndIn` request, `CallActionOut` response):
```
POST /messaging/messages/calls/{call_id}/end
Headers: Cookie: <session>; Authorization: Bearer <token>; X-CSRF-Token: <ui_csrf>
Body (CallEndIn): { "reason": "ended", "idempotency_key": "<opt>" }
  // reason is a free-form string, server default "ended" (NOT an enum;
  //  the spec's "hangup | declined | timeout" was an invented enum — see §16)
200 (CallActionOut) → {
  "call_id": "...", "conversation_id": "...", "state": "ended",
  "event_ts": 1733500000, "from_state": "connected",
  "reason": "ended", "voicemail_eligible": false
}
  // NOTE: there is no top-level "status" or "duration_s" field; lifecycle is in
  //  "state", and there is no server-returned call duration on this response.
```

**Optional quality/QoS report** — **Correction / removed:** there is **no**
`POST /ui/calls/{id}/stats` (or any per-call QoS-report POST) endpoint in the
backend. The only `/ui/calls/stats` route is `GET` → `CallStatsOut`, an
*aggregate per-user* summary (`total_calls`, `calls_by_status`, `calls_by_type`,
`total_duration_seconds`) — not a per-call terminal-quality sink. The reference
web client does not POST any terminal quality report. Therefore this screen does
**not** send a QoS report; terminal quality is emitted only via the §10
`call_ended` analytics event. (See §16, Open assumptions — confirm no future
per-call telemetry endpoint is planned before relying on this.)

Error `detail` mapping follows the project convention and is verified against
`src/api/client.ts: normalizeErrorDetail`: `detail` may be a string, an array of
`{ msg }` items (FastAPI `HTTPValidationError`/422), or an object carrying a
`code` (e.g. authorization/`geo_blocked`). The signaling endpoint additionally
returns `CallSignalingErrorOut` (`{ code, message }`) on 400/403/404/409/429/503.
The Android `ApiResult<T>` error decoder must mirror this. Stats/analytics
failures are swallowed (logged only); end-call failures still tear down the local
session and surface a non-blocking toast.

No new persistent fetch on this screen — all live data is WebRTC stats, not HTTP.

## 6. Data & State Management

```kotlin
data class InCallUiState(
    val callId: String,
    val peerName: String,
    val peerAvatarUrl: String?,
    val lifecycle: CallLifecycle,        // Connecting, Connected, Reconnecting, Ended
    val isVideoCall: Boolean,
    val localVideo: VideoTrack?,
    val remoteVideo: VideoTrack?,
    val micEnabled: Boolean,
    val cameraEnabled: Boolean,
    val flipInFlight: Boolean,
    val hasMultipleCameras: Boolean,
    val audioRoute: AudioRoute,
    val availableRoutes: Set<AudioRoute>,
    val quality: ConnectionQuality,
    val showWeakBanner: Boolean,
    val durationLabel: String,           // "01:37"
    val controlsVisible: Boolean,
    val localTileCorner: PipCorner,
    val endedReason: EndReason?,
)
```

State is derived, not stored authoritatively: `uiState` =
`combine(controller.session, statsSampler.quality(), durationTicker, localUi)`
mapped on the ViewModel scope and exposed via `stateIn(WhileSubscribed(5_000))`.
`micEnabled`, `cameraEnabled`, `audioRoute` are the controller's truth (so they
stay consistent with notification actions); `controlsVisible` and
`localTileCorner` are local view-state held in the ViewModel and persisted in
`SavedStateHandle` to survive rotation.

No Room/DataStore writes are required for this screen. (Persisting call history
is out of scope and not in this ticket's acceptance.) DataStore is read only for
the "default to speaker on video call" user preference if present.

## 7. Error Handling & Resilience

- **ICE disconnect (transient):** lifecycle → `Reconnecting`; remote surface
  shows a spinner + dimmed last frame; duration display freezes but counter keeps
  running. Recovery to `Connected` restores UI. No user action required;
  reconnection/ICE-restart logic is owned by AND-296.
- **ICE failed / reconnect timeout (>~30s):** lifecycle → `Ended(reason=NETWORK)`;
  show "Call ended — connection lost", then pop.
- **Camera/flip failure:** `switchCamera` callback error → clear `flipInFlight`,
  keep current camera, show transient "Couldn't switch camera"; never leave the
  control stuck in a spinner.
- **Audio-route failure (device unavailable):** fall back to earpiece, refresh
  `availableRoutes`, reflect the actual active route from `AudioManager`.
- **End-call HTTP failure:** local teardown proceeds regardless (media + audio
  mode reset); failure logged, non-blocking toast. Backend dev host is unreliable
  — end must be locally authoritative.
- **Double-tap / re-entrancy:** all controls debounce; End is idempotent (guard
  with `endRequested` flag so `POST /end` fires once).
- **Process death mid-call:** if the foreground call service is still alive, the
  screen rebinds to the existing `CallSessionController` via `callId`; otherwise
  it shows `Ended` and pops.

## 8. Security & Privacy

- Requires `RECORD_AUDIO` and (for video) `CAMERA` runtime permissions; these are
  granted/verified by AND-296 before this screen is reachable. If revoked
  mid-call (Android can revoke), detect via track error and degrade to audio-only
  + inform the user.
- No PII is logged. Telemetry uses `callId` (opaque) and peer **user id**, never
  display name, email (`spannella@gmail.com`-class data), or message content.
- Media never persists to disk; `VideoTrack` frames are render-only.
- Session/CSRF: the End request (there is no stats POST — see §5/§16) reuses the
  persistent cookie jar + `Authorization: Bearer` + `X-CSRF-Token` (from the
  `ui_csrf` cookie), matching `src/api/client.ts`. On 401 the OkHttp authenticator
  performs the single `POST /ui/session/refresh` + retry per project policy
  (verified: `client.ts: refreshSession` posts to `/ui/session/refresh` once and
  retries the original request).
- Local video PiP tile is hidden from screenshots only if a global secure-screen
  flag is set elsewhere; this ticket does not set `FLAG_SECURE` unilaterally.

## 9. Accessibility & i18n

- Every control has a `contentDescription` reflecting state, e.g. "Mute
  microphone" vs "Unmute microphone", "Turn camera off" vs "Turn camera on",
  "Speaker on"/"Speaker off", "Flip camera", "End call". State changes announce
  via `semantics { stateDescription = … }`.
- Connection quality and duration are grouped into a single polite
  live-region so screen readers announce changes without flooding (throttle
  duration announcements; do not announce every second).
- Minimum touch target 48x48dp for all controls; control bar respects
  navigation-bar insets and never overlaps system gestures.
- All strings in `strings.xml`; duration formatted with locale-aware
  `mm:ss`/`h:mm:ss` (no hardcoded separators). Layout is RTL-safe — the PiP tile
  default corner and control order mirror in RTL.
- Respect large font scaling; control bar uses icons (size-stable), labels only
  in TalkBack.

## 10. Telemetry & Logging

Events via the `core-data` analytics interface (no PII per §8):

| Event | Properties |
|---|---|
| `call_incall_shown` | callId, isVideo |
| `call_control_tap` | callId, control(mute/camera/speaker/flip/end), newState |
| `call_quality_changed` | callId, level, rttMs, lossPct |
| `call_reconnecting` | callId |
| `call_ended` | callId, durationS, endReason, terminalQuality |

Logging: `Timber` tags `InCall`; quality samples logged at DEBUG, lifecycle
transitions at INFO, control failures at WARN. No frame data or media content
ever logged. Stats-report HTTP failures logged at WARN and suppressed from UI.

## 11. Testing Strategy

**Unit (JVM, `core-testing` rules):**
- `InCallViewModel` maps a fake `CallSessionController.session` + fake quality
  flow into the expected `InCallUiState`; assert each `InCallAction` calls the
  matching controller method exactly once (mockk verify).
- `CallStatsSampler` quality heuristic: table-driven tests mapping
  (rtt, loss, iceState, staleness) → `ConnectionQuality` at all four levels and
  LOST-on-stale.
- Duration formatting: 0s, 59s, 60s, 3599s, 3600s, 3661s → labels; freeze during
  Reconnecting without resetting.
- Idempotent End: two `EndCall` actions → one `endCall()` call.

**Compose UI (Robolectric / `createComposeRule`):**
- Each control toggles its `contentDescription`/state on tap.
- Camera control disabled in audio-only state; flip disabled when
  `hasMultipleCameras == false` or camera off.
- Weak-connection banner appears on POOR and reconnecting spinner on LOST.
- Local PiP hidden when `cameraEnabled == false`; placeholder shown.
- Controls auto-hide after timeout and reappear on tap (advance test clock).

**Instrumented (optional, gated):** smoke test with a loopback
`PeerConnection` verifying mute actually flips the outbound track `enabled` and
end resets `AudioManager.mode`.

Acceptance is met when the "controls function during a call" UI tests pass and
the loopback smoke test confirms track/route side effects.

## 12. Dependencies & Sequencing

- **Hard deps (must land first):**
  - **AND-296** — `CallSessionController`, lifecycle state machine, signaling,
    audio route manager, camera capturer, `endCall`. This ticket cannot start
    integration until its control method signatures are stable.
  - **AND-293** — `LocalVideoRenderer` / `RemoteVideoRenderer` composables.
- **Soft/parallel:** AND-297 (incoming) shares the same screen entry; coordinate
  on the `calls/incall/{callId}` route ownership (route declared once by AND-296).
- **Blocks:** **AND-299** (Group calls) extends this control bar + quality model
  to multi-party; keep `InCallUiState`/control contracts list-friendly so AND-299
  can reuse them per participant tile.
- Suggested order: AND-293 → AND-296 → **AND-298** → AND-297 (entry) → AND-299.

## 13. Risks & Open Questions

- **R1 — Controller API churn (AND-296).** If `CallSessionController` signatures
  shift, this screen breaks. Mitigation: agree the interface in §4 as a contract
  PR before parallel work.
- **R2 — Stats schema variance.** WebRTC `RTCStatsReport` field availability
  varies by codec/transport; heuristic must tolerate missing fields (treat as
  GOOD, not LOST). Validate against real loopback stats.
- **R3 — Audio routing fragmentation** across OEMs/API 24–35 (legacy
  `isSpeakerphoneOn` vs `setCommunicationDevice`). Owned by AND-296 but surfaces
  as wrong route-icon bugs here.
- **Q1 — Does a per-call stats/QoS endpoint exist?** **Resolved (no).** Confirmed
  against `openapi.index.txt`: there is no `POST /ui/calls/{id}/stats` nor any
  per-call QoS sink. `GET /ui/calls/stats` (`CallStatsOut`) is an aggregate
  per-user summary only. The §5 QoS report has been dropped; terminal quality is
  carried by the `call_ended` analytics event (§10).
- **Q2 — PiP (Picture-in-Picture window) on Back:** is system PiP in scope for
  M7, or just minimize? Default: minimize only; system PiP deferred.
- **Q3 — Default audio route for video calls:** speaker-on by default? Pending a
  product/DataStore preference; default speaker for video, earpiece for audio.

## 14. Acceptance Criteria

1. During a connected 1:1 call, **Mute** toggles the outbound audio track and the
   icon/`contentDescription` reflect state; the peer stops/starts hearing audio.
2. **Camera** toggle stops/starts the outbound video track and swaps the local
   surface to/from the avatar placeholder; disabled for audio-only calls.
3. **Speaker/route** changes the active audio route (earpiece ↔ loudspeaker,
   reflecting headset/Bluetooth when present) and the icon shows the active route.
4. **Flip camera** switches front/back without dropping the call; debounced and
   disabled when only one camera or camera off.
5. **End** terminates the call once (single `POST /ui/calls/{id}/end`), resets
   audio mode, and pops back to the originating screen after the terminal state.
6. **Connection-quality** indicator updates within ~2s of stats change across all
   four levels; POOR shows a banner; LOST shows a reconnecting spinner.
7. **Duration** timer starts at Connected, ticks each second, formats
   `mm:ss`/`h:mm:ss`, and does not reset across a Reconnecting interval.
8. Remote video renders full-bleed; local video renders as a draggable, corner-
   snapping PiP tile.
9. All controls meet 48dp targets and expose state-aware accessibility labels.

## 15. Definition of Done

- `feature-calls` `InCallRoute`/`InCallScreen`/`InCallViewModel`/`CallStatsSampler`
  implemented under `com.testlogon.android.feature.calls.incall`, wired to the
  AND-296 `CallSessionController` and AND-293 renderers.
- All §14 criteria demonstrably pass; unit + Compose UI tests in §11 green in CI;
  loopback smoke test verifies mute/route/end side effects.
- No PII in logs/telemetry; lint (incl. accessibility) and Detekt clean.
- Strings externalized and RTL-verified; minSdk 24 / targetSdk 35 builds with the
  pinned toolchain (Kotlin 2.0.21, AGP 8.7.3, JDK 17, Gradle 8.9).
- Control/state contracts reviewed by the AND-299 owner for group-call reuse.
- Merged to `android-port` with screenshots/recording of a working 1:1 call
  attached to the PR.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **End-call endpoint.** Claim (original): `POST /ui/calls/{callId}/end` with body
   `{reason:"hangup"}` → `{call_id,status,duration_s}`.
   **VERDICT: Corrected.** Real route is `POST /messaging/messages/calls/{call_id}/end`,
   request `CallEndIn`, response `CallActionOut`.
   *Source:* OpenAPI `POST /messaging/messages/calls/{call_id}/end`
   (`openapi.index.txt` line 403; op `end_call_endpoint_…`); schemas
   `components.schemas.CallEndIn` and `components.schemas.CallActionOut`
   (`openapi.pretty.json`); frontend `src/api/endpoints/messaging.ts: endCall`.
2. **End-call request body.** Claim: `reason` enum `hangup | declined | timeout`.
   **VERDICT: Corrected.** `CallEndIn.reason` is a free-form `string` (server
   default `"ended"`), plus optional `idempotency_key`. No enum constraint.
   *Source:* `components.schemas.CallEndIn`.
3. **End-call response fields.** Claim: `{call_id, status, duration_s}`.
   **VERDICT: Corrected.** `CallActionOut` = required `call_id`, `conversation_id`,
   `state`, `event_ts`; optional `from_state`, `reason`, `voicemail_eligible`.
   No `status` or `duration_s` field; lifecycle is in `state`.
   *Source:* `components.schemas.CallActionOut`.
4. **Call create/answer/ICE endpoints.** Claim: `POST /ui/calls/start`,
   `/ui/calls/{id}/answer`, `/ui/calls/{id}/ice`.
   **VERDICT: Corrected.** Those paths do not exist. Direct-call lifecycle is
   `POST /messaging/messages/calls/invite` (`CallInviteIn`→`CallInviteOut`),
   `…/{call_id}/accept` (`CallAcceptIn`→`CallActionOut`), and SDP offer/answer +
   ICE candidates all go through `POST /messaging/messages/calls/{call_id}/signal`
   (`CallSignalingIn` with `type` matching
   `^(webrtc\.offer|webrtc\.answer|webrtc\.ice_candidate|webrtc\.screen_share_start|webrtc\.screen_share_stop)$`
   → `CallSignalingOut`). The `/ui/calls/*` namespace is group-calls + history.
   *Source:* OpenAPI lines 399–407 (`openapi.index.txt`); schemas
   `CallSignalingIn`/`CallSignalingOut`; frontend
   `src/api/endpoints/messaging.ts: createCallInvite/acceptCallInvite/sendSignalingEvent`.
5. **Per-call QoS/stats report.** Claim: optional `POST /ui/calls/{callId}/stats`
   with `{rtt_ms_avg, packet_loss_pct, duration_s, quality_terminal}` → `{ok:true}`.
   **VERDICT: Corrected (removed).** No such POST exists. `GET /ui/calls/stats`
   (`CallStatsOut`: `total_calls`, `calls_by_status`, `calls_by_type`,
   `total_duration_seconds`) is an aggregate per-user summary, not a per-call sink.
   The reference web client posts no terminal-quality report.
   *Source:* OpenAPI `GET /ui/calls/stats` (`openapi.index.txt` line 1306);
   `components.schemas.CallStatsOut`; absence in `src/api/endpoints/messaging.ts`.
6. **Transport / auth.** Claim: "Cookie-based session + `X-CSRF-Token`".
   **VERDICT: Corrected (incomplete).** Web client sends, on every call,
   `credentials: include` (cookie) **+** `Authorization: Bearer <accessToken>`
   **+** `X-CSRF-Token` from the `ui_csrf` cookie.
   *Source:* `src/api/client.ts` (lines ~156–171).
7. **401 → session refresh.** Claim: single `POST /ui/session/refresh` + retry.
   **VERDICT: Verified.** Client refreshes once via `POST /ui/session/refresh`,
   then retries the original request; on repeat 401 it logs out.
   *Source:* `src/api/client.ts: refreshSession` (line ~122) and the 401 handler.
8. **Error `detail` decoder shape.** Claim: string | `[{msg}]` | `{code,...}`.
   **VERDICT: Verified.** `normalizeErrorDetail` handles exactly these three
   shapes (string; array of `{msg}`; object with `code`, incl. authorization and
   `geo_blocked`).
   *Source:* `src/api/client.ts: normalizeErrorDetail`.
9. **Signaling error response.** (New, supporting §5.) `POST …/signal` returns
   `CallSignalingErrorOut` (`{code, message}`) on 400/403/404/409/429/503.
   **VERDICT: Verified.**
   *Source:* OpenAPI line 405; `components.schemas.CallSignalingErrorOut`.
10. **TURN credentials.** (Supporting context for AND-296, used by quality/ICE.)
    `POST /messaging/messages/calls/{call_id}/turn-credentials` →
    `TurnCredentialsOut` (`ttl_seconds`, `expires_at`, `ice_servers[]`).
    **VERDICT: Verified.**
    *Source:* OpenAPI line 407; `components.schemas.TurnCredentialsOut` /
    `TurnIceServerOut`; `src/api/endpoints/messaging.ts: fetchTurnCredentials`.
11. **Quality heuristic & 2 s poll.** Claim: poll WebRTC stats every 2 s; from
    candidate-pair RTT + inbound packetsLost/packetsReceived; thresholds
    EXCELLENT rtt<150 & loss<2%, GOOD rtt<300 & loss<5%, POOR otherwise.
    **VERDICT: Verified (thresholds + method + cadence).** Web hook polls
    `getStats()` every 2000 ms, reads `candidate-pair` (state `succeeded`)
    `currentRoundTripTime` (seconds) and `inbound-rtp` `packetsLost`/
    `packetsReceived`, and classifies good `<150ms & <2%`, fair `<300ms & <5%`,
    else poor. (Web names the tiers good/fair/poor + unknown; the Android
    EXCELLENT/GOOD/POOR mapping is 1:1 with web good/fair/poor.)
    *Source:* `src/hooks/useConnectionQuality.ts`.
12. **Fourth "LOST" quality level (ICE disconnected/failed or stale >6s).**
    **VERDICT: Unverified-assumption (Android design extension).** The web has no
    "Lost" quality tier; it surfaces interruption through the call state machine's
    `reconnecting` phase instead, not the quality glyph.
    *Source:* `src/hooks/useConnectionQuality.ts` (only good/fair/poor/unknown);
    `src/pages/messages/callStateMachine.ts` (`CONNECTION_LOST`→`reconnecting`).
    Acceptable as an Android-only UI choice; not a backend contract.
13. **Duration timer starts at Connected, mm:ss / h:mm:ss, ticks 1 Hz.**
    **VERDICT: Verified (web parity for the core behavior).** Web `CallTimer`
    increments every 1000 ms while `running` and renders `mm:ss`. The h:mm:ss
    roll-over past one hour and "freeze display during Reconnecting without
    resetting" are Android refinements (web resets the timer when not running).
    *Source:* `src/pages/messages/CallSessionOverlay.tsx: CallTimer`.
14. **Control accessibility labels** (Mute/Unmute, Turn camera on/off, End call).
    **VERDICT: Verified.** Identical aria-labels in the web control bar.
    *Source:* `src/pages/messages/CallSessionOverlay.tsx: CallControls`.
15. **Mute/camera = toggle track `enabled`.** **VERDICT: Verified (web behavior).**
    Web exposes `onToggleMute`/`onToggleCamera`; `isCameraOff` placeholder shown
    when off; remote video hidden → avatar placeholder when no live video track.
    *Source:* `src/pages/messages/CallSessionOverlay.tsx` (PiP `isCameraOff`
    branch; `hasRemoteVideo` track-enabled/!muted check).
16. **Speaker / audio-route and Flip-camera controls.** **VERDICT:
    Unverified-assumption (mobile-only, no web equivalent / framework refs).** The
    web call UI has no speaker-route or flip-camera control (browser handles
    output routing; no front/back concept). These are Android platform features.
    *Source (framework ref):* `AudioManager.setCommunicationDevice` /
    `MODE_IN_COMMUNICATION`
    (https://developer.android.com/reference/android/media/AudioManager);
    WebRTC `CameraVideoCapturer.switchCamera`
    (https://developer.android.com/develop/connectivity/webrtc — org.webrtc bindings).
17. **`ConnectionService` / foreground call-notification integration.**
    **VERDICT: Unverified-assumption (owned by AND-296; framework ref).** Not
    represented in the web reference; an Android platform integration.
    *Source (framework ref):* Telecom `ConnectionService`
    (https://developer.android.com/reference/android/telecom/ConnectionService);
    foreground service type `phoneCall`
    (https://developer.android.com/about/versions/14/changes/fgs-types-required).
18. **Single-Activity + Navigation-Compose route `calls/incall/{callId}`.**
    **VERDICT: Unverified-assumption (declared by AND-296; no source in repo).**
    Cannot be confirmed from backend/web; it is an internal Android-app contract.
19. **`RECORD_AUDIO` / `CAMERA` runtime permissions.** **VERDICT: Verified
    (framework requirement).** Required for mic/camera capture.
    *Source (framework ref):*
    https://developer.android.com/training/permissions/requesting and
    https://developer.android.com/reference/android/Manifest.permission#CAMERA .

### Corrections made

- §2: replaced non-existent `frontend/src/api/endpoints/calls.ts` with the real
  reference files (`messaging.ts`, `CallSessionOverlay.tsx`, `callStateMachine.ts`,
  `useConnectionQuality.ts`); corrected the transport description to include the
  `Bearer` token alongside cookie session + `X-CSRF-Token`.
- §5: corrected the entire end-call contract — path
  (`/ui/calls/{id}/end` → `/messaging/messages/calls/{call_id}/end`), request body
  (invented `reason` enum → free-form `CallEndIn`), and response shape
  (`{status, duration_s}` → `CallActionOut` `{call_id, conversation_id, state,
  event_ts, …}`). Corrected the bogus `start/answer/ice` paths to the real
  `invite/accept/signal` routes. Removed the non-existent `POST /ui/calls/{id}/stats`
  QoS report and clarified `GET /ui/calls/stats` is an aggregate summary. Added the
  verified error-decoder + `CallSignalingErrorOut` details.
- §8: corrected session/CSRF to include the `Bearer` token and verified the
  `/ui/session/refresh` retry; noted there is no stats POST.
- §13 Q1: marked resolved (no per-call stats endpoint).

### Open assumptions

- **4-tier quality incl. LOST** (item 12): no web/backend basis; Android-only UI
  decision. Verify against real loopback `RTCStatsReport` (R2) before shipping the
  LOST-on-stale (`>6s`) rule, since field availability varies by codec/transport.
- **Speaker-route, flip-camera, ConnectionService, FGS** (items 16–18): mobile
  platform features with no web reference; their exact controller method
  signatures are owned by AND-296 and unverifiable here (R1). Treat §4's
  `CallSessionController` interface as a contract to be ratified with AND-296.
- **Route `calls/incall/{callId}`** (item 18): internal app navigation contract,
  declared by AND-296; not in any authoritative source.
- **Default audio route (speaker for video, earpiece for audio)** (§13 Q3): pending
  product/DataStore preference; no backend or web source.
- **Per-call telemetry endpoint**: none exists today (item 5). If product later
  wants server-side call QoS, a new endpoint must be added; do not assume one.

## 17. Test Plan

Test-target legend: **JVM** = local JVM unit/Robolectric (no device);
**Emu(test35)** = headless AVD `test35`, x86_64, API 35; **Device(A15)** =
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Hardware-dependent
cases prefer Device(A15). MockWebServer cases run on JVM unless a real OkHttp
stack on-device is required.

- **TC-AND-298-01** — Type: unit (JVM). Target: `InCallViewModel`.
  Preconditions: fake `CallSessionController` emitting a `session` in `Connected`
  with mic on, camera on, two cameras, video call; fake quality flow = GOOD.
  Steps: collect `uiState`; assert mapping. Expected: `InCallUiState` has
  `lifecycle=Connected`, `micEnabled=true`, `cameraEnabled=true`,
  `hasMultipleCameras=true`, `quality=GOOD`, `durationLabel` present.
  Traces: AC-1, AC-2, AC-4, AC-6, AC-7.
- **TC-AND-298-02** — Type: unit (JVM). Target: `InCallViewModel.onAction`.
  Preconditions: mockk `CallSessionController`. Steps: dispatch `ToggleMic`,
  `ToggleCamera`, `FlipCamera`, `SetRoute(SPEAKER)`, `EndCall`. Expected: each
  calls the matching controller method exactly once (`verify(exactly=1)`:
  `setMicEnabled`, `setCameraEnabled`, `switchCamera`, `setAudioRoute(SPEAKER)`,
  `endCall`). Traces: AC-1, AC-2, AC-3, AC-4, AC-5.
- **TC-AND-298-03** — Type: unit (JVM). Target: `InCallViewModel` idempotent End.
  Preconditions: connected session. Steps: dispatch `EndCall` twice rapidly.
  Expected: `controller.endCall(...)` invoked exactly once (guarded by
  `endRequested`). Traces: AC-5.
- **TC-AND-298-04** — Type: unit (JVM, table-driven). Target: `CallStatsSampler`
  quality heuristic. Preconditions: synthetic `RTCStatsReport`s + ICE states.
  Steps: feed (rtt=80ms,loss=1%), (rtt=200ms,loss=3%), (rtt=400ms,loss=8%),
  (iceState=DISCONNECTED), (no stats for >6s). Expected: EXCELLENT, GOOD, POOR,
  LOST, LOST respectively; thresholds match `useConnectionQuality.ts`
  (<150ms&<2%, <300ms&<5%). Note: candidate-pair RTT is seconds in the report —
  assert the ms conversion. Traces: AC-6.
- **TC-AND-298-05** — Type: unit (JVM). Target: duration formatter + freeze rule.
  Steps: format 0s, 59s, 60s, 3599s, 3600s, 3661s; then transition to
  `Reconnecting` and back. Expected: `00:00, 00:59, 01:00, 59:59, 1:00:00,
  1:01:01`; display freezes during Reconnecting but the underlying count keeps
  advancing (no reset). Traces: AC-7.
- **TC-AND-298-06** — Type: contract/MockWebServer (JVM). Target: end-call HTTP
  contract. Preconditions: MockWebServer returns 200 `CallActionOut`
  (`{call_id, conversation_id, state:"ended", event_ts, voicemail_eligible:false}`).
  Steps: trigger End; capture the recorded request. Expected: request is
  `POST /messaging/messages/calls/{call_id}/end`, headers include
  `Authorization: Bearer …` and `X-CSRF-Token`, body is `CallEndIn`
  (`reason` string; optional `idempotency_key`); response decodes into the typed
  model and `state` drives the terminal UI (NOT a `status`/`duration_s` field).
  Traces: AC-5.
- **TC-AND-298-07** — Type: contract/MockWebServer (JVM). Target: end-call error +
  decoder. Preconditions: MockWebServer returns 422 `HTTPValidationError`
  (`detail:[{msg:"…"}]`), then a separate run returns 503. Steps: trigger End.
  Expected: `ApiResult` decodes array-of-`{msg}` and object/`code` shapes per
  `normalizeErrorDetail`; **local teardown still proceeds** (media + audio mode
  reset) and a non-blocking toast is shown; no crash. Traces: AC-5.
- **TC-AND-298-08** — Type: integration (JVM, offline/flaky-host). Target: End
  resilience when host unreachable. Preconditions: MockWebServer dispatcher drops
  the connection / `SocketTimeout` (simulating the unreliable
  `18.222.237.167:8000` dev host). Steps: dispatch `EndCall`. Expected: local
  session is torn down and the screen pops regardless of the network failure
  (end is locally authoritative); failure logged at WARN, toast shown, End not
  retried into a stuck spinner. Traces: AC-5.
- **TC-AND-298-09** — Type: Compose-UI (Robolectric, JVM). Target: control states
  & labels. Steps: render `InCallScreen` with various `InCallUiState`s and tap.
  Expected: Mute toggles `contentDescription` "Mute microphone"↔"Unmute
  microphone"; Camera toggles "Turn camera off"↔"Turn camera on" and is disabled
  in audio-only; Flip disabled when `hasMultipleCameras=false` or camera off and
  ignores taps while `flipInFlight=true`; End exposes "End call". Traces: AC-1,
  AC-2, AC-4, AC-9.
- **TC-AND-298-10** — Type: Compose-UI (Robolectric, JVM). Target: quality &
  reconnect affordances + auto-hide. Steps: drive `quality=POOR` then `LOST`
  (Reconnecting), advance the test clock past 4s of inactivity, then tap.
  Expected: POOR shows the "Weak connection" banner; LOST shows the reconnecting
  spinner over the remote surface; controls auto-hide after 4s in video mode and
  reappear on tap; local PiP hidden + placeholder when `cameraEnabled=false`.
  Traces: AC-6, AC-8.
- **TC-AND-298-11** — Type: Compose-UI accessibility (Robolectric, JVM). Target:
  a11y semantics. Steps: assert each control ≥48x48dp, has a state-aware
  `contentDescription`, and quality+duration are one polite live-region with
  throttled duration announcements; verify RTL mirrors the default PiP corner and
  control order. Expected: all assertions pass; lint accessibility check clean.
  Traces: AC-9.
- **TC-AND-298-12** — Type: instrumented/e2e (Device(A15) — **must** run on the
  physical device). Target: real audio-route + mute side effects.
  Preconditions: granted `RECORD_AUDIO`/`CAMERA`; a loopback or live
  `PeerConnection` in `Connected`; real `AudioManager`. Steps: tap Speaker (cycle
  earpiece↔loudspeaker, and with a Bluetooth/wired headset attached confirm route
  reflection), tap Mute, then End. Expected: active route changes and the icon
  reflects it via `setCommunicationDevice`; mute flips the outbound audio track
  `enabled` (peer stops hearing audio); End resets `AudioManager.mode` from
  `MODE_IN_COMMUNICATION`. Rationale for device: OEM audio-routing +
  Bluetooth/wired SCO behavior is not reproducible on the emulator. Traces: AC-1,
  AC-3, AC-5.
- **TC-AND-298-13** — Type: instrumented/e2e (Device(A15) — **must** run on the
  physical device). Target: real camera flip + permission-revocation security
  case. Preconditions: video call connected; both cameras present. Steps: tap
  Flip repeatedly (debounce), then revoke `CAMERA` permission mid-call via
  settings. Expected: front/back switch without dropping the call; rapid taps are
  debounced (single switch in flight); on revocation the screen degrades to
  audio-only and informs the user (no crash, no stuck spinner). Rationale for
  device: real dual-camera hardware + live mid-call permission revocation behavior
  differ from emulator camera emulation. Traces: AC-4, AC-2.
- **TC-AND-298-14** — Type: instrumented (Emu(test35), API 35 vs Device(A15) API
  34). Target: lifecycle/back-press + ABI/API parity. Steps: during an active
  call press system Back; on call end let the terminal state ("Call ended") show
  ~1.5s then pop. Expected: Back does **not** end the call (minimize/PiP per Q2
  default = minimize only); terminal state shows then pops to originator; behavior
  is consistent across API 35 (x86_64) and API 34 (arm64-v8a). Run on both targets
  to catch ABI/API-level differences in the `org.webrtc` native libs. Traces:
  AC-5.

### Coverage matrix (§14 AC → covering TCs)

| AC (§14) | Covered by |
|---|---|
| AC-1 Mute toggles outbound audio + label | TC-01, TC-02, TC-09, TC-12 |
| AC-2 Camera toggle + placeholder; disabled audio-only | TC-01, TC-02, TC-09, TC-13 |
| AC-3 Speaker/route change + icon | TC-02, TC-12 |
| AC-4 Flip camera, debounced, disabled rules | TC-01, TC-02, TC-09, TC-13 |
| AC-5 End once, reset audio mode, pop | TC-02, TC-03, TC-06, TC-07, TC-08, TC-12, TC-14 |
| AC-6 Quality indicator 4 levels + banner/spinner | TC-01, TC-04, TC-10 |
| AC-7 Duration timer start/tick/format/no-reset | TC-01, TC-05 |
| AC-8 Remote full-bleed + draggable corner-snap PiP | TC-10 |
| AC-9 48dp targets + state-aware a11y labels | TC-09, TC-11 |
