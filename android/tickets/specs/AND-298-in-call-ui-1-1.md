---
id: AND-298
title: In-call UI (1:1)
milestone: M7
epic: E40
priority: P0
size: L
status: draft
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
- Web reference: `frontend/src/api/endpoints/calls.ts` for the call/end and
  stats reporting shapes; `frontend/src/api/types.ts` for `CallId`/quality enums.
- Backend FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable);
  OpenAPI at `/openapi.json`. Cookie-based session + `X-CSRF-Token`.

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
media session; the **call create/answer/end/ICE signaling endpoints are owned by
AND-296** (`POST /ui/calls/start`, `/ui/calls/{id}/answer`,
`/ui/calls/{id}/ice`, `/ui/calls/{id}/end`). Two contract touch-points are
relevant here:

**End call** — triggered by the End control; the request is issued by the
controller, but this screen guarantees it fires exactly once:
```
POST /ui/calls/{callId}/end
Headers: Cookie: <session>; X-CSRF-Token: <ui_csrf>
Body: { "reason": "hangup" }   // hangup | declined | timeout
200 → { "call_id": "c_…", "status": "ended", "duration_s": 137 }
```

**Optional quality/QoS report** (best-effort, fire-and-forget on call end if the
endpoint exists per `/openapi.json`; skip if absent):
```
POST /ui/calls/{callId}/stats
Body: { "rtt_ms_avg": 84, "packet_loss_pct": 1.2, "duration_s": 137,
        "quality_terminal": "good" }
200 → { "ok": true }
```
Error `detail` mapping follows the project convention (string |
`[{msg}]` | `{code,...}`) via the shared `ApiResult<T>` error decoder. Stats
reporting failures are swallowed (logged only); end-call failures still tear down
the local session and surface a non-blocking toast.

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
- Session/CSRF: the End and stats requests reuse the persistent cookie jar +
  `X-CSRF-Token`; on 401 the OkHttp authenticator performs the single
  `POST /ui/session/refresh` + retry per project policy.
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
- **Q1 — Does `/ui/calls/{id}/stats` exist?** Confirm against `/openapi.json`; if
  absent, drop the §5 QoS report (it is best-effort).
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
