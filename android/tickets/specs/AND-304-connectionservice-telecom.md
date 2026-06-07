---
id: AND-304
title: ConnectionService / Telecom
milestone: M7
epic: E40
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-297]
blocks: []
---

# AND-304 — ConnectionService / Telecom

## 1. Overview & Goal

Integrate TestLogon's in-app calling with the Android Telecom framework so that
audio/video calls participate in the device's system call experience. Today
(post AND-297) an incoming call invite is delivered via FCM and surfaced through
a self-managed full-screen notification, while audio routing is handled ad hoc.
This ticket replaces the ad-hoc plumbing with a **self-managed `ConnectionService`**
that registers a `PhoneAccount`, creates `Connection` objects for each call, and
delegates audio focus, audio device routing (earpiece/speaker/Bluetooth/wired
headset), call-state reporting, and interaction with native phone calls (hold on
cellular call, etc.) to the OS.

The goal is that a TestLogon call behaves like a first-class call on the device:
it shows up in the system call UI where the OEM supports it, mutes/holds when a
cellular call arrives, follows the hardware "end call" / headset hook button,
and routes audio through the correct device. The acceptance bar is deliberately
scoped: **"Calls integrate with system telecom (where supported)."** Self-managed
ConnectionService is API 26+ (`O`), so on our `minSdk 24` floor and on OEMs with
broken Telecom implementations we must degrade gracefully to the AND-297
notification-driven path. This is a *Feature* (P1) ticket living in module
`feature-call` with supporting types in `core-call` (audio routing) and
`core-model`.

## 2. Context & References

- **Depends on AND-297** (Incoming call — push + full-screen): provides the FCM
  call-invite parsing, the `CallInvite` model, the full-screen ringing UI, and
  accept/decline/timeout flows. AND-304 inserts the Telecom layer underneath
  those flows: AND-297's accept/decline actions become `Connection` callbacks.
- **Package base:** `com.testlogon.android`. Telecom code lives in
  `com.testlogon.android.feature.call.telecom` and
  `com.testlogon.android.core.call.audio`.
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Media3/ExoPlayer 1.4
  (the media transport for HLS/RTP-over-app is owned elsewhere; this ticket owns
  only signalling state and audio routing, not the media pipeline). minSdk 24,
  compileSdk/targetSdk 35, JDK 17.
- **Android docs:** `android.telecom.ConnectionService`, `Connection`,
  `PhoneAccount`/`PhoneAccountHandle`, `TelecomManager`,
  `CallAudioState`/`CallEndpoint` (API 34+), `AudioManager` focus APIs.
- **Backend:** Call signalling (accept/decline/hangup) reuses the existing call
  REST/WS layer established with AND-297; no new FastAPI endpoints are introduced
  by this ticket (see §5). Backend host
  `http://18.222.237.167:8000` (plaintext, unreliable dev host).
- **Web reference:** WebRTC-based; the web app has no Telecom analogue, so there
  is no `frontend/` parity reference for this ticket — Telecom is an
  Android-platform concern only.

## 3. Functional Requirements

FR-1. On app start (and on first call if registration was deferred), register a
self-managed `PhoneAccount` with `CAPABILITY_SELF_MANAGED` under a stable
`PhoneAccountHandle` keyed to `TestLogonConnectionService`.

FR-2. **Outgoing call:** when the user starts a call, place it through
`TelecomManager.placeCall(uri, extras)` (or `addNewOutgoingCall`), causing the OS
to invoke `onCreateOutgoingConnection`, which returns a `TestLogonConnection` in
`STATE_DIALING`, transitioning to `STATE_ACTIVE` when the peer answers.

FR-3. **Incoming call:** when AND-297 receives an FCM invite, the call layer
calls `TelecomManager.addNewIncomingCall(handle, extras)`; the OS invokes
`onCreateIncomingConnection`, returning a `TestLogonConnection` in
`STATE_RINGING`. The connection drives (or, on unsupported devices, defers to)
the AND-297 full-screen UI.

FR-4. **Accept / reject:** `Connection.onAnswer()` and `onReject()`/`onDisconnect()`
are the single source of truth for call disposition; the AND-297 UI buttons and
the system call UI both route through these callbacks.

FR-5. **Audio focus & routing:** while a call is `ACTIVE`, hold transient-exclusive
audio focus and reflect the selected route (earpiece / speaker / Bluetooth SCO /
wired headset) via `CallAudioState`/`setAudioRoute`/`requestCallEndpointChange`.
Expose the current route and available routes to the in-call UI as a `StateFlow`.

FR-6. **Interop with cellular calls:** when a GSM/CS call becomes active, the OS
issues `onHold()`; TestLogon must mute/pause its media and report `STATE_HOLDING`,
then resume on `onUnhold()`.

FR-7. **Hardware controls:** respond to the headset hook / `onCallAudioStateChanged`
(mute toggle) and to system end-call. `Connection.onAbort()`/`onDisconnect()` must
tear down the media session and clear the FCM/notification state.

FR-8. **Graceful degradation:** on API < 26, or when self-managed registration
throws / `TelecomManager` is unavailable / OEM rejects `placeCall`, fall back to
the AND-297 notification path with no Telecom involvement. The user-facing call
flow must remain fully functional in fallback mode.

FR-9. **Lifecycle correctness:** exactly one active `TestLogonConnection` per
call id; ending, network loss, or process death must not leak a stuck Telecom
call (the OS would otherwise show a phantom ongoing call).

## 4. Technical Design

New module surface in `feature-call` and `core-call`:

```kotlin
// core-call/.../audio/CallAudioRoute.kt
enum class CallAudioRoute { EARPIECE, SPEAKER, BLUETOOTH, WIRED_HEADSET }

data class CallAudioStateUi(
    val active: CallAudioRoute,
    val available: Set<CallAudioRoute>,
    val muted: Boolean,
)

// feature-call/.../telecom/TelecomCallController.kt
@Singleton
class TelecomCallController @Inject constructor(
    @ApplicationContext private val context: Context,
    private val telecomManager: TelecomManager,        // provided by Hilt
    private val capabilities: TelecomCapabilities,
) {
    /** True only when self-managed Telecom is usable on this device. */
    fun isTelecomSupported(): Boolean

    /** Idempotent; safe to call repeatedly. No-op if unsupported. */
    fun ensurePhoneAccountRegistered()

    fun phoneAccountHandle(): PhoneAccountHandle

    /** @return false if the OS refused; caller must use AND-297 fallback. */
    fun placeOutgoing(callId: String, displayName: String, video: Boolean): Boolean
    fun reportIncoming(callId: String, invite: CallInvite): Boolean
}
```

```kotlin
// feature-call/.../telecom/TestLogonConnectionService.kt
@AndroidEntryPoint
class TestLogonConnectionService : ConnectionService() {
    @Inject lateinit var registry: ConnectionRegistry   // call-id -> Connection
    @Inject lateinit var callSignaling: CallSignaling    // accept/decline/hangup
    @Inject lateinit var audioRouter: CallAudioRouter

    override fun onCreateIncomingConnection(
        handle: PhoneAccountHandle?, req: ConnectionRequest?
    ): Connection
    override fun onCreateOutgoingConnection(
        handle: PhoneAccountHandle?, req: ConnectionRequest?
    ): Connection
    override fun onCreateIncomingConnectionFailed(/* ... */) { /* fallback */ }
}

// feature-call/.../telecom/TestLogonConnection.kt
class TestLogonConnection(
    private val callId: String,
    private val signaling: CallSignaling,
    private val audioRouter: CallAudioRouter,
    private val scope: CoroutineScope,
) : Connection() {
    override fun onAnswer() { setActive(); signaling.accept(callId) }
    override fun onReject() { signaling.decline(callId); destroyWith(DisconnectCause(REJECTED)) }
    override fun onDisconnect() { signaling.hangup(callId); destroyWith(DisconnectCause(LOCAL)) }
    override fun onHold() { setOnHold(); audioRouter.pause() }
    override fun onUnhold() { setActive(); audioRouter.resume() }
    override fun onAbort() { destroyWith(DisconnectCause(CANCELED)) }
    override fun onCallAudioStateChanged(state: CallAudioState) { audioRouter.onSystemAudioState(state) }
    override fun onStateChanged(state: Int) { /* mirror into UiState */ }
}
```

`AndroidManifest.xml` (feature-call) registers the service:

```xml
<service
    android:name=".telecom.TestLogonConnectionService"
    android:permission="android.permission.BIND_TELECOM_CONNECTION_SERVICE"
    android:exported="true">
    <intent-filter>
        <action android:name="android.telecom.ConnectionService" />
    </intent-filter>
</service>
```

`PhoneAccount` is built with `CAPABILITY_SELF_MANAGED`,
`CAPABILITY_VIDEO_CALLING` when applicable, an app icon and the address scheme
`testlogon` (custom `tel`-like `Uri.fromParts("testlogon", callId, null)`).

`CallAudioRouter` (in `core-call`) wraps `AudioManager` focus
(`AudioFocusRequest` with `AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE`,
`USAGE_VOICE_COMMUNICATION`) and translates between `CallAudioState`/`CallEndpoint`
and `CallAudioStateUi`. On API 34+ it prefers `CallEndpoint`/
`requestCallEndpointChange`; on 26–33 it uses
`setAudioRoute(int)`/`onCallAudioStateChanged`.

`TelecomCapabilities` performs the support probe:
`Build.VERSION.SDK_INT >= 26 && telecomManager != null && account registration
succeeds` and caches the result (DataStore boolean, see §6) so a one-time OEM
failure isn't re-probed every call.

Connection lifecycle is bridged to the existing `CallViewModel` (AND-297):
`registry` maps `callId -> TestLogonConnection`; signalling events from the WS
layer (peer answered / peer hung up) call `connection.setActive()` /
`connection.setDisconnected(...)` so the OS state always tracks real call state.

## 5. API Contract

No new backend HTTP endpoints. Telecom is a device-local framework; call
signalling (accept/decline/hangup, peer state) is owned by AND-297's existing
call signalling layer (WS + the call REST routes). For reference, the disposition
actions this ticket triggers map to existing call-disposition endpoints. **Corrected
against OpenAPI (the earlier draft used `/calls/{call_id}/...` and a `hangup`
verb, both of which do not exist):**

```
POST /messaging/messages/calls/{call_id}/accept    req=CallAcceptIn  resp=200:CallActionOut
POST /messaging/messages/calls/{call_id}/decline   req=CallDeclineIn resp=200:CallActionOut
POST /messaging/messages/calls/{call_id}/end       req=CallEndIn     resp=200:CallActionOut
```

Notes verified against the sources:
- The disposition verb is **`/end`**, not `hangup`. There is no `/hangup`
  endpoint anywhere in the OpenAPI index.
- The web reference app calls these via the shorter `/messages/calls/{id}/...`
  prefix (`src/api/endpoints/messaging.ts: acceptCallInvite/declineCallInvite/
  endCall`); the canonical server paths in the OpenAPI index are
  `/messaging/messages/calls/{id}/...`. Use the canonical OpenAPI paths for the
  Android Retrofit client; the difference is a frontend base-path artifact.
- Request bodies are small/optional: `CallAcceptIn { idempotency_key? }`,
  `CallDeclineIn { reason="declined" }`, `CallEndIn { reason="ended",
  idempotency_key? }`. All three return `CallActionOut { call_id,
  conversation_id, state, event_ts, from_state?, reason?, voicemail_eligible }`.
- WebRTC media signalling (offer/answer/ICE) is a separate endpoint,
  `POST /messaging/messages/calls/{call_id}/signal` (req=CallSignalingIn,
  resp=200:CallSignalingOut), which returns typed `CallSignalingErrorOut
  { code, message }` on 400/403/404/409/429/503. This ticket does not call
  `/signal` directly — it consumes the `CallSignaling` abstraction — but the
  real error shape is noted here for the test plan.

These ride the **authenticated session** (§8): `Authorization: Bearer
<accessToken>` **plus** the `ui_csrf` cookie echoed as `X-CSRF-Token`, with
cookies sent (`credentials: include`). On 401 the shared OkHttp authenticator
performs the single `POST /ui/session/refresh` (no body) then retries once
(idempotency: these POSTs are *not* auto-retried on transient network errors —
only the refresh-once rule applies). This ticket consumes the `CallSignaling`
interface, not raw Retrofit:

```kotlin
interface CallSignaling {
    fun accept(callId: String)
    fun decline(callId: String)
    fun hangup(callId: String)
    fun observe(callId: String): Flow<CallSignalState>   // ANSWERED, REMOTE_HANGUP, ...
}
```

The Telecom→signalling and signalling→Telecom mappings:

| Telecom callback        | Signalling action                |
|-------------------------|----------------------------------|
| `onAnswer()`            | `accept(callId)`                 |
| `onReject()`            | `decline(callId)`                |
| `onDisconnect()`        | `hangup(callId)` → `POST .../end` |
| `CallSignalState.ANSWERED`   | `connection.setActive()`    |
| `CallSignalState.REMOTE_HANGUP` | `connection.setDisconnected(REMOTE)` |

## 6. Data & State Management

- `CallViewModel.uiState: StateFlow<CallUiState>` (from AND-297) gains an
  `audio: CallAudioStateUi` field and a `telecomManaged: Boolean` flag.
- `CallAudioRouter.audioState: StateFlow<CallAudioStateUi>` is the canonical
  route/mute source; the in-call screen collects it and renders the
  earpiece/speaker/BT/headset selector and mute button.
- Telecom support probe result persisted in **DataStore** (`prefs/call.preferences_pb`)
  key `telecom_supported: Boolean?` (null = not yet probed). Re-probed on app
  version change.
- No Room rows are introduced; Telecom connections are ephemeral process state
  held in `ConnectionRegistry` (an in-memory `ConcurrentHashMap<String, TestLogonConnection>`),
  scoped `@Singleton` via Hilt.
- State machine for a connection mirrors `Connection` states: `NEW → DIALING|RINGING
  → ACTIVE ⇄ HOLDING → DISCONNECTED`. The registry removes the entry on
  `DISCONNECTED` and `destroy()`.

## 7. Error Handling & Resilience

- **Unsupported / refused Telecom:** `placeOutgoing`/`reportIncoming` return
  `false` and `onCreateIncomingConnectionFailed`/`onCreateOutgoingConnectionFailed`
  trigger the AND-297 fallback path (full-screen notification + manual audio
  focus). This must be transparent to the user.
- **Registration failure:** `ensurePhoneAccountRegistered()` wraps
  `registerPhoneAccount` in try/catch (`SecurityException`, OEM
  `IllegalArgumentException`); on failure caches `telecom_supported=false`.
- **Audio focus loss** (`AUDIOFOCUS_LOSS`): end media gracefully and reflect via
  `setOnHold()` if transient, or disconnect if permanent; never leave a silent
  zombie call.
- **Stuck connections:** a watchdog disconnects any `TestLogonConnection` that
  has been non-terminal for > 60s without matching live signalling state
  (`CallSignaling.observe` completed/closed), preventing OS phantom calls.
- **Process death:** the foreground call service (AND-297) restart re-syncs the
  registry; orphan Telecom connections are disconnected with
  `DisconnectCause(ERROR)` on next service create.
- **Backend unreliability:** decline/hangup signalling failures (timeout on the
  20s dev-host budget) must NOT block local teardown — the local `Connection` is
  disconnected immediately and the signalling POST is fire-and-forget with a
  single best-effort retry; the OS call UI never hangs on a flaky network.

## 8. Security & Privacy

- The `ConnectionService` is exported (required by the framework) but protected
  by the system permission `BIND_TELECOM_CONNECTION_SERVICE`, so only the OS may
  bind it. No app-defined permission is needed and no IPC surface is exposed.
- Self-managed PhoneAccount requires no `MANAGE_OWN_CALLS` runtime grant beyond
  the manifest `<uses-permission android:name="android.permission.MANAGE_OWN_CALLS"/>`;
  no READ/CALL_PHONE or default-dialer privileges are requested.
- Bluetooth SCO routing on API 31+ requires `BLUETOOTH_CONNECT` (runtime). If the
  user denies it, BT is silently dropped from `available` routes; the call
  continues on earpiece/speaker.
- Call signalling continues to ride the **authenticated session**: an
  `Authorization: Bearer <accessToken>` header **and** a persistent cookie jar
  with `ui_csrf`→`X-CSRF-Token` echo (verified in `src/api/client.ts`; the
  earlier draft mentioned only the cookie/CSRF half and omitted the Bearer
  header). No credentials or tokens are
  placed into Telecom `extras`/`Uri` (which can be logged by the OS). Only the
  opaque `callId` and a display name appear in Telecom extras.
- No call content, peer identifiers, or audio is persisted by this ticket.

## 9. Accessibility & i18n

The Telecom-managed system call UI is owned and localized by the OS, so it is
inherently accessible (TalkBack, large-text, hardware controls). For the in-app
fallback in-call screen this ticket touches only the audio-route selector and
mute control:

- All route buttons (Earpiece/Speaker/Bluetooth/Headset) and the mute toggle
  expose `contentDescription` and `Role.Button`/`Role.Switch` with selected
  state announced (e.g. "Speaker, selected").
- Strings (`Earpiece`, `Speaker`, `Bluetooth`, `Wired headset`, `Mute`,
  `Unmute`, and the BT-permission rationale) are added to
  `core-ui`/`feature-call` `strings.xml` with no hardcoded literals; RTL-safe.
- Audio-route changes are announced via a live region so blind users learn the
  active device after toggling.

## 10. Telemetry & Logging

- Structured events (existing analytics façade, no PII): `telecom_supported`
  (bool, device/OEM, api), `telecom_register_failed` (reason), `telecom_place_refused`,
  `call_connection_state` (callId hash, from→to), `audio_route_changed`
  (route, source=user|system), `telecom_fallback_used`.
- Logs use the app's Timber tree at `DEBUG` for state transitions and `WARN` for
  fallback/refusal; **never** log cookies, CSRF token, raw `callId`, or peer
  identity. `callId` is hashed before logging.
- A debug-only overlay (behind `BuildConfig.DEBUG`) shows current Connection
  state, audio route, and support flag for field diagnosis of OEM Telecom bugs.

## 11. Testing Strategy

- **Unit (JVM, `core-testing`):** `TelecomCapabilities` probe logic (SDK gating,
  cached value, version-change re-probe); `CallAudioRouter` mapping of
  `CallAudioState`/`CallEndpoint` ⇄ `CallAudioStateUi`; `TestLogonConnection`
  callback→signalling mapping with a fake `CallSignaling`; watchdog timeout.
- **Robolectric:** `TestLogonConnectionService.onCreateIncoming/Outgoing*` returns
  a connection with correct initial state; `onCreateIncomingConnectionFailed`
  triggers fallback. Use Robolectric shadows for `TelecomManager`/`AudioManager`.
- **Instrumented (connectedAndroidTest, API 26/30/34 emulators):** register the
  PhoneAccount, place a self-managed outgoing call via `TelecomManager.placeCall`,
  assert the OS reports it (via `InCallService` test double or `dumpsys telecom`),
  exercise `onHold` by simulating a second call, and verify audio route changes.
- **Manual matrix:** Pixel (clean Telecom), Samsung One UI, and one OEM with
  known partial Telecom support, plus a wired headset and a Bluetooth headset,
  verifying hardware end-call/hook and cellular-call interop.
- **Acceptance test:** automated check that on a supported emulator a call
  appears in system telecom and connects on accept; on a simulated-unsupported
  build the AND-297 fallback path still completes a call (proves "where supported").

## 12. Dependencies & Sequencing

- **Hard dependency: AND-297** must be merged — its `CallInvite`, full-screen
  ringing UI, foreground call service, and `CallSignaling` are consumed directly.
  AND-304 wires Telecom *underneath* AND-297's accept/decline/timeout flows.
- Transitively relies on AND-297's deps (AND-296 FCM, AND-108) being in place;
  no new dependency is added by this ticket.
- **Blocks:** nothing currently in scope (no downstream ticket lists AND-304 as a
  dependency); it is an enhancement layer on top of the working call flow.
- **Sequencing within ticket:** (1) PhoneAccount + capability probe + manifest;
  (2) ConnectionService/Connection skeleton + registry; (3) audio router +
  StateFlow into in-call UI; (4) hold/interop + hardware controls; (5) fallback
  hardening + watchdog; (6) telemetry + tests.

## 13. Risks & Open Questions

- **OEM Telecom fragmentation:** several OEMs silently break self-managed
  ConnectionService (calls don't appear, `placeCall` throws, audio routing
  ignored). Mitigation: the capability probe + per-device fallback; treat
  "where supported" literally and gate by a remote-config OEM denylist if needed.
- **API 24/25 floor vs. API 26 Telecom:** ~minimal user base below 26 but must
  not crash — covered by fallback. *Open:* confirm minSdk-24 user share to size
  fallback investment.
- **CallEndpoint (API 34) vs. legacy CallAudioState:** dual code paths add
  complexity; risk of route desync. Mitigation: single `CallAudioRouter`
  abstraction, tested on both.
- **Open question:** should outgoing calls also be placed through Telecom on
  unsupported OEMs (some accept incoming but refuse outgoing self-managed)? Lean
  toward independent per-direction probing.
- **Open question:** interaction with Media3/ExoPlayer audio attributes for the
  media transport — confirm whether the media owner releases focus to let
  `CallAudioRouter` own `USAGE_VOICE_COMMUNICATION` focus exclusively.

## 14. Acceptance Criteria

AC-1. On an API 26+ device with working Telecom, an incoming TestLogon call is
registered via `addNewIncomingCall`, rings even when backgrounded (inherited from
AND-297), and on accept the call connects and appears in the system call UI.

AC-2. An outgoing call placed via `TelecomManager.placeCall` produces a
`TestLogonConnection` that transitions `DIALING → ACTIVE` on peer answer.

AC-3. Accept/decline/hangup from both the system call UI and the in-app UI route
through `Connection.onAnswer/onReject/onDisconnect` and reach the backend
signalling.

AC-4. Audio routes correctly across earpiece, speaker, wired headset, and
Bluetooth, and the active/available routes + mute state are reflected in the
in-call UI; the headset hook button toggles as expected.

AC-5. When a cellular call arrives, the TestLogon call is put on hold (`onHold`),
media pauses, and resumes on `onUnhold`.

AC-6. On API < 26 or an unsupported/refusing device, the app falls back to the
AND-297 notification path and a call can still be received, accepted, and
conducted with correct audio focus — with no crash and no phantom OS call.

AC-7. No Telecom connection is leaked: ending a call (locally, remotely, on
error, or after process death) results in `DISCONNECTED` and registry removal,
verified by the watchdog and by `dumpsys telecom` showing no lingering call.

AC-8. No cookies, CSRF token, or raw `callId` appear in logs or Telecom extras.

## 15. Definition of Done

- All FRs (§3) and ACs (§14) implemented and verified on the API 26/30/34
  emulator matrix plus the manual device/headset matrix (§11).
- `feature-call` ConnectionService, `TestLogonConnection`, `TelecomCallController`,
  `TelecomCapabilities`, and `core-call` `CallAudioRouter` merged behind the
  capability probe with the AND-297 fallback fully functional.
- Manifest service + `MANAGE_OWN_CALLS` (and conditional `BLUETOOTH_CONNECT`)
  declared; PhoneAccount registers idempotently.
- Unit + Robolectric + instrumented tests green in CI; new strings localized and
  accessibility checks pass.
- Telemetry events emit with no PII; debug overlay present only in debug builds.
- Code review approved; merged to `android-port`; no regressions in the AND-297
  call flow; risks/open questions in §13 either resolved or logged as follow-ups.

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and an exact source pointer.

1. **Disposition endpoints are `POST /calls/{call_id}/accept|decline|hangup`.**
   VERDICT: **Corrected.** No `/calls/...` path and no `hangup` verb exist. The
   real endpoints are `POST /messaging/messages/calls/{call_id}/accept`,
   `/decline`, and `/end`. SOURCE: OpenAPI index lines for
   `POST /messaging/messages/calls/{call_id}/accept`,
   `POST /messaging/messages/calls/{call_id}/decline`,
   `POST /messaging/messages/calls/{call_id}/end`; frontend
   `src/api/endpoints/messaging.ts: acceptCallInvite / declineCallInvite /
   endCall` (which call them under the `/messages/calls/...` base prefix).

2. **The disposition endpoints return `CallActionOut`.**
   VERDICT: Verified. SOURCE: OpenAPI `POST /messaging/messages/calls/{call_id}/accept`
   `resp=200:CallActionOut` (same for decline/end); schema
   `components.schemas.CallActionOut { call_id, conversation_id, state,
   event_ts, from_state?, reason?, voicemail_eligible }`.

3. **Request bodies for accept/decline/end.**
   VERDICT: Verified. SOURCE: schemas `CallAcceptIn { idempotency_key? }`,
   `CallDeclineIn { reason="declined" }`, `CallEndIn { reason="ended",
   idempotency_key? }` (openapi.pretty.json components.schemas).

4. **Auth = cookie-based session with `ui_csrf`→`X-CSRF-Token`.**
   VERDICT: **Corrected (incomplete).** The CSRF/cookie half is right, but the
   client ALSO sends `Authorization: Bearer <accessToken>` and uses
   `credentials: include`. SOURCE: `src/api/client.ts` (`headers.set
   ("Authorization", "Bearer …")`, `getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", …)`, `credentials: "include"`).

5. **On 401, refresh once via `POST /ui/session/refresh`, then retry.**
   VERDICT: Verified. SOURCE: `src/api/client.ts` `refreshSession()` →
   `POST /ui/session/refresh` (no body), single in-flight `refreshPromise`,
   one retry of the original request; OpenAPI index
   `POST /ui/session/refresh | req= | resp=200`.

6. **No new backend HTTP endpoints are introduced by this ticket.**
   VERDICT: Verified. SOURCE: all consumed paths
   (`/messaging/messages/calls/{call_id}/accept|decline|end|signal`,
   `/ui/session/refresh`) already exist in openapi.index.txt; Telecom is
   device-local.

7. **WebRTC media signalling rides a `/signal` endpoint with a typed error
   shape.** VERDICT: Verified. SOURCE: OpenAPI
   `POST /messaging/messages/calls/{call_id}/signal | req=CallSignalingIn |
   resp=200:CallSignalingOut; 400/403/404/409/429/503:CallSignalingErrorOut`;
   `CallSignalingErrorOut { code, message }`; `CallSignalingIn` `type` is a
   regex over `webrtc.offer|webrtc.answer|webrtc.ice_candidate|
   webrtc.screen_share_start|webrtc.screen_share_stop`.

8. **`CallInvite` model, full-screen ringing UI, and `CallSignaling` come from
   AND-297.** VERDICT: Unverified-assumption (cross-ticket dependency). AND-297
   is not in the provided sources; an `CallInviteIn/CallInviteOut` schema and a
   `POST /messaging/messages/calls/invite` endpoint do exist in the OpenAPI
   index, which is consistent with the dependency. SOURCE: OpenAPI
   `POST /messaging/messages/calls/invite | req=CallInviteIn |
   resp=200:CallInviteOut`; AND-297 spec not provided.

9. **The `CallSignalState` enum (`ANSWERED`, `REMOTE_HANGUP`) used in §5.**
   VERDICT: Unverified-assumption. This is an Android-internal abstraction over
   WS/signalling, not a backend schema; no such enum exists in the OpenAPI
   spec. SOURCE: none (Android-side type defined by AND-297/this ticket).

10. **The web app has no Telecom analogue / Telecom is Android-only.**
    VERDICT: Verified. SOURCE: no Telecom/ConnectionService/PhoneAccount
    references anywhere in `reference/src/`; the web call path is WebRTC-based
    (`src/hooks/useRtcPeerConnection.ts`, `src/pages/messages/...`).

11. **Self-managed `ConnectionService` requires API 26+ (`O`).**
    VERDICT: Verified (framework ref). `PhoneAccount.CAPABILITY_SELF_MANAGED`
    and self-managed ConnectionService were added in API 26. SOURCE: framework
    ref — developer.android.com/reference/android/telecom/PhoneAccount
    (CAPABILITY_SELF_MANAGED, added in API level 26).

12. **`CallEndpoint` / `requestCallEndpointChange` is API 34+.**
    VERDICT: Verified (framework ref). SOURCE: framework ref —
    developer.android.com/reference/android/telecom/CallEndpoint (added in API
    level 34); `Connection.requestCallEndpointChange` added in API 34.

13. **The exported service is protected by
    `BIND_TELECOM_CONNECTION_SERVICE`.** VERDICT: Verified (framework ref).
    SOURCE: framework ref —
    developer.android.com/reference/android/telecom/ConnectionService
    (service must require permission BIND_TELECOM_CONNECTION_SERVICE and declare
    the `android.telecom.ConnectionService` intent-filter).

14. **`MANAGE_OWN_CALLS` is required for self-managed calls; BT SCO on API 31+
    needs runtime `BLUETOOTH_CONNECT`.** VERDICT: Verified (framework ref).
    SOURCE: framework ref — developer.android.com/reference/android/telecom/
    TelecomManager (`addNewIncomingCall`/`placeCall` for self-managed require
    `MANAGE_OWN_CALLS`); developer.android.com/.../Manifest.permission
    (BLUETOOTH_CONNECT, runtime, API 31+).

15. **Backend dev host `http://18.222.237.167:8000` (plaintext, unreliable).**
    VERDICT: Unverified-assumption. Host/port is environment config, not
    derivable from the OpenAPI/frontend sources (frontend uses
    `VITE_API_BASE_URL`). SOURCE: `src/api/client.ts: API_BASE_URL` (env-driven,
    value not in repo); treat the literal IP as deployment config.

### Corrections made

- **§5 endpoint paths:** replaced the nonexistent `POST /calls/{call_id}/accept|
  decline|hangup` with the real `POST /messaging/messages/calls/{call_id}/
  accept|decline|end`, added request schemas (`CallAcceptIn`/`CallDeclineIn`/
  `CallEndIn`) and the `CallActionOut` response, and documented the
  frontend `/messages/...` base-prefix difference. (claim 1, 2, 3)
- **§5 verb `hangup` → `end`:** the disposition verb is `/end`; updated the
  prose and the Telecom→signalling mapping table row. (claim 1)
- **§5 + §8 auth model:** added the omitted `Authorization: Bearer
  <accessToken>` header (the draft cited only the cookie/CSRF half). (claim 4)
- **§5:** noted the real `/signal` endpoint and its `CallSignalingErrorOut
  { code, message }` error shape for use in the test plan. (claim 7)

### Open assumptions

- **AND-297 surface (`CallInvite`, full-screen UI, `CallSignaling`,
  foreground call service):** not in the provided sources; assumed correct per
  the cross-ticket dependency. Consistent with the existing
  `/messaging/messages/calls/invite` + `CallInviteIn/Out` schemas. (claim 8)
- **`CallSignalState` enum (`ANSWERED`/`REMOTE_HANGUP`):** an Android-side
  abstraction over the WS/signalling layer, not a backend schema; cannot be
  verified against OpenAPI. (claim 9)
- **Dev host IP/port and HTTPS-vs-plaintext:** deployment/env config; the
  frontend derives its base URL from `VITE_API_BASE_URL`, so the literal value
  is not verifiable here. (claim 15)
- **OEM Telecom fragmentation behavior** (which OEMs silently break
  self-managed ConnectionService): empirical/per-device; not derivable from any
  source — must be established by the §11 manual device matrix.

## 17. Test Plan

Test IDs `TC-AND-304-NN`. "Traces" links to §14 acceptance criteria. Targets:
JVM/Robolectric (local, no device), emulator AVD `test35` (x86_64, API 35), and
the physical **Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 /
API 34, arm64-v8a)**. Hardware-dependent cases (real Bluetooth/wired headset,
hardware end-call/hook button, real cellular interop, real-network flakiness)
MUST run on the physical device; framework/state logic runs on JVM/Robolectric;
ABI/API-34-vs-35 differences are checked on both the emulator and the device.

**TC-AND-304-01 — Capability probe gating & caching**
- Type: unit (JVM/Robolectric).
- Target: `TelecomCapabilities`.
- Preconditions: fake `Build.VERSION.SDK_INT`, fake `TelecomManager`, DataStore
  in-memory.
- Steps: probe at SDK 25, 26, 35; force a registration `SecurityException`;
  re-probe after a simulated app-version bump.
- Expected: SDK<26 → unsupported without touching TelecomManager; SDK≥26 with
  successful registration → supported and cached `telecom_supported=true`;
  registration exception → cached `false`; version bump → re-probe occurs.
- Traces: AC-6.

**TC-AND-304-02 — Connection callback → signalling mapping**
- Type: unit (JVM).
- Target: `TestLogonConnection` with a fake `CallSignaling`.
- Preconditions: connection in `RINGING`/`ACTIVE`.
- Steps: invoke `onAnswer()`, `onReject()`, `onDisconnect()`, `onHold()`,
  `onUnhold()`, `onAbort()`.
- Expected: `onAnswer`→`setActive()`+`accept(callId)`; `onReject`→
  `decline(callId)`+`DisconnectCause(REJECTED)`; `onDisconnect`→`hangup(callId)`
  which maps to the **`POST .../end`** disposition + `DisconnectCause(LOCAL)`;
  `onHold`→`setOnHold()`+`audioRouter.pause()`; `onUnhold`→`setActive()`+
  `resume()`; `onAbort`→`DisconnectCause(CANCELED)`.
- Traces: AC-3, AC-5.

**TC-AND-304-03 — Audio route/mute mapping (CallAudioState ⇄ CallAudioStateUi)**
- Type: unit (JVM/Robolectric).
- Target: `CallAudioRouter`.
- Preconditions: fake `CallAudioState` (legacy, API 26–33) and `CallEndpoint`
  set (API 34+).
- Steps: feed earpiece/speaker/BT/wired states and mute toggles through both the
  legacy `onCallAudioStateChanged` path and the API-34 `CallEndpoint` path.
- Expected: `CallAudioRouter.audioState` StateFlow emits the correct `active`
  route, `available` set, and `muted` flag for both code paths; no route desync
  between the two paths.
- Traces: AC-4.

**TC-AND-304-04 — Disposition contract (accept/decline/end) shapes**
- Type: contract / MockWebServer.
- Target: Retrofit call layer behind `CallSignaling`.
- Preconditions: MockWebServer scripting the three endpoints.
- Steps: trigger accept/decline/hangup; capture outbound requests; return
  `200:CallActionOut`.
- Expected: requests go to `POST /messaging/messages/calls/{id}/accept` (body
  `CallAcceptIn`), `/decline` (`CallDeclineIn { reason }`), and **`/end`**
  (`CallEndIn`) — NOT `/hangup`; each carries `Authorization: Bearer …` and
  `X-CSRF-Token` headers; responses deserialize to `CallActionOut` with
  `call_id, conversation_id, state, event_ts`.
- Traces: AC-3, AC-8.

**TC-AND-304-05 — 401 refresh-once then retry**
- Type: contract / MockWebServer.
- Target: OkHttp authenticator + `CallSignaling`.
- Preconditions: MockWebServer returns 401 on first disposition call, 200 on
  retry; `/ui/session/refresh` returns 200.
- Steps: invoke a disposition action.
- Expected: exactly one `POST /ui/session/refresh` (no body) is issued, then the
  original request is retried once and succeeds; a second consecutive 401 does
  not loop (surfaces as auth failure, local teardown still proceeds per §7).
- Traces: AC-3, AC-6.

**TC-AND-304-06 — Signalling error shape handling**
- Type: contract / MockWebServer.
- Target: signalling error mapping.
- Preconditions: MockWebServer returns 409 and 503 with body
  `CallSignalingErrorOut { code, message }` on the `/signal` (and disposition)
  path.
- Steps: drive a signalling action that fails.
- Expected: the typed `{ code, message }` error is parsed (not treated as raw
  text); per §7 a decline/hangup failure does NOT block local `Connection`
  teardown.
- Traces: AC-7.

**TC-AND-304-07 — ConnectionService create returns correct initial state +
fallback on create-failed**
- Type: Robolectric.
- Target: `TestLogonConnectionService`.
- Preconditions: Robolectric shadows for `TelecomManager`/`AudioManager`.
- Steps: call `onCreateIncomingConnection` and `onCreateOutgoingConnection`;
  then invoke `onCreateIncomingConnectionFailed`/`onCreateOutgoingConnectionFailed`.
- Expected: incoming → `STATE_RINGING`, outgoing → `STATE_DIALING`, registered
  in `ConnectionRegistry` keyed by callId (exactly one per id); the failed
  callbacks trigger the AND-297 fallback path and leave no registry entry.
- Traces: AC-1, AC-2, AC-6, AC-9-equivalent (no leak).

**TC-AND-304-08 — Watchdog / no leaked Telecom connection**
- Type: unit (JVM, virtual time) + Robolectric assertion.
- Target: stuck-connection watchdog + `ConnectionRegistry`.
- Preconditions: a `TestLogonConnection` left non-terminal with no matching live
  signalling state.
- Steps: advance virtual time past 60s; also simulate signalling `observe`
  closing.
- Expected: connection is disconnected (`DisconnectCause`), removed from the
  registry, and `destroy()` is called; no entry remains.
- Traces: AC-7.

**TC-AND-304-09 — Outgoing self-managed call end-to-end (emulator)**
- Type: instrumented / e2e.
- Target: full Telecom flow on AVD `test35` (API 35).
- Preconditions: PhoneAccount registered; MockWebServer/test signalling double.
- Steps: place a call via `TelecomManager.placeCall`; simulate peer answer via
  signalling; inspect `dumpsys telecom`.
- Expected: a self-managed call appears in Telecom (`DIALING`→`ACTIVE`); on local
  end the call disappears from `dumpsys telecom` (no phantom).
- Traces: AC-2, AC-7.

**TC-AND-304-10 — Incoming call + cellular interop hold/unhold (PHYSICAL
DEVICE)**
- Type: instrumented / e2e. MUST run on the physical Samsung A15 5G (real
  cellular radio; emulator cannot raise a real CS call).
- Target: `addNewIncomingCall` + `onHold`/`onUnhold`.
- Preconditions: device has an active SIM; TestLogon call in `ACTIVE`.
- Steps: report an incoming TestLogon call, accept it; place/receive a real GSM
  cellular call; end the cellular call.
- Expected: TestLogon call rings even when backgrounded, connects on accept and
  shows in the system call UI; when the cellular call goes active the OS issues
  `onHold` → TestLogon reports `STATE_HOLDING` and media pauses; on cellular end,
  `onUnhold` → `STATE_ACTIVE` and media resumes.
- Traces: AC-1, AC-5.

**TC-AND-304-11 — Audio routing + hardware controls across real devices
(PHYSICAL DEVICE)**
- Type: instrumented / manual. MUST run on the physical device (real BT/wired
  headset, hardware end-call/hook button).
- Target: `CallAudioRouter` + `CallAudioState`/`CallEndpoint`.
- Preconditions: a paired Bluetooth headset and a wired headset available;
  `BLUETOOTH_CONNECT` granted.
- Steps: during an active call, toggle earpiece→speaker→wired→BT SCO; press the
  headset hook (mute toggle) and the hardware/system end-call.
- Expected: active/available routes and mute state in the in-call UI track the
  real device; headset hook toggles mute; hardware/system end-call drives
  `onDisconnect`/`onAbort` and tears down media + clears notification.
- Traces: AC-4, AC-7.

**TC-AND-304-12 — Graceful degradation / flaky-host + offline teardown**
- Type: instrumented (emulator `test35`) + contract.
- Target: fallback path + §7 resilience.
- Preconditions: build with Telecom forced-unsupported (probe→false); separately,
  airplane-mode/offline and a 20s-timeout dev-host scenario via MockWebServer
  delay.
- Steps: (a) on the forced-unsupported build, receive/accept/conduct a call;
  (b) with the network offline/timed-out, end a call locally.
- Expected: (a) the AND-297 notification fallback completes a full call with
  correct manual audio focus, no crash, no phantom OS call; (b) the local
  `Connection` disconnects immediately without waiting on the network — the
  disposition POST is fire-and-forget with a single best-effort retry; the call
  UI never hangs.
- Traces: AC-6, AC-7.

**TC-AND-304-13 — Security: no secrets in logs or Telecom extras + permission
boundary**
- Type: instrumented / manual (emulator or device).
- Target: logging, Telecom `extras`/`Uri`, manifest permission.
- Preconditions: debug build with Timber capture; `dumpsys telecom` access.
- Steps: run a full call; capture logs and `dumpsys telecom` extras; verify the
  service binding.
- Expected: no cookie, no CSRF token, no Bearer token, and no raw `callId`
  appear in logs (callId is hashed) or in Telecom `extras`/`Uri` (only opaque
  callId + display name); the `ConnectionService` is bound only by the system
  (protected by `BIND_TELECOM_CONNECTION_SERVICE`); denying `BLUETOOTH_CONNECT`
  silently drops BT from `available` without crashing.
- Traces: AC-8, AC-4.

**TC-AND-304-14 — Accessibility of the fallback in-call audio controls**
- Type: Compose-UI (emulator `test35`) + manual TalkBack pass on device.
- Target: in-app fallback in-call screen (route selector + mute).
- Preconditions: fallback in-call screen rendered.
- Steps: assert semantics; run a TalkBack pass; toggle a route.
- Expected: each route button and the mute toggle expose `contentDescription`
  and `Role.Button`/`Role.Switch` with selected state announced (e.g. "Speaker,
  selected"); strings come from `strings.xml` (no hardcoded literals), RTL-safe;
  a route change is announced via a live region.
- Traces: AC-4.

### Coverage matrix

| AC (§14) | Covered by |
|----------|-----------|
| AC-1 (incoming registered, rings backgrounded, connects on accept) | TC-07, TC-10 |
| AC-2 (outgoing DIALING→ACTIVE) | TC-07, TC-09 |
| AC-3 (accept/decline/hangup route through callbacks → backend) | TC-02, TC-04, TC-05 |
| AC-4 (audio routing + mute + headset hook in UI) | TC-03, TC-11, TC-13, TC-14 |
| AC-5 (cellular interop hold/unhold, media pause/resume) | TC-02, TC-10 |
| AC-6 (fallback on API<26 / unsupported, no crash, no phantom) | TC-01, TC-05, TC-07, TC-12 |
| AC-7 (no leaked Telecom connection; resilient teardown) | TC-06, TC-08, TC-09, TC-11, TC-12 |
| AC-8 (no secrets/raw callId in logs or extras) | TC-04, TC-13 |
