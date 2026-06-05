---
id: AND-299
title: Group calls
milestone: M7
epic: E40
priority: P1
size: L
status: draft
depends_on: [AND-298]
blocks: []
---

# AND-299 — Group calls

## 1. Overview & Goal

Extend the existing 1:1 calling stack (AND-296 outgoing flow, AND-298 in-call UI) to support multi-party voice/video calls of three or more participants. This ticket delivers the group-call signaling layer over the backend `/ui/calls/group/*` endpoints, the multi-party media plumbing (one peer connection per remote participant in a mesh, sufficient for small groups), and an adaptive Compose grid UI that renders N participant tiles, per-participant state (mute/video-off/speaking/connection quality), and roster mutations (join/leave) in real time.

The single, measurable goal is: **a call with 3 or more participants connects** — i.e., a host starts a group call, two or more invitees accept, and every connected participant has a live audio/video session with every other connected participant, with the roster and per-tile state reflecting reality. All 1:1 in-call controls (mute, camera toggle, speaker, flip, end) from AND-298 continue to function per local participant.

Out of scope: SFU/MCU server-side mixing (this ticket assumes a client-side mesh; an SFU migration is a future ticket), screen sharing, call recording, large rooms (>6 participants is best-effort only), and call scheduling.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace:** `com.testlogon.android` (applicationId base and Kotlin package root).
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore, Media3/ExoPlayer 1.4. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Module layering:** `app -> feature-call -> core-*` (`core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`). ViewModels expose `StateFlow<UiState>`; typed `ApiResult<T>`; FastAPI `detail` mapping (`string | [{msg}] | {code,...}`).
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI at `/openapi.json`. Auth is cookie-based; the persistent cookie jar and `X-CSRF-Token` echo from AND-290 apply to all `/ui/calls/group/*` requests.
- **Upstream tickets:** AND-298 (In-call UI 1:1) supplies `CallControlsBar`, `CallSession`, the `WebRtcEngine` abstraction, and the foreground call service. AND-296 supplies invite/ringing/connect lifecycle. AND-295/AND-293 supply the realtime channel (WebSocket/SSE) used for signaling fan-out. **AND-299 generalizes these from a single remote peer to a keyed map of remote peers.**
- **Web reference:** mirror request/response shapes against `frontend/src/api/endpoints/calls.ts` and `frontend/src/api/types.ts` (`GroupCall`, `CallParticipant`); confirm exact field names against `/openapi.json` before freezing the Moshi DTOs.

## 3. Functional Requirements

FR-1. A user can start a group call by selecting 2+ invitees (from a thread or a multi-select people picker) and tapping "Group call". The app calls `POST /ui/calls/group` and transitions to the in-call screen in a `Connecting` state.

FR-2. A user can invite additional participants to an in-progress group call via `POST /ui/calls/group/{call_id}/invite`; new tiles appear in `Ringing`/`Connecting` state.

FR-3. An invitee receives a group-call invite over the realtime channel, sees an incoming-group-call screen listing the host and current roster, and can Accept (`POST /ui/calls/group/{call_id}/join`) or Decline (`POST /ui/calls/group/{call_id}/decline`).

FR-4. Once joined, each participant establishes a media session with **every other connected participant** (full mesh). Local audio/video must be heard/seen by all peers and vice versa.

FR-5. The in-call grid renders one tile per participant (including a self-tile). Layout adapts: 2 tiles (incl. self) = stacked/side-by-side; 3–4 = 2×2 grid; 5–6 = 3×2 grid; >6 = scrollable grid (best-effort). The active speaker is highlighted.

FR-6. Each tile shows: display name, avatar fallback (video off), mute indicator, connection-quality glyph, and a connecting/reconnecting spinner.

FR-7. Roster changes (a participant joins, leaves, or drops) update tiles within ~2s of the realtime event without recomposing unaffected tiles.

FR-8. The local participant can leave with the End control (`POST /ui/calls/group/{call_id}/leave`); the call continues for others. If the host (call owner) leaves and `end_on_host_leave` is true, the backend ends the call and all clients tear down.

FR-9. All AND-298 local controls (mute, camera on/off, speaker route, camera flip) apply to the local participant and propagate state to peers via signaling.

FR-10. A foreground service + ongoing notification (reused from AND-298) keeps the call alive when backgrounded and shows participant count.

## 4. Technical Design

New feature module: `feature-call` is extended (no new module). Package `com.testlogon.android.feature.call.group`.

**State model (core-model):**

```kotlin
enum class ParticipantState { Ringing, Connecting, Connected, Reconnecting, Left, Failed }
enum class ConnQuality { Good, Fair, Poor, Unknown }

data class ParticipantId(val value: String)

data class CallParticipant(
    val id: ParticipantId,
    val userId: String,
    val displayName: String,
    val avatarUrl: String?,
    val isSelf: Boolean,
    val isHost: Boolean,
    val state: ParticipantState,
    val micMuted: Boolean,
    val cameraOff: Boolean,
    val speaking: Boolean,
    val quality: ConnQuality,
)

data class GroupCallUiState(
    val callId: String?,
    val phase: CallPhase,                       // Idle, Inviting, Incoming, Active, Ending, Ended
    val participants: List<CallParticipant>,    // includes self; stable sort by joinedAt
    val localControls: LocalCallControls,       // mute/cam/speaker/flip from AND-298
    val activeSpeakerId: ParticipantId?,
    val error: CallError?,
)
```

**ViewModel:**

```kotlin
@HiltViewModel
class GroupCallViewModel @Inject constructor(
    private val groupCallRepository: GroupCallRepository,
    private val signaling: CallSignalingClient,       // from AND-293/295
    private val mesh: MeshConnectionManager,
    private val savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<GroupCallUiState>
    fun start(inviteeUserIds: List<String>, video: Boolean)
    fun accept(callId: String)
    fun decline(callId: String)
    fun invite(userIds: List<String>)
    fun leave()
    fun toggleMute(); fun toggleCamera(); fun toggleSpeaker(); fun flipCamera()
}
```

**Mesh manager** — the core new abstraction. Holds a `Map<ParticipantId, PeerConnection>` and bridges the AND-298 `WebRtcEngine` (which previously held a single peer) to N peers:

```kotlin
interface MeshConnectionManager {
    val peerEvents: SharedFlow<PeerEvent>          // Connected, Disconnected, Quality, Speaking, RemoteTrack
    suspend fun addPeer(p: ParticipantId, isInitiator: Boolean)
    suspend fun applyRemoteSdp(p: ParticipantId, sdp: SessionDescription)
    suspend fun applyRemoteIce(p: ParticipantId, candidate: IceCandidate)
    fun setLocalMute(muted: Boolean); fun setLocalVideo(on: Boolean)
    suspend fun removePeer(p: ParticipantId)
    suspend fun closeAll()
}
```

The local capture (mic/camera) tracks are created once and **added to every** `PeerConnection`. Offer/answer glare is resolved deterministically: the participant with the lexicographically smaller `userId` is the initiator for a given pair, so each new joiner negotiates with the existing roster predictably.

**Signaling flow (per pair):** SDP offers/answers and ICE candidates are relayed through the realtime channel from AND-293/295, tagged with `call_id` + target `participant_id`. Signaling messages: `sdp_offer`, `sdp_answer`, `ice_candidate`, `participant_joined`, `participant_left`, `participant_state` (mute/cam), `call_ended`.

**UI (Compose):** `GroupCallScreen(state, onAction)` renders `ParticipantGrid` (a `LazyVerticalGrid` with adaptive cell count derived from `participants.size`), `CallControlsBar` (reused from AND-298), and an overlay roster sheet. Each `ParticipantTile` is keyed by `ParticipantId.value` so roster mutations only recompose affected tiles. Remote video renders into a Media3/WebRTC `SurfaceViewRenderer` hosted via `AndroidView`.

## 5. API Contract

All requests carry session cookies + `X-CSRF-Token` (AND-290). Idempotent GETs use the ~20s timeout + bounded backoff; mutations (POST) are not retried automatically.

`POST /ui/calls/group` — start a call.
```json
// request
{ "invitee_user_ids": ["u_123","u_456"], "video": true }
// response 201
{ "call_id": "gc_789", "host_user_id": "u_self",
  "participants": [
    {"participant_id":"p_self","user_id":"u_self","state":"connected","is_host":true},
    {"participant_id":"p_1","user_id":"u_123","state":"ringing"},
    {"participant_id":"p_2","user_id":"u_456","state":"ringing"}
  ],
  "end_on_host_leave": true }
```

`GET /ui/calls/group/{call_id}` — fetch current roster (idempotent; used for reconnect/resync).
```json
{ "call_id":"gc_789","host_user_id":"u_self","state":"active",
  "participants":[ {"participant_id":"p_1","user_id":"u_123","display_name":"Ada","avatar_url":null,"state":"connected","mic_muted":false,"camera_off":true} ] }
```

`POST /ui/calls/group/{call_id}/join` → `200 {"participant_id":"p_3","ice_servers":[{"urls":["stun:..."],"username":null,"credential":null}]}`
`POST /ui/calls/group/{call_id}/decline` → `204`
`POST /ui/calls/group/{call_id}/invite` body `{"user_ids":["u_999"]}` → `200 {"participants":[...]}`
`POST /ui/calls/group/{call_id}/leave` → `204`

Signaling relay (if exposed as REST fallback alongside the AND-293/295 socket):
`POST /ui/calls/group/{call_id}/signal` body `{"target_participant_id":"p_2","type":"sdp_offer","payload":{...}}` → `204`.

Retrofit service (`core-network`):
```kotlin
interface GroupCallApi {
    @POST("ui/calls/group") suspend fun start(@Body body: StartGroupCallRequest): Response<GroupCallDto>
    @GET("ui/calls/group/{id}") suspend fun get(@Path("id") id: String): Response<GroupCallDto>
    @POST("ui/calls/group/{id}/join") suspend fun join(@Path("id") id: String): Response<JoinResponseDto>
    @POST("ui/calls/group/{id}/invite") suspend fun invite(@Path("id") id: String, @Body b: InviteRequest): Response<GroupCallDto>
    @POST("ui/calls/group/{id}/decline") suspend fun decline(@Path("id") id: String): Response<Unit>
    @POST("ui/calls/group/{id}/leave") suspend fun leave(@Path("id") id: String): Response<Unit>
}
```
**Field names above are provisional** — verify against `/openapi.json` and `frontend/src/api/types.ts` before merge; do not invent fields the backend does not return.

## 6. Data & State Management

- **Source of truth:** `GroupCallViewModel` holds the live `GroupCallUiState` in memory only — a call is ephemeral and is **not** persisted to Room. Roster is reconciled from two streams: REST responses (start/join/invite/get) and realtime `participant_*` events, merged into the `participants` list keyed by `participant_id`.
- **Reconciliation rule:** realtime events win for transient fields (state, mute, camera, speaking, quality); REST `GET` is the authority on membership after a reconnect resync. A small reducer `fun reduce(state, event): GroupCallUiState` keeps mutations pure and testable.
- **Ordering:** participants sorted by `joinedAt` then `displayName` for stable tile positions; self always pinned to a known slot per the layout rule.
- **DataStore:** only persists call preferences (default to video on/off, default speaker route) — not call state.
- **Process death:** `SavedStateHandle` retains `callId`; on restore the VM calls `GET /ui/calls/group/{call_id}` to resync and re-establishes mesh peers. If the call no longer exists (`404`), transition to `Ended`.
- **Active speaker:** derived in the VM from audio-level `PeerEvent.Speaking`, debounced ~300ms to avoid flicker.

## 7. Error Handling & Resilience

- Map FastAPI `detail` via the shared `ApiResult` mapper (`string | [{msg}] | {code}`) to `CallError` types: `NotFound`, `Forbidden`, `CallFull`, `AlreadyJoined`, `Network`, `Unknown`.
- **401 on any call request:** trigger the shared single `POST /ui/session/refresh` then retry once (AND-290 interceptor); if refresh fails, surface auth error and tear down the call.
- **Per-peer failure isolation:** a failed `PeerConnection` to one participant must NOT drop the whole call. That tile shows `Reconnecting`; the mesh manager attempts ICE restart with bounded backoff (e.g., 2s, 4s, 8s, cap 3 tries) before marking the tile `Failed`. Other peers stay live.
- **Realtime channel drop:** on socket reconnect (AND-293/295), perform a full `GET /ui/calls/group/{call_id}` resync and renegotiate any peers whose state diverged.
- **Unreliable dev host:** all GET resyncs use ~20s timeout + bounded backoff; mutations are not auto-retried — surface a retryable inline error with manual retry.
- **No participants connected within 30s of start:** transition to `Failed` with a "Couldn't connect" state and offer retry/end.
- **Network loss:** show a global "Reconnecting…" banner; auto-resume on restore; if offline >60s, end the call locally.

## 8. Security & Privacy

- Camera + microphone runtime permissions (`RECORD_AUDIO`, `CAMERA`) requested before media capture; missing-permission state blocks start with a rationale.
- All call requests authenticated via the cookie jar; `X-CSRF-Token` header on every mutation. No call tokens or SDP logged at INFO.
- `INTERNET`, `ACCESS_NETWORK_STATE`, and the foreground-service types (`microphone`, `camera`) declared with the narrowest scope.
- Media is peer-to-peer (mesh): ICE/STUN/TURN servers come from the backend `join` response — do not hardcode. Prefer DTLS-SRTP defaults from the WebRTC stack; do not disable encryption.
- **Dev backend is plaintext HTTP** — signaling (SDP/ICE) traverses cleartext in dev. Document this risk; production must use HTTPS/WSS. Do not weaken `cleartextTrafficPermitted` beyond the existing dev-only network-security-config from AND-290.
- Avatar images load through Coil with the authenticated client; no PII (names, user ids) written to crash logs.

## 9. Accessibility & i18n

- Every tile control and indicator has a `contentDescription` (e.g., "Ada, muted, poor connection"); the active-speaker highlight is conveyed via text/semantics, not color alone.
- Control buttons meet 48dp touch targets; `CallControlsBar` already complies (AND-298).
- TalkBack announces roster changes ("Ada joined", "Ben left") via a `LiveRegion` on the roster summary.
- All user-facing strings in `strings.xml` with plural resources for participant count (`<plurals name="call_participants">`); no concatenation. RTL-safe layouts (use start/end).
- Respect system font scaling; tiles use constraints, not fixed text sizes.

## 10. Telemetry & Logging

- Structured events (existing analytics wrapper): `group_call_started` (invitee_count, video), `group_call_joined`, `group_call_participant_connected` (time_to_connect_ms), `group_call_peer_failed` (reason), `group_call_ended` (duration_ms, peak_participants, end_reason).
- The key acceptance metric — **3+ party connect** — is observable via `peak_participants >= 3` plus all-peer `Connected`.
- Logging: per-peer state transitions and ICE connection states at DEBUG; never log SDP payloads, candidates, cookies, or CSRF tokens. Errors mapped to `CallError` logged at WARN with the participant id only.
- A debug overlay (debug builds only) shows per-peer RTT/quality for manual verification.

## 11. Testing Strategy

- **Unit (core-testing, JUnit + Turbine + MockWebServer):**
  - `reduce(state, event)` reducer: join/leave/state events produce correct roster; idempotent duplicate `participant_joined` is a no-op.
  - `GroupCallViewModel`: `start()` → `Inviting`; join events → tiles flip `Ringing`→`Connected`; **assert `phase == Active` with `participants.count { it.state == Connected } >= 3`** (directly encodes acceptance).
  - Glare resolution: initiator selection deterministic by `userId` ordering.
  - Error mapping for 401-refresh-retry, 404→Ended, CallFull.
  - Per-peer failure isolation: one peer `Failed` leaves others `Connected`.
- **Repository:** MockWebServer fixtures for all `/ui/calls/group/*` endpoints incl. malformed `detail` shapes and timeouts.
- **Mesh manager:** fake `WebRtcEngine` verifies local tracks added to every peer and `removePeer` closes only the target.
- **Compose UI tests:** `ParticipantGrid` renders N tiles for N participants; adaptive cell count for 2/4/6; tile keyed-recomposition (adding a tile doesn't recompose others — verify via recomposition counter); content descriptions present.
- **Manual / instrumented E2E:** 3-device (or 1 device + 2 emulators) run against dev backend — host starts, two join, verify bidirectional audio/video across all pairs and correct roster. This is the literal acceptance test.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-298** (In-call UI 1:1) — supplies `CallControlsBar`, `WebRtcEngine`, `CallSession`, and the foreground call service that this ticket generalizes to N peers. Cannot start before AND-298 lands.
- Transitive: AND-296 (call lifecycle), AND-293/AND-295 (realtime signaling channel), AND-290 (cookie/CSRF auth + network-security-config).
- **Sequencing within this ticket:** (1) DTOs + `GroupCallApi` + repository (verify against OpenAPI); (2) `reduce` reducer + `GroupCallViewModel` with fake mesh; (3) `MeshConnectionManager` over `WebRtcEngine`; (4) `GroupCallScreen` grid UI; (5) signaling wiring + reconnect/resync; (6) instrumented multi-device E2E.
- **Blocks:** none recorded in backlog. A future SFU-migration ticket would build on the mesh interfaces defined here.

## 13. Risks & Open Questions

- **Mesh scalability:** full mesh is O(n²) connections/bandwidth; degrades past ~5–6 participants. This ticket targets the 3+ acceptance bar; large rooms need an SFU (out of scope). Risk: P1 acceptance is fine, but document the ceiling.
- **TURN availability:** mesh NAT traversal needs working STUN/TURN from the backend `join` response. **Open question:** does the dev backend return usable TURN credentials? If only STUN, symmetric-NAT peers may fail to connect — confirm with backend team.
- **Signaling fan-out semantics:** **Open question** — does AND-293/295 channel support targeted per-participant routing, or only broadcast? Affects whether SDP/ICE go over the socket or the REST `/signal` fallback.
- **Exact API shape:** `/ui/calls/group/*` field names are provisional pending `/openapi.json` verification; confirm `end_on_host_leave`, `ice_servers`, and participant state enum values.
- **Glare/renegotiation under churn:** rapid join/leave could cause SDP negotiation races; mitigated by deterministic initiator rule but needs E2E soak testing.
- **Dev host instability** may make multi-device E2E flaky; budget retries and consider a staging host for the acceptance demo.

## 14. Acceptance Criteria

- AC-1 (**primary, from backlog**): A group call with **3 or more participants connects** — host starts, two+ invitees join, and `GroupCallUiState.phase == Active` with at least 3 participants in `Connected` state, each having a live media session with every other connected participant (verified by bidirectional audio/video across all pairs).
- AC-2: Starting a call calls `POST /ui/calls/group` and renders a tile per invitee in `Ringing`, then `Connected` on join.
- AC-3: A participant leaving (`/leave`) removes only their tile; the call continues for others; if the host leaves and `end_on_host_leave`, all clients tear down.
- AC-4: All AND-298 local controls (mute, camera, speaker, flip, end) function during a group call and propagate to peers.
- AC-5: One peer connection failing shows that tile `Reconnecting`/`Failed` without dropping other peers.
- AC-6: Roster/state changes reflect within ~2s; tiles are keyed so unaffected tiles don't recompose.
- AC-7: 401 triggers a single `session/refresh` + retry; 404 on resync ends the call gracefully.
- AC-8: Adaptive grid renders correct layout for 2/4/6 participants; active speaker highlighted with non-color-only cues.

## 15. Definition of Done

- All AC-1…AC-8 met; the multi-device E2E acceptance run (3+ parties connect) passes against the dev (or staging) backend and is documented.
- `feature-call` group code merged to `android-port`; package `com.testlogon.android.feature.call.group`; layering respected (`feature-call -> core-*`).
- DTO field names verified against `/openapi.json`; no fabricated fields.
- Unit, repository, mesh, and Compose tests pass in CI; the reducer test encoding "3+ connected" is green.
- Lint/detekt/ktlint clean; no SDP/cookies/CSRF/PII in logs; permissions and foreground-service types declared minimally.
- Accessibility pass (TalkBack roster announcements, content descriptions, 48dp targets) and string externalization with plurals complete.
- Telemetry events emitting with `peak_participants` and per-peer connect timing; debug per-peer overlay available in debug builds.
- Open questions in §13 (TURN credentials, signaling routing) resolved or explicitly deferred with owners before release.
