---
id: AND-299
title: Group calls
milestone: M7
epic: E40
priority: P1
size: L
depends_on: [AND-298]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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

FR-1. A user can start a group call from a conversation/thread by tapping "Group call". **[CORRECTED]** Group calls are **conversation-scoped**, not invitee-list-scoped: the app calls `POST /ui/calls/group/create` with `{conversation_id, mode}` (where `mode` is `"audio" | "video"`) and transitions to the in-call screen in a `Connecting` state. There is **no** server-side invitee list on create — every member of the conversation is eligible to join the active call. (Verified: OpenAPI `POST /ui/calls/group/create`, `GroupCallCreateIn`; frontend `src/api/endpoints/groupCalls.ts: createGroupCall`.)

FR-2. **[CORRECTED]** There is **no** `POST /ui/calls/group/{call_id}/invite` endpoint. Adding participants is implicit: conversation members discover the active call via `GET /ui/calls/group/active/{conversation_id}` (e.g., surfaced by a realtime "call started" event) and join it directly. New tiles appear in `Ringing`/`Connecting` state as `participant_*` realtime events arrive. The app surfaces an "active call" affordance in the conversation rather than an explicit invite action.

FR-3. A conversation member is notified of an active group call over the realtime channel (or via `GET /ui/calls/group/active/{conversation_id}`), sees an incoming/active-group-call screen listing the creator and current roster, and can Accept (`POST /ui/calls/group/{call_id}/join`) or dismiss locally. **[CORRECTED]** There is **no** `POST /ui/calls/group/{call_id}/decline` endpoint; declining is a purely local/UI dismissal of the active-call affordance (no server call). (Verified: OpenAPI index — only `join`/`leave`/`end`/`media`/`signal`/`participants` exist under `/ui/calls/group/{call_id}`.)

FR-4. Once joined, each participant establishes a media session with **every other connected participant** (full mesh). Local audio/video must be heard/seen by all peers and vice versa.

FR-5. The in-call grid renders one tile per participant (including a self-tile). Layout adapts: 2 tiles (incl. self) = stacked/side-by-side; 3–4 = 2×2 grid; 5–6 = 3×2 grid; >6 = scrollable grid (best-effort). The active speaker is highlighted.

FR-6. Each tile shows: display name, avatar fallback (video off), mute indicator, connection-quality glyph, and a connecting/reconnecting spinner.

FR-7. Roster changes (a participant joins, leaves, or drops) update tiles within ~2s of the realtime event without recomposing unaffected tiles.

FR-8. The local participant can leave with the End control (`POST /ui/calls/group/{call_id}/leave`); the call continues for others. **[CORRECTED]** The `leave` response (`GroupCallLeaveOut`) is `{ok, call_ended, remaining_participants}` — when `call_ended == true` (e.g., the creator left or the room emptied) all clients tear down. The creator can also explicitly end the call for everyone via `POST /ui/calls/group/{call_id}/end` (`GroupCallEndOut`). There is **no** `end_on_host_leave` request/response field; host-leave teardown is conveyed by `call_ended: true` and/or a `call_ended` realtime event.

FR-9. All AND-298 local controls (mute, camera on/off, speaker route, camera flip) apply to the local participant. **[CORRECTED]** Mute/camera state is propagated to peers by `PATCH /ui/calls/group/{call_id}/media` with `{audio?, video?, screen?}` booleans (`GroupCallMediaUpdateIn` → `GroupCallMediaUpdateOut {ok, media_status}`); the backend fans the resulting `media_status` out to other participants (reflected in each `GroupCallParticipant.media_status`). Speaker route and camera flip are purely local device operations with no server call. (Verified: OpenAPI `PATCH /ui/calls/group/{call_id}/media`, `GroupCallMediaUpdateIn`; frontend `groupCalls.ts: updateGroupCallMedia`.)

FR-10. A foreground service + ongoing notification (reused from AND-298) keeps the call alive when backgrounded and shows participant count.

## 4. Technical Design

New feature module: `feature-call` is extended (no new module). Package `com.testlogon.android.feature.call.group`.

**State model (core-model):**

```kotlin
enum class ParticipantState { Ringing, Connecting, Connected, Reconnecting, Left, Failed }
enum class ConnQuality { Good, Fair, Poor, Unknown }

// CORRECTED: the backend has no `participant_id`. Participants are keyed by `user_id`
// (the only stable identity returned by GroupCallParticipant). ParticipantId wraps user_id.
data class ParticipantId(val value: String)   // == GroupCallParticipant.user_id

data class CallParticipant(
    val id: ParticipantId,                     // wraps user_id; there is no separate participant_id
    val userId: String,                        // == id.value
    val displayName: String,                   // GroupCallParticipant.display_name
    val avatarUrl: String?,                    // ASSUMPTION: not in GroupCallParticipant; resolve via profile lookup
    val isSelf: Boolean,
    val isHost: Boolean,                        // derived: user_id == GroupCallOut.creator_user_id
    val state: ParticipantState,               // GroupCallParticipant.state (string enum, see below)
    val micMuted: Boolean,                     // !GroupCallParticipant.media_status.audio
    val cameraOff: Boolean,                     // !GroupCallParticipant.media_status.video
    val speaking: Boolean,                      // client-derived (audio level), not server-provided
    val quality: ConnQuality,                   // GroupCallParticipant.connection_quality (string)
    val joinedAt: Long,                         // GroupCallParticipant.joined_at (epoch)
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

**Signaling flow (per pair):** SDP offers/answers and ICE candidates are relayed through the realtime channel from AND-293/295, or via the REST fallback `POST /ui/calls/group/{call_id}/signal`. **[CORRECTED]** The signal body (`GroupCallSignalIn`) targets a peer by `target_user_id` (NOT `participant_id`/`target_participant_id`), with `type: string` and a free-form `payload: object`. Application-level message `type`s the client uses: `sdp_offer`, `sdp_answer`, `ice_candidate`. Roster/state changes (`participant_joined`, `participant_left`, `media_status` updates, `call_ended`) arrive as realtime events and/or are reconciled from `GET /ui/calls/group/{call_id}` + `GET .../participants`. **[CORRECTED]** Mute/camera is NOT sent as a `participant_state` signal — it is published via `PATCH .../media` (see FR-9) and surfaces back as `GroupCallParticipant.media_status`.

**UI (Compose):** `GroupCallScreen(state, onAction)` renders `ParticipantGrid` (a `LazyVerticalGrid` with adaptive cell count derived from `participants.size`), `CallControlsBar` (reused from AND-298), and an overlay roster sheet. Each `ParticipantTile` is keyed by `ParticipantId.value` (= `user_id`) so roster mutations only recompose affected tiles. Remote video renders into a Media3/WebRTC `SurfaceViewRenderer` hosted via `AndroidView`.

## 5. API Contract

All requests carry session cookies + `X-CSRF-Token` (AND-290). **[VERIFIED]** the web client reads the CSRF token from the `ui_csrf` cookie and sends it as `X-CSRF-Token` on all requests with `credentials: "include"` (`src/api/client.ts`). Idempotent GETs use the ~20s timeout + bounded backoff; mutations (POST/PATCH) are not retried automatically.

> **[MAJOR CORRECTION]** The provisional contract in the prior draft (`POST /ui/calls/group`, `/invite`, `/decline`, `participant_id`, `end_on_host_leave`, top-level `ice_servers`, 204 responses) did **not** match the backend. The verified contract follows. Endpoints confirmed via `reference/openapi.index.txt` (lines 1288–1297); shapes via `components.schemas.*` and `src/api/types.ts` + `src/api/endpoints/groupCalls.ts`. All group endpoints declare only `200/201` success and `422 HTTPValidationError`.

`POST /ui/calls/group/create` — start a call. Request `GroupCallCreateIn`, response **201** `GroupCallOut`.
```json
// request (GroupCallCreateIn) — conversation_id required; mode default "video"; max_participants default 8, range 2..8
{ "conversation_id": "conv_123", "mode": "video", "max_participants": 8 }
// response 201 (GroupCallOut)
{ "call_id": "gc_789", "conversation_id": "conv_123", "creator_user_id": "u_self",
  "state": "active", "mode": "video", "max_participants": 8, "current_participant_count": 1,
  "participants": [
    { "user_id": "u_self", "display_name": "Me", "joined_at": 1717700000, "left_at": 0,
      "media_status": {"audio": true, "video": true, "screen": false},
      "connection_quality": "good", "state": "connected" }
  ],
  "created_at": 1717700000, "started_at": 1717700000, "end_ts": 0, "end_reason": "",
  "duration_seconds": 0,
  "signaling": { "mode": "...", "ice_servers": [ {"urls": "...", "username": "...", "credential": "..."} ] } }
```

`GET /ui/calls/group/{call_id}` — fetch current call + roster (`GroupCallOut`; idempotent; reconnect/resync).
`GET /ui/calls/group/{call_id}/participants` — roster only (`GroupCallParticipantsOut {participants[], total_active, total_joined}`).
`GET /ui/calls/group/active/{conversation_id}` — discover an active call for a conversation (`GroupCallActiveOut {active, call_id?, state?, mode?, current_participant_count?, participants?}`).
`GET /ui/calls/group/history/{conversation_id}` — past calls (`GroupCallHistoryOut {calls: GroupCallOut[]}`).

`POST /ui/calls/group/{call_id}/join` → **200** `GroupCallJoinOut`:
```json
{ "call_id":"gc_789", "state":"active", "mode":"video", "current_participant_count":2,
  "participants":[ /* GroupCallParticipant[] */ ],
  "signaling": { "mode":"mesh", "ice_servers":[ {"urls":"...","username":"...","credential":"..."} ] } }
```
**[CORRECTED]** ICE/STUN/TURN servers come from `GroupCallJoinOut.signaling.ice_servers` (nested under `signaling`), NOT a top-level `ice_servers`. The exact ICE-server object key set is `{urls, username, credential}` per `TurnIceServerOut`/`GroupCallSignalingInfo`. A separate per-call TURN endpoint also exists for the 1:1 stack — `POST /messaging/messages/calls/{call_id}/turn-credentials` → `TurnCredentialsOut {ttl_seconds, expires_at, ice_servers: TurnIceServerOut[]}` — usable as a fallback/refresh source.

`POST /ui/calls/group/{call_id}/leave` → **200** `GroupCallLeaveOut {ok, call_ended, remaining_participants}`. (Not 204; teardown signalled by `call_ended`.)
`POST /ui/calls/group/{call_id}/end` → **200** `GroupCallEndOut {ok, call_id, duration_seconds, total_participants}` (creator ends for all).
`PATCH /ui/calls/group/{call_id}/media` body `GroupCallMediaUpdateIn {audio?, video?, screen?}` → **200** `GroupCallMediaUpdateOut {ok, media_status}`.
`POST /ui/calls/group/{call_id}/signal` body `GroupCallSignalIn {type, target_user_id, payload}` → **200** `GroupCallSignalOut {ok, relayed_to}`. (REST fallback alongside the AND-293/295 socket.)

> **[CORRECTED] Endpoints that do NOT exist** and were removed from the design: `POST /ui/calls/group` (use `/create`), `POST .../invite`, `POST .../decline`. Joining is conversation-scoped (no invitee list). There is also no `participant_id`, `host_user_id`, `mic_muted`, `camera_off`, `is_host`, or `end_on_host_leave` field anywhere in the group schemas.

Retrofit service (`core-network`):
```kotlin
interface GroupCallApi {
    @POST("ui/calls/group/create") suspend fun create(@Body body: CreateGroupCallRequest): Response<GroupCallDto>
    @GET("ui/calls/group/{id}") suspend fun get(@Path("id") id: String): Response<GroupCallDto>
    @GET("ui/calls/group/{id}/participants") suspend fun participants(@Path("id") id: String): Response<ParticipantsDto>
    @GET("ui/calls/group/active/{conversationId}") suspend fun active(@Path("conversationId") c: String): Response<ActiveCallDto>
    @POST("ui/calls/group/{id}/join") suspend fun join(@Path("id") id: String): Response<JoinResponseDto>
    @POST("ui/calls/group/{id}/leave") suspend fun leave(@Path("id") id: String): Response<LeaveResponseDto>
    @POST("ui/calls/group/{id}/end") suspend fun end(@Path("id") id: String): Response<EndResponseDto>
    @PATCH("ui/calls/group/{id}/media") suspend fun media(@Path("id") id: String, @Body b: MediaUpdateRequest): Response<MediaUpdateDto>
    @POST("ui/calls/group/{id}/signal") suspend fun signal(@Path("id") id: String, @Body b: SignalRequest): Response<SignalDto>
}
// CreateGroupCallRequest(conversation_id, mode = "video", max_participants = 8)
// MediaUpdateRequest(audio: Boolean?, video: Boolean?, screen: Boolean?)
// SignalRequest(type: String, target_user_id: String, payload: Map<String, Any?>)
```
DTO field names above are **verified** against `GroupCall*` schemas / `src/api/types.ts`. Participant state/quality enum string values (`state`, `connection_quality`) are returned as free-form strings by the backend — treat unknown values defensively (map to `Unknown`).

## 6. Data & State Management

- **Source of truth:** `GroupCallViewModel` holds the live `GroupCallUiState` in memory only — a call is ephemeral and is **not** persisted to Room. Roster is reconciled from two streams: REST responses (create/join/get/participants) and realtime `participant_*` events, merged into the `participants` list **[CORRECTED]** keyed by `user_id` (there is no `participant_id`).
- **Reconciliation rule:** realtime events win for transient fields (state, mute, camera, speaking, quality); REST `GET` is the authority on membership after a reconnect resync. A small reducer `fun reduce(state, event): GroupCallUiState` keeps mutations pure and testable.
- **Ordering:** participants sorted by `joinedAt` then `displayName` for stable tile positions; self always pinned to a known slot per the layout rule.
- **DataStore:** only persists call preferences (default to video on/off, default speaker route) — not call state.
- **Process death:** `SavedStateHandle` retains `callId`; on restore the VM calls `GET /ui/calls/group/{call_id}` to resync and re-establishes mesh peers. If the call no longer exists (`404`), transition to `Ended`.
- **Active speaker:** derived in the VM from audio-level `PeerEvent.Speaking`, debounced ~300ms to avoid flicker.

## 7. Error Handling & Resilience

- Map FastAPI `detail` via the shared `ApiResult` mapper (`string | [{msg}] | {code}`) to `CallError` types: `NotFound`, `Forbidden`, `CallFull`, `AlreadyJoined`, `Network`, `Unknown`. **[UNVERIFIED]** The group endpoints only declare `200/201` and `422 HTTPValidationError` in the OpenAPI; specific statuses for `CallFull` (max_participants=8 exceeded) / `Forbidden` (non-member) / `NotFound` (404) are **assumptions** — the backend may surface them as 4xx with a FastAPI `detail` string, or as 422. Map defensively by HTTP status first, then `detail` body. (`max_participants` cap of 8 is verified from `GroupCallCreateIn`.)
- **401 on any call request:** **[VERIFIED]** trigger the shared single `POST /ui/session/refresh` then retry once — the web client does exactly this (single shared `refreshPromise`, then re-issues the request) in `src/api/client.ts`. If refresh fails, surface auth error and tear down the call.
- **Per-peer failure isolation:** a failed `PeerConnection` to one participant must NOT drop the whole call. That tile shows `Reconnecting`; the mesh manager attempts ICE restart with bounded backoff (e.g., 2s, 4s, 8s, cap 3 tries) before marking the tile `Failed`. Other peers stay live.
- **Realtime channel drop:** on socket reconnect (AND-293/295), perform a full `GET /ui/calls/group/{call_id}` resync and renegotiate any peers whose state diverged.
- **Unreliable dev host:** all GET resyncs use ~20s timeout + bounded backoff; mutations are not auto-retried — surface a retryable inline error with manual retry.
- **No participants connected within 30s of start:** transition to `Failed` with a "Couldn't connect" state and offer retry/end.
- **Network loss:** show a global "Reconnecting…" banner; auto-resume on restore; if offline >60s, end the call locally.

## 8. Security & Privacy

- Camera + microphone runtime permissions (`RECORD_AUDIO`, `CAMERA`) requested before media capture; missing-permission state blocks start with a rationale.
- All call requests authenticated via the cookie jar; `X-CSRF-Token` header on every mutation. No call tokens or SDP logged at INFO.
- `INTERNET`, `ACCESS_NETWORK_STATE`, and the foreground-service types (`microphone`, `camera`) declared with the narrowest scope.
- Media is peer-to-peer (mesh): **[CORRECTED]** ICE/STUN/TURN servers come from `GroupCallJoinOut.signaling.ice_servers` (nested), with `{urls, username, credential}` objects — do not hardcode. Optionally refresh via `POST /messaging/messages/calls/{call_id}/turn-credentials` (`TurnCredentialsOut` carries `ttl_seconds`/`expires_at`). Prefer DTLS-SRTP defaults from the WebRTC stack; do not disable encryption.
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
- **TURN availability:** mesh NAT traversal needs working STUN/TURN from `GroupCallJoinOut.signaling.ice_servers`. The schema confirms `{urls, username, credential}` are returned, and a dedicated `TurnCredentialsOut` (with `ttl_seconds`/`expires_at`) exists — but **open question:** does the *dev* backend populate real TURN (not just STUN) creds? If only STUN, symmetric-NAT peers may fail — confirm with backend team.
- **Signaling fan-out semantics:** the REST fallback `POST .../signal` is confirmed (`GroupCallSignalIn` targets a peer by `target_user_id`). **Open question** — does the AND-293/295 socket support targeted per-`user_id` routing, or only broadcast? Affects whether SDP/ICE prefer the socket or the REST `/signal` fallback.
- **Exact API shape:** **[RESOLVED in this review]** `/ui/calls/group/*` field names are now verified against the OpenAPI schemas and `src/api/types.ts` (see §5 and §16). Note: `end_on_host_leave` does **not** exist (use `GroupCallLeaveOut.call_ended`); `ice_servers` is nested under `signaling`; participant `state`/`connection_quality` are free-form strings (enum values not constrained in the schema) — map unknown values to `Unknown`.
- **Glare/renegotiation under churn:** rapid join/leave could cause SDP negotiation races; mitigated by deterministic initiator rule but needs E2E soak testing.
- **Dev host instability** may make multi-device E2E flaky; budget retries and consider a staging host for the acceptance demo.

## 14. Acceptance Criteria

- AC-1 (**primary, from backlog**): A group call with **3 or more participants connects** — host starts, two+ invitees join, and `GroupCallUiState.phase == Active` with at least 3 participants in `Connected` state, each having a live media session with every other connected participant (verified by bidirectional audio/video across all pairs).
- AC-2: **[CORRECTED]** Starting a call calls `POST /ui/calls/group/create` with `{conversation_id, mode}` and renders the creator tile; as conversation members join (`/join`), their tiles appear `Ringing`/`Connecting`, then `Connected`.
- AC-3: **[CORRECTED]** A participant leaving (`POST /leave`) removes only their tile and the call continues for others; when the `GroupCallLeaveOut.call_ended` flag is `true` (creator left / room emptied) or the creator calls `POST /end`, all clients tear down.
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

## 16. Citations & Assumption Audit

Sources: OpenAPI index `reference/openapi.index.txt`; OpenAPI spec `reference/openapi.pretty.json` (`components.schemas.*`); frontend `reference/src/api/...`.

1. **Start endpoint is `POST /ui/calls/group/create` (not `POST /ui/calls/group`).** VERDICT: Corrected. SOURCE: OpenAPI `POST /ui/calls/group/create` (op `create_call_endpoint_ui_calls_group_create_post`, req `GroupCallCreateIn`, resp 201); `src/api/endpoints/groupCalls.ts: createGroupCall`.
2. **Create request body is `{conversation_id (req), mode "audio"|"video" (default "video"), max_participants (default 8, 2..8)}` — not `{invitee_user_ids, video}`. Group calls are conversation-scoped.** VERDICT: Corrected. SOURCE: schema `GroupCallCreateIn`; `groupCalls.ts: createGroupCall`.
3. **No `POST /ui/calls/group/{call_id}/invite` endpoint exists.** VERDICT: Corrected (removed). SOURCE: OpenAPI index lines 1288–1297 (no invite path); `groupCalls.ts` (no invite fn).
4. **No `POST /ui/calls/group/{call_id}/decline` endpoint exists; declining is local-only.** VERDICT: Corrected (removed). SOURCE: OpenAPI index 1288–1297; `groupCalls.ts`.
5. **`GET /ui/calls/group/active/{conversation_id}` is how members discover an active call** (`GroupCallActiveOut`). VERDICT: Verified. SOURCE: OpenAPI `GET /ui/calls/group/active/{conversation_id}`; `src/api/types.ts: GroupCallActiveOut`; `groupCalls.ts: getActiveGroupCall`.
6. **`POST /ui/calls/group/{call_id}/join` returns 200 `GroupCallJoinOut {call_id, state, mode, current_participant_count, participants, signaling}`** (not 204, no `participant_id`). VERDICT: Corrected. SOURCE: OpenAPI `POST .../join` (resp 200); `src/api/types.ts: GroupCallJoinOut`.
7. **ICE servers are nested under `signaling.ice_servers` (`GroupCallSignalingInfo`), objects `{urls, username, credential}` — not a top-level `ice_servers`.** VERDICT: Corrected. SOURCE: `src/api/types.ts: GroupCallSignalingInfo`; schema `TurnIceServerOut`.
8. **`POST .../leave` returns 200 `GroupCallLeaveOut {ok, call_ended, remaining_participants}`** (not 204). VERDICT: Corrected. SOURCE: OpenAPI `POST .../leave` (resp 200); `src/api/types.ts: GroupCallLeaveOut`.
9. **`end_on_host_leave` field does not exist; host-leave teardown is conveyed by `call_ended`. Creator ends for all via `POST .../end` (`GroupCallEndOut`).** VERDICT: Corrected. SOURCE: schemas/`types.ts` (no such field); OpenAPI `POST .../end`; `GroupCallEndOut`.
10. **Mute/camera propagation is `PATCH /ui/calls/group/{call_id}/media` with `{audio?, video?, screen?}` → `GroupCallMediaUpdateOut {ok, media_status}` — not a `participant_state` signaling message.** VERDICT: Corrected. SOURCE: OpenAPI `PATCH .../media`, `GroupCallMediaUpdateIn`; `src/api/types.ts: GroupCallMediaUpdateOut`/`GroupCallMediaStatus`; `groupCalls.ts: updateGroupCallMedia`.
11. **Signaling relay `POST .../signal` body `GroupCallSignalIn {type, target_user_id, payload}` → `GroupCallSignalOut {ok, relayed_to}`. Targeting is by `target_user_id`, not `target_participant_id`.** VERDICT: Corrected. SOURCE: schema `GroupCallSignalIn`; OpenAPI `POST .../signal`; `groupCalls.ts: sendGroupCallSignal`; `src/api/types.ts: GroupCallSignalOut`.
12. **Participants are identified by `user_id`; `GroupCallParticipant` has no `participant_id`/`is_host`/`mic_muted`/`camera_off`. Fields are `{user_id, display_name, joined_at, left_at, media_status, connection_quality, state}`. Host = `user_id == GroupCallOut.creator_user_id`.** VERDICT: Corrected. SOURCE: `src/api/types.ts: GroupCallParticipant`, `GroupCallOut`.
13. **`GET /ui/calls/group/{call_id}` (`GroupCallOut`) and `GET .../participants` (`GroupCallParticipantsOut {participants, total_active, total_joined}`) are the resync sources.** VERDICT: Verified. SOURCE: OpenAPI `GET .../` and `GET .../participants`; `src/api/types.ts`.
14. **Auth/CSRF: cookie session + `X-CSRF-Token` read from the `ui_csrf` cookie, `credentials: include`.** VERDICT: Verified. SOURCE: `src/api/client.ts` (lines ~167–170, 183).
15. **401 → single shared `POST /ui/session/refresh` then one retry.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`refreshPromise`, `refreshSession`, lines ~119–220).
16. **Group endpoints declare only `200/201` success + `422 HTTPValidationError`; rich error envelopes (`CallSignalingErrorOut`, `ErrorEnvelope`) belong to the separate 1:1 `/messaging/messages/calls/*` paths, not the group paths.** VERDICT: Verified. SOURCE: OpenAPI index lines 1288–1297 vs 399–407.
17. **`max_participants` hard cap is 8 (mesh ceiling aligns with the spec's "best-effort >6").** VERDICT: Verified. SOURCE: schema `GroupCallCreateIn` (`maximum: 8`).
18. **TURN credential refresh endpoint `POST /messaging/messages/calls/{call_id}/turn-credentials` → `TurnCredentialsOut {ttl_seconds, expires_at, ice_servers}`.** VERDICT: Verified (exists). SOURCE: OpenAPI index line 407; schema `TurnCredentialsOut`.
19. **Compose mesh / `WebRtcEngine` / `MeshConnectionManager` / `LazyVerticalGrid` keyed-tile design and stack choices (Kotlin 2.0.21, Compose M3, Hilt, Retrofit/OkHttp/Moshi, Media3).** VERDICT: Unverified-assumption (Android client design, not constrained by backend). SOURCE: framework ref — Jetpack Compose lazy grids (developer.android.com/jetpack/compose/lists), WebRTC Android (webrtc.github.io). Carried over from AND-298/upstream tickets, not independently verified here.
20. **Participant `state` / `connection_quality` enum string values (e.g. "ringing", "connected", "good").** VERDICT: Unverified-assumption. SOURCE: `src/api/types.ts` types them as bare `string` (no enum); the example values in §5 are illustrative — map unknown values to `Unknown`.

### Corrections made

- Start endpoint `POST /ui/calls/group` → `POST /ui/calls/group/create`; request body `{invitee_user_ids, video}` → `{conversation_id, mode, max_participants}` (FR-1, §5, AC-2).
- Removed non-existent `POST .../invite` and `POST .../decline` endpoints; reworked FR-2/FR-3 to conversation-scoped join + local decline.
- `/join`, `/leave`, `/end` return **200 with bodies**, not 204; documented `GroupCallJoinOut`/`GroupCallLeaveOut`/`GroupCallEndOut` shapes (§5, FR-8).
- ICE servers moved from top-level `ice_servers` to nested `signaling.ice_servers` (§5, §8).
- Removed fabricated fields: `participant_id`, `host_user_id`, `is_host`, `mic_muted`, `camera_off`, `end_on_host_leave`; keying changed to `user_id`; host derived from `creator_user_id` (§4, §5, §6, AC-3).
- Mute/camera propagation reclassified from a `participant_state` signal to `PATCH .../media` (FR-9, §4).
- Signaling target key `target_participant_id` → `target_user_id` (§4, §5).
- Corrected/expanded §5 Retrofit interface to the verified 9 endpoints (added `/participants`, `/active`, `/end`, `/media`; removed `/invite`, `/decline`).
- §13 "exact API shape" open question marked resolved; §7 error-status assumptions flagged explicitly.

### Open assumptions

- **Participant `state` / `connection_quality` values** — typed as bare `string` in the frontend, no enum in OpenAPI. Why unverifiable: backend does not constrain them; defensively map unknowns to `Unknown`.
- **HTTP status codes for semantic errors** (CallFull / Forbidden / NotFound) — group endpoints only declare 200/201 + 422. Why unverifiable: actual 4xx behavior isn't in the schema; must be confirmed against a live backend or by reading server code.
- **Dev backend TURN (vs STUN-only) credentials** — schema supports TURN creds but whether the *dev* host issues working TURN is unknown. Why unverifiable: requires a live call against the dev/staging host.
- **AND-293/295 realtime channel routing (targeted per-user vs broadcast)** — not in OpenAPI (it's a socket/SSE concern). Why unverifiable: depends on the realtime layer delivered by the dependency tickets.
- **`avatarUrl` for participant tiles** — not present in `GroupCallParticipant`; assumed resolved via a separate profile lookup. Why unverifiable: no group-call field carries it.
- **Android client design choices** (mesh manager, Compose grid, library versions) — framework/design decisions, not backend-constrained; inherited from AND-298 and not re-derived here.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (no device); **emu35** = headless emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Hardware-dependent media/permission cases PREFER the physical device.

- **TC-AND-299-01** — Type: unit (JVM). Target: `reduce(state, event)` reducer. Preconditions: empty `GroupCallUiState` after `create` returns `GroupCallOut` with creator only. Steps: feed two `participant_joined` events then two `state=connected` updates (keyed by `user_id`). Expected: `participants.size == 3`, all keyed by distinct `user_id`, sorted by `joined_at`; `phase == Active`; `participants.count { it.state == Connected } >= 3`. Traces: AC-1, AC-2.
- **TC-AND-299-02** — Type: unit (JVM). Target: `reduce` idempotency. Preconditions: roster with `user_id=u_1` present. Steps: feed a duplicate `participant_joined` for `u_1`. Expected: no-op (no duplicate tile, list unchanged). Traces: AC-6.
- **TC-AND-299-03** — Type: contract/MockWebServer (JVM). Target: `GroupCallApi.create` + repository mapping. Preconditions: MockWebServer enqueues **201** `GroupCallOut` fixture (real shape: `creator_user_id`, `participants[].media_status`, `signaling.ice_servers`). Steps: call `create(conversation_id="conv_1", mode="video")`; assert request path `ui/calls/group/create`, body `{conversation_id, mode, max_participants}`, `X-CSRF-Token` header present. Expected: parsed DTO has `call_id`, host = `creator_user_id`, ICE from `signaling.ice_servers`; no `invitee_user_ids`/`participant_id` fields. Traces: AC-2.
- **TC-AND-299-04** — Type: contract/MockWebServer (JVM). Target: `join` → `GroupCallJoinOut`. Preconditions: enqueue **200** `GroupCallJoinOut` with `signaling.ice_servers=[{urls,username,credential}]`. Steps: call `join(callId)`. Expected: ICE servers read from `signaling.ice_servers` (nested), `current_participant_count` parsed; path is `ui/calls/group/{id}/join` POST. Traces: AC-1, AC-7.
- **TC-AND-299-05** — Type: contract/MockWebServer (JVM). Target: `media` PATCH. Preconditions: enqueue **200** `GroupCallMediaUpdateOut {ok, media_status}`. Steps: `toggleMute()` → `media(callId, {audio=false})`. Expected: PATCH `ui/calls/group/{id}/media`, body has `audio:false`; returned `media_status.audio==false` reflected on self tile; no `/signal` `participant_state` message emitted. Traces: AC-4.
- **TC-AND-299-06** — Type: contract/MockWebServer (JVM). Target: `signal` POST. Preconditions: enqueue **200** `GroupCallSignalOut {ok, relayed_to}`. Steps: send an SDP offer for peer `u_2`. Expected: body `{type:"sdp_offer", target_user_id:"u_2", payload:{...}}` (key is `target_user_id`, not `target_participant_id`); `relayed_to` parsed. Traces: AC-1.
- **TC-AND-299-07** — Type: contract/MockWebServer (JVM). Target: error mapping. Preconditions: enqueue **401** then a successful `/ui/session/refresh`, then a 200 on retry; separately enqueue **422 HTTPValidationError** and a 404 on `GET .../{id}` resync. Steps: trigger a join under 401; trigger a resync GET that 404s. Expected: exactly one `/ui/session/refresh` + single retry on 401; 404 → `phase == Ended`; 422 `detail` mapped to `CallError`. Traces: AC-7.
- **TC-AND-299-08** — Type: unit (JVM). Target: glare/initiator selection. Preconditions: local `userId="u_b"`, peers `u_a`, `u_c`. Steps: compute initiator per pair. Expected: deterministic by lexicographic `userId` (initiator for u_a/u_b = u_a; for u_b/u_c = u_b). Traces: AC-1.
- **TC-AND-299-09** — Type: unit (JVM, fake `WebRtcEngine`). Target: `MeshConnectionManager`. Steps: `addPeer` x3, then `removePeer(u_2)`. Expected: local mic/camera tracks added to **every** `PeerConnection`; `removePeer` closes only `u_2`; others remain `Connected`; one peer transitioning to `Failed` (ICE failure injected, 3 bounded retries 2/4/8s) leaves the other two `Connected`. Traces: AC-1, AC-5.
- **TC-AND-299-10** — Type: Compose-UI (emu35). Target: `ParticipantGrid` adaptive layout + keyed recomposition. Preconditions: provide rosters of 2, 4, 6 participants. Steps: render each; add a 5th tile to the 4-roster while observing a recomposition counter. Expected: cell counts match (2→stacked, 4→2x2, 6→3x2); adding a tile recomposes only the new tile (keyed by `user_id`), unaffected tiles' counters unchanged. Traces: AC-6, AC-8.
- **TC-AND-299-11** — Type: Compose-UI / accessibility (emu35). Target: tile semantics + roster LiveRegion. Steps: render a tile with name="Ada", muted, poor quality; enable semantics; simulate a join. Expected: every control/indicator has a `contentDescription` ("Ada, muted, poor connection"); active-speaker highlight has a non-color semantic cue; roster `LiveRegion` announces "Ada joined"; touch targets >= 48dp; participant count uses `<plurals>`. Traces: AC-6, AC-8.
- **TC-AND-299-12** — Type: instrumented/security (A15 — physical device required). Target: runtime permission gating. Preconditions: `RECORD_AUDIO`/`CAMERA` not yet granted. Steps: tap "Group call"; deny camera, grant mic. Expected: start blocked with rationale when permissions missing; with mic-only granted, audio-mode call proceeds and camera capture stays off; foreground-service types (`microphone`,`camera`) declared; no SDP/CSRF/cookies in logcat. MUST run on A15 (real camera/mic + Credential/permission behavior). Traces: AC-4.
- **TC-AND-299-13** — Type: integration / offline+flaky-host (emu35, dev backend). Target: resync + reconnect resilience. Steps: join a call; toggle airplane mode ~10s then restore; separately point at the unreliable dev host and force a GET timeout. Expected: "Reconnecting…" banner shows; on restore a full `GET /ui/calls/group/{call_id}` resync runs (≤20s timeout + bounded backoff) and diverged peers renegotiate; mutations are NOT auto-retried (manual inline retry offered); offline >60s ends the call locally. Traces: AC-5, AC-7.
- **TC-AND-299-14** — Type: instrumented/e2e (A15 + emu35 + one more emulator/device — physical device required for the acceptance demo). Target: full 3-party connect (literal acceptance test). Preconditions: 3 conversation members, working STUN/TURN. Steps: A15 host calls `create`; two others `join`; verify each pair. Expected: `GroupCallUiState.phase == Active` with ≥3 `Connected`, bidirectional audio/video across **all** pairs; leave on one continues call for others; creator `/end` or `call_ended` tears down all; telemetry `peak_participants >= 3`. MUST include the A15 (real arm64 media/WebRTC audio+video, API-34 vs emulator API-35 ABI differences). Traces: AC-1, AC-3, AC-4.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (3+ connect) | TC-01, TC-04, TC-06, TC-08, TC-09, TC-14 |
| AC-2 (create + tiles) | TC-01, TC-03 |
| AC-3 (leave/end teardown) | TC-14 |
| AC-4 (local controls propagate) | TC-05, TC-12, TC-14 |
| AC-5 (per-peer failure isolation) | TC-09, TC-13 |
| AC-6 (≤2s roster, keyed recompose) | TC-02, TC-10, TC-11 |
| AC-7 (401 refresh / 404 end) | TC-04, TC-07, TC-13 |
| AC-8 (adaptive grid + active speaker) | TC-10, TC-11 |
