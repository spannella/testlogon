---
id: AND-290
title: Signaling transport
milestone: M7
epic: E39
priority: P0
size: L
status: draft
depends_on: [AND-289, AND-143]
blocks: [AND-291]
---

# AND-290 — Signaling transport

## 1. Overview & Goal

This ticket delivers the **signaling transport layer** that carries WebRTC
session-establishment messages (SDP offer/answer and trickled ICE candidates)
between two peers via the TestLogon FastAPI backend. WebRTC media flows
peer-to-peer, but the initial negotiation must traverse a third party; the
backend is that third party. AND-290 owns *only the transport* — the reliable,
ordered, authenticated movement of opaque signaling envelopes in and out of the
app. It does **not** own the `PeerConnection` that produces/consumes those
envelopes (AND-289) nor the TURN/STUN credential fetch (AND-291).

Concretely, the deliverable is a `SignalingClient` that:

- Sends locally-produced signaling messages to the backend with `POST /signal`.
- Receives remotely-produced signaling messages addressed to this peer, via a
  server-pushed **SSE** stream with a **long-poll fallback** when SSE is
  unavailable or repeatedly drops.
- Exposes inbound messages as a cold `Flow<SignalingEnvelope>` and a
  hot connection-state `StateFlow<SignalingState>`.
- Is session-scoped, cookie-authenticated, CSRF-aware, and survives transient
  network loss with bounded reconnect/backoff.

**Definition of success:** two devices (or one device + the web reference app)
join the same signaling room and reliably exchange an offer, an answer, and a
burst of ICE candidates through the backend, verified in a staged end-to-end
run and in instrumented MockWebServer tests.

## 2. Context & References

- **Module:** new `core-signaling` module (layer: `core-*`), consumed by
  `feature-call` (the WebRTC feature module) and by AND-289's
  `PeerConnectionWrapper`. Depends on `core-network`, `core-model`, `core-data`.
- **AND-289 (PeerConnection wrapper + lifecycle, dep):** produces
  `SessionDescription` (offer/answer) and `IceCandidate` objects and consumes
  remote ones. AND-290 serializes/deserializes the *wire form* of these but
  treats the SDP/ICE payloads as opaque strings — no SDP parsing here.
- **AND-143 (SSE client core, dep):** provides the reusable
  `SseClient`/`EventSource` wrapper (OkHttp `EventSources.createFactory`,
  lifecycle-aware, auth cookies attached, reconnect/backoff, `Flow<SseEvent>`).
  AND-290 builds the `/signal/events` consumer on top of it rather than
  re-implementing SSE plumbing.
- **AND-291 (TURN/STUN credentials, blocked by this):** consumes the established
  session but is independent of transport; listed as `blocks` because the call
  feature wires both together.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json` — the exact `/signal`
  schema MUST be reconciled against `/openapi.json` during implementation (see
  §5 and §13). Web reference: `frontend/src/api/endpoints/*.ts`,
  `frontend/src/api/types.ts`.
- **Auth:** cookie-based session (AND-009 chain); persistent cookie jar with
  `ui_csrf` echoed as `X-CSRF-Token`; single `POST /ui/session/refresh` on 401
  then retry. AND-290 reuses the shared authenticated OkHttp client so SSE and
  POST both ride the existing session.

## 3. Functional Requirements

FR-1 **Join/leave a signaling room.** The client opens a transport bound to a
`roomId` (a.k.a. `session_id`/`call_id`) and a `peerId` (this device's stable
id within the room). Opening starts inbound delivery; closing tears it down and
releases the SSE/poll resource.

FR-2 **Send signaling.** `send(envelope)` transmits one envelope (offer,
answer, ICE candidate, or control such as `bye`) to the backend addressed to
the room. Sends are **fire-and-confirmed**: the call suspends until the backend
acknowledges (2xx) or fails.

FR-3 **Receive signaling.** Inbound envelopes addressed to this peer are
emitted in arrival order on `incoming: Flow<SignalingEnvelope>`. The client
MUST NOT echo this peer's own sent messages back to it (filter by `from`).

FR-4 **Real-time push with fallback.** Inbound delivery uses SSE
(`GET /signal/events`). If the SSE handshake fails or the stream drops more than
`SSE_FAILURE_THRESHOLD` (default 3) times within a window, the client degrades
to long-poll (`GET /signal/poll`) transparently; `SignalingState` reflects the
active transport. The client periodically attempts to re-upgrade to SSE.

FR-5 **Ordering & idempotency.** Each envelope carries a monotonically
increasing `seq` (per-sender) and a `messageId` (UUID). The receiver
de-duplicates by `messageId` and surfaces a gap-detected warning if `seq` skips,
but does not block delivery (ICE is order-tolerant; SDP is single-shot).

FR-6 **Connection state.** `state: StateFlow<SignalingState>` exposes
`Idle | Connecting | Connected(transport) | Degraded(transport) |
Reconnecting(attempt) | Closed | Error(cause)`.

FR-7 **Lifecycle binding.** The active stream is bound to a `CoroutineScope`
(the call's lifecycle scope) and the process lifecycle: it pauses on
`ON_STOP`/`ON_DESTROY` and resumes on `ON_START`, inheriting AND-143 behavior.

FR-8 **Resilience.** Transient failures (network loss, 5xx, stream EOF) trigger
bounded exponential backoff reconnect. A 401 triggers exactly one
`session/refresh` then one retry (delegated to the shared OkHttp authenticator).

## 4. Technical Design

New module `core-signaling`. Public API:

```kotlin
package com.testlogon.android.core.signaling

interface SignalingClient {
    /** Hot connection/transport state. */
    val state: StateFlow<SignalingState>

    /** Cold stream of inbound envelopes for the joined room (dedup'd, self filtered). */
    val incoming: Flow<SignalingEnvelope>

    /** Open transport for [roomId] as [peerId]; starts inbound delivery. */
    suspend fun open(roomId: String, peerId: String)

    /** Send one envelope to the room; suspends until backend ack or throws. */
    suspend fun send(envelope: SignalingEnvelope): ApiResult<Unit>

    /** Stop inbound delivery and release resources. Idempotent. */
    suspend fun close()
}

sealed interface SignalingState {
    data object Idle : SignalingState
    data object Connecting : SignalingState
    data class  Connected(val transport: Transport) : SignalingState
    data class  Degraded(val transport: Transport) : SignalingState
    data class  Reconnecting(val attempt: Int) : SignalingState
    data object Closed : SignalingState
    data class  Error(val cause: SignalingError) : SignalingState
    enum class Transport { SSE, POLL }
}
```

Domain model (in `core-model` so AND-289 can reference it without depending on
`core-signaling`):

```kotlin
@JsonClass(generateAdapter = true)
data class SignalingEnvelope(
    val messageId: String,                 // UUID, sender-generated
    val roomId: String,
    val from: String,                      // sender peerId
    val to: String?,                       // null = broadcast to room
    val seq: Long,                         // per-sender monotonic
    val type: SignalType,                  // OFFER | ANSWER | ICE | BYE
    val payload: SignalPayload,
    val sentAt: Long                       // epoch millis, client clock
)

enum class SignalType { OFFER, ANSWER, ICE, BYE }

@JsonClass(generateAdapter = true)
data class SignalPayload(
    val sdp: String? = null,               // for OFFER/ANSWER
    val sdpMid: String? = null,            // for ICE
    val sdpMLineIndex: Int? = null,        // for ICE
    val candidate: String? = null          // for ICE
)
```

Implementation `DefaultSignalingClient(@Assisted ...)` is built via a Hilt
`@AssistedFactory` (room/peer are runtime values). Internals:

- **Outbound:** `SignalingApi.postSignal(...)` (Retrofit/Moshi) over the shared
  authenticated OkHttp client. Sends are serialized through a `Mutex` so `seq`
  assignment is race-free per client instance.
- **Inbound (SSE path):** wraps AND-143's `SseClient`. Subscribes to
  `GET /signal/events?room={roomId}&peer={peerId}`, maps each named event
  `signal` data line (JSON) → `SignalingEnvelope`, drops malformed lines with a
  logged warning. Honors SSE `id:` for `Last-Event-ID` resume.
- **Inbound (poll path):** `pollLoop()` issues
  `GET /signal/poll?room=&peer=&after={lastSeq}&wait=20` with a 20s read
  timeout (matching backend long-poll); on 200 emits the batch and advances
  `after`; on 204/timeout re-issues immediately.
- **Transport selection** lives in a `TransportSupervisor` coroutine that owns
  the `state` `MutableStateFlow`, counts SSE failures, switches to POLL past the
  threshold, and schedules periodic SSE re-upgrade probes.
- **Dedup:** a bounded `LinkedHashSet<String>` (cap 512) of seen `messageId`s.

Threading: all stream work on `Dispatchers.IO` via the injected
`@Dispatcher(IO)` `CoroutineDispatcher`; `state`/`incoming` are collected on the
caller's dispatcher.

DI:

```kotlin
@Module @InstallIn(SingletonComponent::class)
abstract class SignalingModule {
    @Binds abstract fun bindApi(impl: RetrofitSignalingApi): SignalingApi
}

@AssistedFactory
interface SignalingClientFactory {
    fun create(/* injected deps via constructor */): DefaultSignalingClient
}
```

## 5. API Contract

> The backend `/signal` surface is **not yet confirmed against
> `/openapi.json`** (see §13, OQ-1). The shapes below are the contract this
> ticket targets; if `/openapi.json` differs, the Moshi DTOs and paths are the
> single point of change and acceptance is measured against the real schema.

**Send — `POST /signal`**

Request (auth cookies + `X-CSRF-Token` required):
```json
{
  "room_id": "call_abc123",
  "message": {
    "message_id": "9f1c…",
    "from": "peer-A",
    "to": "peer-B",
    "seq": 7,
    "type": "ICE",
    "payload": { "sdpMid": "0", "sdpMLineIndex": 0, "candidate": "candidate:…" },
    "sent_at": 1717603200000
  }
}
```
Response `200`: `{ "delivered": true, "message_id": "9f1c…" }`.
Errors: `401` (refresh+retry), `403` (CSRF), `404` (unknown room), `409`
(stale seq — treated as already-delivered), `422` FastAPI validation.

**Receive (SSE) — `GET /signal/events?room={roomId}&peer={peerId}`**

`Accept: text/event-stream`. Event frames:
```
id: 42
event: signal
data: {"message_id":"…","from":"peer-B","to":"peer-A","seq":3,"type":"OFFER","payload":{"sdp":"v=0…"},"sent_at":…}

event: ping
data: {}
```
`ping` keep-alives are ignored (used by AND-143 to detect liveness).

**Receive (poll) — `GET /signal/poll?room={roomId}&peer={peerId}&after={seq}&wait=20`**

Response `200`: `{ "messages": [ <message>, … ], "last_seq": 9 }`;
`204` when nothing arrives within `wait` seconds.

**Error envelope:** FastAPI `detail` mapped via the shared decoder
(`string | [{msg}] | {code,...}`) into `SignalingError`.

## 6. Data & State Management

- **No Room persistence.** Signaling is ephemeral and session-bound; envelopes
  are never written to the `core-data` Room cache. The only persisted artifact
  is the **cookie jar** (already provided by `core-network`/DataStore), reused so
  the SSE and POST share the live session.
- **In-memory only:** dedup set, per-sender `seq` counter (outbound), `lastSeq`
  high-water mark (inbound poll cursor), and `Last-Event-ID` for SSE resume.
- **State exposure:** `SignalingState` via `StateFlow` (conflated, replay-1);
  `incoming` is a `SharedFlow` with `replay=0`, `extraBufferCapacity=64`, and
  `BufferOverflow.DROP_OLDEST` only as a last resort (a dropped ICE candidate is
  recoverable; a dropped SDP is fatal, so SDP types bypass the lossy path by
  using `emit` with suspension on a separate priority channel — see §7).
- ViewModels in `feature-call` collect `state` and `incoming` and feed AND-289's
  wrapper; AND-290 itself holds no UI state.

## 7. Error Handling & Resilience

- **Timeouts:** 20s read/connect timeouts for POST and poll (matches the
  unreliable dev host). SSE uses AND-143's read timeout tuned to be longer than
  the server `ping` interval.
- **Backoff:** reconnect uses exponential backoff with full jitter —
  `min(BASE * 2^n, MAX)` with `BASE=500ms`, `MAX=15s`, randomized; attempt count
  surfaced as `Reconnecting(attempt)`. **Retries apply to idempotent GETs only**
  (the SSE/poll inbound side). `POST /signal` is retried at most once and only on
  connection-level failures (not on a received 4xx/5xx body), because
  re-sending could duplicate — duplicates are tolerated by `messageId` dedup but
  we still avoid amplification.
- **Auth:** 401 handled by the shared OkHttp `Authenticator` (single
  `POST /ui/session/refresh` then retry); if refresh fails →
  `Error(SignalingError.AuthExpired)` and `state = Error`.
- **SSE→POLL degrade:** after `SSE_FAILURE_THRESHOLD` drops in a 60s window,
  switch to POLL, set `Degraded(POLL)`, and schedule SSE re-probe every 30s.
- **Backpressure / SDP safety:** OFFER/ANSWER/BYE are delivered on a
  non-lossy path; only ICE may be dropped under extreme buffer pressure, and a
  drop emits a `SignalingError.IceDropped` telemetry warning (call can still
  succeed via remaining candidates / TURN relay from AND-291).
- **Malformed frames:** logged and skipped, never crash the stream.

```kotlin
sealed interface SignalingError {
    data object AuthExpired : SignalingError
    data object RoomNotFound : SignalingError
    data class  Transport(val httpCode: Int?) : SignalingError
    data class  Decode(val raw: String) : SignalingError
    data object IceDropped : SignalingError
}
```

## 8. Security & Privacy

- **Transport secrecy (dev caveat):** the dev backend is **plaintext HTTP**, so
  signaling (including SDP, which exposes local/host IP candidates) is
  unencrypted on dev. This is acceptable only for dev/staging; production MUST be
  HTTPS. Cleartext is gated to the dev host via a scoped
  `network_security_config.xml` `cleartextTrafficPermitted` domain entry, not a
  global allow.
- **Auth:** all `/signal*` calls carry the session cookies and `X-CSRF-Token`
  (mutating `POST` requires CSRF). No bearer tokens, no app-stored secrets.
- **Authorization:** the backend enforces that `peer`/`from` belongs to the
  caller's session and room; the client never trusts `to`/`from` for security,
  only for routing/filtering.
- **PII:** SDP/ICE contain network topology (IPs) but no user PII; envelopes are
  not logged at full payload level (see §10 redaction). Nothing is persisted to
  disk.
- **CSRF/XSS-equivalent:** inbound `data:` JSON is parsed with Moshi into typed
  DTOs only; no `eval`-style handling.

## 9. Accessibility & i18n

No direct UI surface — this is a transport library, so traditional a11y
(TalkBack, focus order, touch targets) is **N/A here** and owned by the call UI
ticket in `feature-call`. i18n scope is limited to user-surfaced *error/status
strings* that the client emits for the UI to render (e.g.
"Reconnecting…", "Connection lost"). These MUST be exposed as
**string resource keys** (`R.string.signaling_state_reconnecting`, etc.) defined
in `core-ui`/`feature-call`, never as hard-coded English in `core-signaling`.
`SignalingState` is a typed enum precisely so the UI layer maps to localized,
RTL-safe strings.

## 10. Telemetry & Logging

- **Events** (via the shared analytics/`Logger` interface in `core-*`):
  `signaling_open{roomId, transport}`,
  `signaling_send{type, seq, latencyMs, result}`,
  `signaling_recv{type, seq, gap:Boolean}`,
  `signaling_transport_switch{from, to, reason}`,
  `signaling_reconnect{attempt, backoffMs}`,
  `signaling_error{code, httpCode}`,
  `signaling_close{durationMs, sent, received}`.
- **Redaction:** never log `payload.sdp` or `payload.candidate` contents; log
  only `type`, `seq`, `messageId`, and lengths. `roomId`/`peerId` logged as
  short ids.
- **Levels:** state transitions at `DEBUG`, degrade/reconnect at `INFO`,
  auth/transport failures at `WARN`/`ERROR`. No logging in release of raw
  frames.

## 11. Testing Strategy

**Unit / instrumented (MockWebServer, `core-testing`):**

- T-1 `send()` issues `POST /signal` with correct body, cookies, and
  `X-CSRF-Token`; maps `200` → `ApiResult.Success`.
- T-2 SSE happy path: MockWebServer streams two `signal` events → `incoming`
  emits two correctly-typed envelopes in order; `ping` frames ignored.
- T-3 **Self-filter:** an inbound frame with `from == peerId` is not emitted.
- T-4 **Dedup:** duplicate `messageId` emitted once; gap in `seq` sets the
  `gap` telemetry flag but still delivers.
- T-5 **Reconnect:** server closes the SSE stream → client reconnects with
  backoff (assert `Reconnecting(attempt)` sequence) and resumes via
  `Last-Event-ID`. (Reuses AND-143's MockWebServer reconnect harness.)
- T-6 **Degrade:** force `SSE_FAILURE_THRESHOLD` SSE failures → state becomes
  `Degraded(POLL)` and poll requests begin with advancing `after` cursor.
- T-7 **401 path:** first SSE/POST returns `401`, refresh stub returns `200`,
  request retried once and succeeds; refresh failure → `Error(AuthExpired)`.
- T-8 Malformed `data:` line is skipped without terminating the stream.

**End-to-end / staged (acceptance):**

- E-1 Two emulator instances (or one emulator + `frontend/` web app) join room
  `call_test`; peer A's offer reaches B, B's answer reaches A, and a burst of
  ICE candidates is exchanged bidirectionally through the staged backend.
  Verified by AND-289's harness consuming AND-290's `incoming`.

Coverage gate: ≥ 80% line coverage on `core-signaling` non-DI code.

## 12. Dependencies & Sequencing

- **AND-289 (PeerConnection wrapper):** hard dep — provides the SDP/ICE
  producers/consumers and the test harness for E-1. AND-290 can be built against
  a stub wrapper but cannot be *accepted* without it.
- **AND-143 (SSE client core):** hard dep — AND-290 reuses its `SseClient`,
  reconnect/backoff, lifecycle binding, and cookie attachment. Do not duplicate
  SSE logic.
- **Implicitly:** the cookie-auth/CSRF/refresh chain (AND-009 family) via
  `core-network` must be in place.
- **Blocks AND-291 (TURN/STUN):** the call feature wires the established
  signaling session and the TURN credentials together; sequence AND-290 →
  AND-291 → call UI.
- Recommended order: confirm `/openapi.json` `/signal` schema → DTOs/`SignalingApi`
  → outbound `send` → SSE inbound (on AND-143) → poll fallback + supervisor →
  E-1 staged run.

## 13. Risks & Open Questions

- **OQ-1 (highest):** Does the backend actually expose `/signal`,
  `/signal/events` (SSE), and `/signal/poll`? The exact paths, query params, and
  body schema MUST be confirmed against `/openapi.json` and
  `frontend/src/api/endpoints/*.ts`. If the web app uses a different mechanism
  (e.g. a single WebSocket or a different route), the transport impl changes
  while the public `SignalingClient` API stays stable. **Resolve before coding
  DTOs.**
- **OQ-2:** Does the backend long-poll honor a `wait`/`after` cursor, and does
  SSE honor `Last-Event-ID`? Determines resume strategy; fall back to
  full re-fetch with client dedup if not.
- **R-1:** Dev host unreliability may make E-1 flaky; mitigate by also proving
  exchange against MockWebServer (T-2/T-5) and treating staged E-1 as the
  confirmatory, not sole, gate.
- **R-2:** SDP candidate loss under buffer pressure could break calls; mitigated
  by the non-lossy SDP path (§7) and TURN relay (AND-291).
- **R-3:** Plaintext signaling on dev exposes IPs; acceptable for dev only,
  flagged for production HTTPS hardening.

## 14. Acceptance Criteria

- AC-1 Two peers exchange signaling via the backend in a staged run: an
  `OFFER`, an `ANSWER`, and ≥1 `ICE` candidate each direction are delivered and
  consumed (maps to source acceptance "Two peers exchange signaling via backend
  (tested/staged)", E-1).
- AC-2 `SignalingClient.send()` posts to `POST /signal` with session cookies and
  `X-CSRF-Token`, returning `ApiResult.Success` on `200` (T-1).
- AC-3 `incoming` emits inbound envelopes in arrival order, deduped by
  `messageId`, with the peer's own messages filtered out (T-2, T-3, T-4).
- AC-4 SSE drop triggers bounded backoff reconnect with `Last-Event-ID` resume;
  state transitions are observable on `state` (T-5).
- AC-5 After the SSE failure threshold, the client degrades to long-poll and
  continues delivering messages, then re-probes SSE (T-6).
- AC-6 A `401` triggers exactly one `session/refresh` + retry; failure surfaces
  `Error(AuthExpired)` (T-7).
- AC-7 Malformed frames are skipped without terminating the stream (T-8).
- AC-8 No signaling payloads are persisted to disk; SDP/candidate contents are
  never logged (§6, §10 verified by inspection/test).

## 15. Definition of Done

- `core-signaling` module created under `com.testlogon.android.core.signaling`,
  building on Kotlin 2.0.21 / AGP 8.7.3 / Gradle 8.9, with Hilt+KSP wiring and
  module layering respected (`core-signaling` → `core-network/model/data`).
- `SignalingClient`, `SignalingState`, `SignalingError`, `SignalingEnvelope`
  (+ Moshi adapters) implemented; DTO paths/shapes reconciled with
  `/openapi.json` (OQ-1 resolved and recorded in the PR).
- All §11 unit/instrumented tests green; ≥80% coverage on non-DI code; staged
  E-1 exchange demonstrated and captured (log/recording linked in PR).
- Telemetry events emitted with redaction; cleartext scoped to the dev host
  only in `network_security_config.xml`.
- User-facing status/error strings exposed as resource keys for the call UI to
  localize.
- Code review approved on branch `android-port`; no new lint/Detekt errors;
  public API KDoc'd; AND-291 unblocked.
