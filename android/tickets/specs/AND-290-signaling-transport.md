---
id: AND-290
title: Signaling transport
milestone: M7
epic: E39
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
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

- Sends locally-produced signaling messages to the backend with
  `POST /messaging/messages/calls/{call_id}/signal`. **(Corrected: the spec
  previously claimed `POST /signal`, which does not exist in `/openapi.json`.
  Verified: openapi index `POST /messaging/messages/calls/{call_id}/signal`,
  schema `CallSignalingIn`; frontend `src/api/endpoints/messaging.ts:
  sendSignalingEvent`.)**
- Receives remotely-produced signaling messages addressed to this peer, via the
  **shared messaging SSE stream** `GET /messaging/events/stream`, on which the
  backend multiplexes `webrtc.offer` / `webrtc.answer` /
  `webrtc.ice_candidate` events alongside all other messaging events. There is
  **no dedicated `/signal/events` SSE endpoint and no separate `/signal/poll`
  endpoint** (both were unverified assumptions in earlier drafts and are
  removed). A poll-style fallback, if needed, is built on the **same**
  `GET /messaging/events/stream` using its `after` / `poll_ms` query params.
  **(Verified: openapi index `GET /messaging/events/stream | params=after,limit,
  poll_ms,x_request_id,authorization,X-SESSION-ID`; frontend
  `src/hooks/useMessagingStream.ts`.)**
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
  AND-290 builds the `GET /messaging/events/stream` consumer on top of it
  rather than re-implementing SSE plumbing, and filters the multiplexed stream
  for `webrtc.*` event types. **(Corrected: previously said `/signal/events`,
  which does not exist.)**
- **AND-291 (TURN/STUN credentials, blocked by this):** consumes the established
  session but is independent of transport; listed as `blocks` because the call
  feature wires both together.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json` — the signaling
  surface has now been reconciled (see §5, §13, §16): the real send endpoint is
  `POST /messaging/messages/calls/{call_id}/signal` (`CallSignalingIn` →
  `CallSignalingOut`) and the real inbound channel is the shared SSE
  `GET /messaging/events/stream`. Web reference:
  `frontend/src/api/endpoints/messaging.ts` (`sendSignalingEvent`,
  `fetchTurnCredentials`), `frontend/src/hooks/useMessagingStream.ts` (SSE),
  `frontend/src/hooks/useRtcPeerConnection.ts` (consumer/glare/ICE-restart).
- **Auth:** cookie-based session (AND-009 chain); persistent cookie jar with
  `ui_csrf` echoed as `X-CSRF-Token`; single `POST /ui/session/refresh` on 401
  then retry. AND-290 reuses the shared authenticated OkHttp client so SSE and
  POST both ride the existing session.

## 3. Functional Requirements

FR-1 **Join/leave a signaling session.** The client opens a transport bound to
a `callId` (path id used for `POST .../calls/{call_id}/signal`), a
`conversationId` (carried in the body as `conversation_id`), and the local and
remote user ids (`from` = caller's `user_id`; `to` = `recipient_user_id`).
**(Corrected: the backend keys signaling on `call_id` + `conversation_id` +
`recipient_user_id`, not on a generic `roomId`/`peerId`. Verified:
`CallSignalingIn` fields `conversation_id`, `recipient_user_id`; path param
`call_id`.)** Opening attaches to the shared messaging SSE stream and starts
inbound delivery; closing detaches and releases the resource.

FR-2 **Send signaling.** `send(envelope)` transmits one envelope (offer,
answer, ICE candidate, or control such as `bye`) to the backend addressed to
the room. Sends are **fire-and-confirmed**: the call suspends until the backend
acknowledges (2xx) or fails.

FR-3 **Receive signaling.** Inbound envelopes for this call are emitted in
arrival order on `incoming: Flow<SignalingEnvelope>`. The client MUST filter the
multiplexed SSE stream to `webrtc.*` events for the active `call_id`, and MUST
NOT echo this peer's own sent messages back to it. **(Corrected self-filter
key: the web client filters by `detail.sender_user_id === userId`, not by a
`from` field, and matches `detail.call_id`. Verified:
`src/hooks/useRtcPeerConnection.ts` lines ~276–278.)**

FR-4 **Real-time push with fallback.** Inbound delivery uses the shared
messaging SSE stream (`GET /messaging/events/stream`, EventSource semantics,
`withCredentials`). **(Corrected: not `GET /signal/events`.)** If the SSE
handshake fails or the stream drops more than `SSE_FAILURE_THRESHOLD`
(default 3) times within a window, the client degrades to a poll loop against
the **same** endpoint using its `after` / `poll_ms` query params
(`GET /messaging/events/stream?after={cursor}&poll_ms={ms}`); `SignalingState`
reflects the active transport. **(Corrected: there is no separate
`GET /signal/poll`; the long-poll fallback reuses `messaging/events/stream`'s
documented `after`/`poll_ms` params — verified in the openapi index.)** The
client periodically attempts to re-upgrade to streaming SSE. Note: the **web
reference does not implement a poll fallback** (SSE-only with exponential
reconnect), so the Android poll path is an Android-side enhancement, not a
mirrored web behavior.

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
    val candidate: String? = null,         // for ICE
    val usernameFragment: String? = null   // for ICE (web sends this; preserve it)
)
```

> **Wire-vs-domain mapping (verified against `CallSignalingIn` /
> `SignalingPayload` / `useRtcPeerConnection.ts`).** The domain
> `SignalingEnvelope` above is Android-internal. The DTO actually serialized to
> the backend is the flat `CallSignalingIn`:
> `type` is one of `webrtc.offer|webrtc.answer|webrtc.ice_candidate`
> (regex-enforced by the backend; `webrtc.screen_share_start/stop` also exist
> but are out of AND-290 scope), `event_id` (≤128, sender-generated), `nonce`
> (8–128 chars), `conversation_id` (≤128), `recipient_user_id` (≤128),
> `sent_at` (**integer epoch seconds** — the web client uses
> `Math.floor(Date.now()/1000)`, not millis), and `payload` (free-form object).
> For OFFER/ANSWER, `payload` = `{ sdp, type }`. For ICE, `payload` =
> `{ candidate, sdpMid, sdpMLineIndex, usernameFragment }`. **(Corrections:
> spec's `SignalType` enum values `OFFER/ANSWER/ICE/BYE` must serialize to the
> dotted wire strings; spec's `sent_at` epoch-**millis** is wrong (backend
> expects seconds); `BYE` has no `webrtc.*` wire type — call teardown uses
> `POST /messaging/messages/calls/{call_id}/end`, not a signaling envelope.)**

Implementation `DefaultSignalingClient(@Assisted ...)` is built via a Hilt
`@AssistedFactory` (room/peer are runtime values). Internals:

- **Outbound:** `SignalingApi.postSignal(callId, CallSignalingIn)` →
  `POST /messaging/messages/calls/{call_id}/signal` (Retrofit/Moshi) over the
  shared authenticated OkHttp client. The wire body is the flat `CallSignalingIn`
  shape: `{ type, event_id, conversation_id, recipient_user_id, nonce, sent_at,
  payload }` — **there is no `room_id`/`message` wrapper and no top-level `seq`
  or `from` on the wire.** **(Corrected against schema `CallSignalingIn`.)** Sends
  are serialized through a `Mutex` so the local `seq` counter (an Android-only
  ordering aid, not sent to the backend) is race-free per client instance.
- **Inbound (SSE path):** wraps AND-143's `SseClient`. Subscribes to
  `GET /messaging/events/stream` (no room/peer query params — the stream is
  per-session and multiplexed). The backend emits **named** SSE events; this
  client listens for `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate`
  (and ignores the other ~30 messaging event types), filters by
  `call_id == this.callId`, maps each event `data:` JSON → `SignalingEnvelope`,
  and drops malformed lines with a logged warning. **(Corrected from
  `GET /signal/events?room=&peer=` and from the assumption of a single
  `event: signal` frame type — the real stream uses per-type named events; see
  `useMessagingStream.ts` `EVENT_TYPES`.)** `Last-Event-ID`/`after` resume is
  used if the server honors it (see OQ-2).
- **Inbound (poll path):** `pollLoop()` issues
  `GET /messaging/events/stream?after={cursor}&poll_ms={ms}` with a read timeout
  ≥ `poll_ms`; on a non-empty response it emits the batch and advances the
  `after` cursor; on empty/timeout it re-issues immediately. **(Corrected from
  `GET /signal/poll?...&wait=20`; the real params are `after` and `poll_ms` on
  the shared stream endpoint.)**
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

> This contract has been **reconciled against `/openapi.json` and the web
> reference** (OQ-1 resolved; see §16). The shapes below are the real backend
> contract. Earlier drafts targeted a non-existent `/signal` surface; the
> corrected paths/shapes follow.

**Send — `POST /messaging/messages/calls/{call_id}/signal`**
(op `send_signaling_event`; req `CallSignalingIn`; resp `CallSignalingOut`).

Request (auth cookies + `X-CSRF-Token` required; `call_id` in the path):
```json
{
  "type": "webrtc.ice_candidate",
  "event_id": "ice-9f1c…",
  "conversation_id": "conv_abc123",
  "recipient_user_id": "user-B",
  "nonce": "a1b2c3d4e5",
  "sent_at": 1717603200,
  "payload": {
    "candidate": "candidate:…",
    "sdpMid": "0",
    "sdpMLineIndex": 0,
    "usernameFragment": "…"
  }
}
```
For OFFER/ANSWER, `type` is `webrtc.offer` / `webrtc.answer` and `payload` is
`{ "sdp": "v=0…", "type": "offer" }`. `sent_at` is **epoch seconds** (integer).
`type` is regex-constrained by the backend:
`^(webrtc\.offer|webrtc\.answer|webrtc\.ice_candidate|webrtc\.screen_share_start|webrtc\.screen_share_stop)$`.

Response `200` (`CallSignalingOut`):
```json
{
  "event_id": "ice-9f1c…",
  "call_id": "call_abc123",
  "conversation_id": "conv_abc123",
  "event_type": "webrtc.ice_candidate",
  "delivered_to": "user-B",
  "status": "delivered"
}
```
(`status` is `"delivered"` or `"duplicate"` per the web `SignalingAck` type.)
Errors return **`CallSignalingErrorOut`** = `{ "code": string, "message":
string }` at HTTP `400` (bad request/validation), `403` (not a participant /
CSRF), `404` (unknown call), `409` (conflict), `429` (rate limited), `503`
(transport unavailable); `422` is the standard FastAPI `HTTPValidationError`.
**(Corrected: earlier draft listed a `{delivered, message_id}` body and a
`401/403/404/409/422` set; the real success body is `CallSignalingOut` and the
real error body is `CallSignalingErrorOut` with the HTTP set above. `401` is
still handled by the shared refresh+retry authenticator even though it is not
enumerated in the OpenAPI responses for this op.)**

**Receive (SSE) — `GET /messaging/events/stream`**
(op `events_stream`; params `after, limit, poll_ms, x_request_id, authorization,
X-SESSION-ID`).

`Accept: text/event-stream`, EventSource semantics, cookies attached. The
backend emits **named** SSE events (not a single `event: signal` frame). The
relevant types for AND-290 are `webrtc.offer`, `webrtc.answer`,
`webrtc.ice_candidate` (the full multiplexed set includes ~30 `message:*`,
`call.*`, `presence:*`, etc. types — see `useMessagingStream.ts` `EVENT_TYPES`).
Example frame:
```
event: webrtc.offer
data: {"call_id":"call_abc123","conversation_id":"conv_abc123","sender_user_id":"user-B","event_type":"webrtc.offer","payload":{"sdp":"v=0…","type":"offer"}}
```
The client filters by `call_id == this.callId` and ignores its own events
(`sender_user_id == localUserId`). Heartbeat/comment lines and parse errors are
ignored. **(Corrected from `GET /signal/events?room=&peer=`, a single `signal`
event type, and `from`/`to`/`seq` inbound fields; the real inbound fields are
`call_id`, `conversation_id`, `sender_user_id`, `event_type`, `payload`.)**

**Receive (poll fallback) — `GET /messaging/events/stream?after={cursor}&poll_ms={ms}`**

Same endpoint; long-poll mode via `after`/`poll_ms`. Returns the batch of events
after the cursor (or empties on timeout). **(Corrected from `GET /signal/poll`;
the web client does not use a poll fallback at all — this is Android-only and
must be validated against the live backend, see OQ-2.)**

**Error envelope:** for `POST .../signal`, the typed `CallSignalingErrorOut`
`{code, message}` is decoded into `SignalingError`; for generic `422` and other
FastAPI `detail` shapes, the shared decoder (`string | [{msg}] | {code,...}`)
applies.

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

- T-1 `send()` issues `POST /messaging/messages/calls/{call_id}/signal` with the
  correct flat `CallSignalingIn` body, cookies, and `X-CSRF-Token`; maps
  `200` (`CallSignalingOut`) → `ApiResult.Success`.
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

- **OQ-1 — RESOLVED (this review).** The backend does **not** expose
  `/signal`, `/signal/events`, or `/signal/poll`. Send is
  `POST /messaging/messages/calls/{call_id}/signal` (`CallSignalingIn` →
  `CallSignalingOut`); inbound is the **shared multiplexed SSE**
  `GET /messaging/events/stream` filtered to `webrtc.*` events. The public
  `SignalingClient` API stays stable; the DTOs/paths above are corrected to
  match. (Verified: openapi index + `messaging.ts` + `useMessagingStream.ts` +
  `useRtcPeerConnection.ts`.)
- **OQ-2 (still open, partially answered):** `GET /messaging/events/stream`
  documents `after`, `limit`, `poll_ms` query params, so a long-poll fallback is
  feasible on the same endpoint. Whether the SSE side honors `Last-Event-ID` for
  resume is **not confirmed** from the OpenAPI (the web `EventSource` relies on
  browser-native `Last-Event-ID` and does not pass `after`). Determine empirically
  against the staged backend; fall back to `after`-cursor re-fetch with client
  dedup if `Last-Event-ID` is not honored.
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
- AC-2 `SignalingClient.send()` posts to
  `POST /messaging/messages/calls/{call_id}/signal` with session cookies and
  `X-CSRF-Token`, returning `ApiResult.Success` on `200` (`CallSignalingOut`)
  (T-1).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source.

1. **Send endpoint is `POST /signal`.** VERDICT: **Corrected** → real endpoint
   is `POST /messaging/messages/calls/{call_id}/signal`. SOURCE: OpenAPI
   `POST /messaging/messages/calls/{call_id}/signal` (op `send_signaling_event`);
   `src/api/endpoints/messaging.ts: sendSignalingEvent`.
2. **Send request body is `{room_id, message:{message_id, from, to, seq, type,
   payload, sent_at}}`.** VERDICT: **Corrected** → flat `CallSignalingIn`
   `{type, event_id, conversation_id, recipient_user_id, nonce, sent_at,
   payload}`; no wrapper, no `from`/`to`/`seq` on the wire. SOURCE: schema
   `CallSignalingIn`; `src/api/endpoints/messaging.ts: SignalingPayload`.
3. **`type` values are `OFFER|ANSWER|ICE|BYE`.** VERDICT: **Corrected** → wire
   values are `webrtc.offer|webrtc.answer|webrtc.ice_candidate`
   (+`webrtc.screen_share_start/stop`, out of scope); no `BYE` signaling type.
   SOURCE: `CallSignalingIn.type` regex; `src/hooks/useMessagingStream.ts`
   `EVENT_TYPES`; `src/api/endpoints/messaging.ts: SignalingPayload`.
4. **`sent_at` is epoch millis.** VERDICT: **Corrected** → epoch **seconds**
   (integer). SOURCE: `src/hooks/useRtcPeerConnection.ts`
   (`Math.floor(Date.now()/1000)`); `CallSignalingIn.sent_at: integer`.
5. **Send success response is `{delivered:true, message_id}`.** VERDICT:
   **Corrected** → `CallSignalingOut` `{event_id, call_id, conversation_id,
   event_type, delivered_to, status}` with `status ∈ {delivered, duplicate}`.
   SOURCE: schema `CallSignalingOut`; `src/api/endpoints/messaging.ts:
   SignalingAck`.
6. **Send error set is `401/403/404/409/422` with FastAPI `detail`.** VERDICT:
   **Corrected** → typed `CallSignalingErrorOut` `{code, message}` at
   `400/403/404/409/429/503`, plus `422 HTTPValidationError`. (`401` not in the
   op's OpenAPI responses but still handled by the shared authenticator.) SOURCE:
   OpenAPI resp list for `send_signaling_event`; schema `CallSignalingErrorOut`.
7. **Inbound is a dedicated SSE `GET /signal/events?room=&peer=` with a single
   `event: signal` frame type.** VERDICT: **Corrected** → inbound is the shared
   multiplexed SSE `GET /messaging/events/stream`, with per-type named events
   (`webrtc.offer`/`webrtc.answer`/`webrtc.ice_candidate` among ~30 types).
   SOURCE: OpenAPI `GET /messaging/events/stream` (op `events_stream`);
   `src/hooks/useMessagingStream.ts` (`MESSAGING_STREAM_URL`, `EVENT_TYPES`,
   `EventSource`).
8. **Inbound envelope fields are `from/to/seq`.** VERDICT: **Corrected** →
   inbound event detail carries `call_id`, `conversation_id`, `sender_user_id`,
   `event_type`, `payload`. SOURCE: `src/hooks/useRtcPeerConnection.ts`
   (`detail.call_id`, `detail.sender_user_id`, `detail.event_type`,
   `detail.payload`); `src/hooks/useMessagingStream.ts` dispatch of
   `messaging:webrtc-signal`.
9. **Self-filter is by `from == peerId`.** VERDICT: **Corrected** → web filters
   by `sender_user_id == userId` (and `call_id == callId`). SOURCE:
   `src/hooks/useRtcPeerConnection.ts` (signalingHandler).
10. **Poll fallback is `GET /signal/poll?...&wait=20` returning `{messages,
    last_seq}` / `204`.** VERDICT: **Corrected** → no such endpoint; long-poll, if
    used, is `GET /messaging/events/stream?after=&poll_ms=` on the same stream.
    Also note: the web client implements **no** poll fallback (SSE-only). SOURCE:
    OpenAPI `GET /messaging/events/stream | params=after,limit,poll_ms,…`;
    `src/hooks/useMessagingStream.ts` (no poll path).
11. **ICE payload fields `sdpMid, sdpMLineIndex, candidate`.** VERDICT:
    **Verified (and extended)** → also includes `usernameFragment`. SOURCE:
    `src/hooks/useRtcPeerConnection.ts` (onicecandidate / candidate handler).
12. **OFFER/ANSWER payload is `{sdp}`.** VERDICT: **Corrected** → payload is
    `{sdp, type}` (the SDP `type` string is sent alongside). SOURCE:
    `src/hooks/useRtcPeerConnection.ts` (offer/answer payloads).
13. **Auth: cookie session + `ui_csrf` echoed as `X-CSRF-Token` on mutating
    requests.** VERDICT: **Verified.** SOURCE: `src/api/client.ts`
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`,
    `credentials:"include"`).
14. **401 → single `POST /ui/session/refresh` then one retry.** VERDICT:
    **Verified.** SOURCE: `src/api/client.ts` (`refreshSession()` →
    `/ui/session/refresh`, single-flight `refreshPromise`, retry once, second 401
    throws).
15. **SSE uses cookie auth (`withCredentials`).** VERDICT: **Verified.** SOURCE:
    `src/hooks/useMessagingStream.ts` (`new EventSource(url,{withCredentials:true})`).
16. **TURN/STUN fetch is out of scope (AND-291) via a separate endpoint.**
    VERDICT: **Verified** → `POST /messaging/messages/calls/{call_id}/turn-credentials`
    (empty body) → `TurnCredentialsOut`. SOURCE: OpenAPI
    `issue_turn_credentials_endpoint…`; `src/api/endpoints/messaging.ts:
    fetchTurnCredentials`.
17. **Call teardown (`BYE`) goes through signaling.** VERDICT: **Corrected** →
    teardown is `POST /messaging/messages/calls/{call_id}/end` (`CallEndIn` →
    `CallActionOut`), not a `webrtc.*` envelope. SOURCE: OpenAPI
    `end_call_endpoint…`.
18. **Glare handling: polite-peer rollback on colliding offers.** VERDICT:
    **Verified (web behavior to mirror in AND-289 consumer).** SOURCE:
    `src/hooks/useRtcPeerConnection.ts` (`setLocalDescription({type:"rollback"})`
    when `have-local-offer` && callee).
19. **ICE-restart re-offers carry `{iceRestart:true}` and re-fetch TURN.**
    VERDICT: **Verified (AND-289/AND-291 boundary; transport just carries it).**
    SOURCE: `src/hooks/useRtcPeerConnection.ts: performIceRestart`.
20. **Web reconnect backoff is `min(1000·2^n, MAX)`.** VERDICT: **Verified** —
    spec's `BASE=500ms` is an Android-side choice that differs from web's 1000ms;
    flagged, not a backend contract. SOURCE: `src/hooks/useMessagingStream.ts`
    (`Math.min(1000*Math.pow(2,n), MAX_RETRY_DELAY)`).
21. **Framework: OkHttp `EventSources.createFactory` for SSE; Retrofit+Moshi for
    POST; Hilt `@AssistedFactory`.** VERDICT: **Unverified-assumption (framework
    ref).** SOURCE: framework ref —
    https://square.github.io/okhttp/ (EventSource),
    https://github.com/square/retrofit, https://dagger.dev/hilt/. Reasonable for
    an OkHttp/Retrofit stack; confirm against AND-143's actual `SseClient`.
22. **Cleartext scoped to dev host via `network_security_config.xml`.** VERDICT:
    **Unverified-assumption (framework ref).** SOURCE: framework ref —
    https://developer.android.com/privacy-and-security/security-config. Sound
    Android practice; the dev host `http://18.222.237.167:8000` is from the spec,
    not the OpenAPI.

### Corrections made

- §1, §2, §3 (FR-1/FR-3/FR-4), §4, §5, §13 (OQ-1/OQ-2), §11 (T-1), §14 (AC-2):
  replaced the fictional `/signal`, `/signal/events`, `/signal/poll` surface with
  the real `POST /messaging/messages/calls/{call_id}/signal` +
  `GET /messaging/events/stream` (multiplexed `webrtc.*` SSE).
- Corrected the send body to flat `CallSignalingIn`; success body to
  `CallSignalingOut`; error body to `CallSignalingErrorOut` with HTTP set
  `400/403/404/409/429/503` (+`422`).
- Corrected `type` enum to dotted `webrtc.*` wire strings; removed `BYE` as a
  signaling type (teardown = `…/end`).
- Corrected `sent_at` to epoch **seconds**; added `payload.type` for SDP and
  `payload.usernameFragment` for ICE.
- Corrected self-filter key from `from` to `sender_user_id`; corrected inbound
  field set to `call_id/conversation_id/sender_user_id/event_type/payload`.
- Corrected poll fallback to `after`/`poll_ms` on the shared stream, and noted
  the web client has no poll fallback (Android-only addition).

### Open assumptions

- **OQ-2 / `Last-Event-ID` resume:** the OpenAPI does not state whether
  `GET /messaging/events/stream` honors `Last-Event-ID`; the web client relies on
  browser-native resume and never passes `after`. Must be confirmed empirically
  against the staged backend (else fall back to `after`-cursor + client dedup).
- **`401` on `…/signal`:** not enumerated in the op's OpenAPI responses; we
  assume the shared authenticator still applies (consistent with `client.ts`),
  but the exact server behavior on an expired session for this route is
  unverified.
- **OkHttp SSE / Retrofit / Hilt choices (claims 21–22):** Android-framework
  decisions, not derivable from backend/web sources; verify against AND-143's
  existing `SseClient` implementation.
- **Backoff `BASE=500ms` (Android):** an Android-side tuning choice that differs
  from the web's 1000ms base; not a contract, left as-is but flagged.

## 17. Test Plan

Test IDs `TC-AND-290-NN`. Targets: **JVM** = JVM/Robolectric local; **MWS** =
JVM + OkHttp MockWebServer (contract); **emu35** = headless AVD `test35`
(x86_64, API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U,
R5CX821TA9R, API 34, arm64-v8a). Hardware-dependent cases prefer **device**.

- **TC-AND-290-01 — Send offer/answer/ICE body & headers.**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: authenticated cookie jar with `ui_csrf` cookie set; MWS enqueues
  `200` `CallSignalingOut`.
  Steps: call `send()` for an OFFER, an ANSWER, and an ICE envelope.
  Expected: each request is `POST /messaging/messages/calls/{callId}/signal`;
  body is flat `CallSignalingIn` with correct `type` (`webrtc.offer` etc.),
  `event_id`, `conversation_id`, `recipient_user_id`, `nonce` (8–128 chars),
  `sent_at` in **seconds**, and `payload` shaped `{sdp,type}` (SDP) or
  `{candidate,sdpMid,sdpMLineIndex,usernameFragment}` (ICE); `Cookie` and
  `X-CSRF-Token: <ui_csrf>` headers present; returns `ApiResult.Success`.
  Traces: AC-2.

- **TC-AND-290-02 — Inbound SSE happy path (multiplexed filter).**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: MWS streams a `webrtc.offer`, a `webrtc.ice_candidate`, an
  unrelated `message:new`, and a `webrtc.answer`, all for the active `call_id`.
  Steps: `open(callId, …)`, collect `incoming`.
  Expected: only the three `webrtc.*` events are emitted, in arrival order,
  correctly typed; the `message:new` is ignored; heartbeat/comment lines ignored.
  Traces: AC-1, AC-3.

- **TC-AND-290-03 — Self-filter & wrong-call filter.**
  Type: unit + contract/MockWebServer. Target: MWS (JVM).
  Preconditions: stream contains one event with `sender_user_id == localUserId`,
  one with a different `call_id`, and one valid peer event.
  Steps: collect `incoming`.
  Expected: only the valid peer event is emitted; own-echo and wrong-call events
  dropped. Traces: AC-3.

- **TC-AND-290-04 — Dedup & seq-gap warning.**
  Type: unit. Target: JVM.
  Preconditions: feed two inbound envelopes with the same `event_id`, then one
  with a skipped local `seq`.
  Steps: collect `incoming` and telemetry.
  Expected: duplicate emitted once (dedup set cap 512 honored); gap sets the
  `gap` telemetry flag but still delivers. Traces: AC-3.

- **TC-AND-290-05 — SSE drop → bounded backoff reconnect.**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: MWS opens the stream then closes it mid-flight, then accepts a
  reconnect that resumes delivery.
  Steps: observe `state`.
  Expected: `state` transitions through `Reconnecting(attempt)` with increasing
  attempts and exponential backoff (full-jitter, `BASE=500ms`, `MAX=15s`); on
  reconnect, resume uses `Last-Event-ID`/`after` if available and delivery
  continues. Traces: AC-4.

- **TC-AND-290-06 — Degrade to poll after failure threshold + re-probe.**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: SSE handshake fails `SSE_FAILURE_THRESHOLD` (3) times in the
  window; poll responses to `…/events/stream?after=&poll_ms=` return batches.
  Steps: observe `state` and outgoing requests.
  Expected: `state` becomes `Degraded(POLL)`; poll requests issue with an
  advancing `after` cursor; messages keep flowing; an SSE re-probe is scheduled.
  Traces: AC-5.

- **TC-AND-290-07 — 401 → single refresh + one retry; refresh failure.**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: first `POST …/signal` (and/or SSE open) returns `401`; stubbed
  `POST /ui/session/refresh` returns `200`; a second sub-case returns refresh
  failure.
  Steps: call `send()` / `open()`.
  Expected: exactly one `/ui/session/refresh` then one retry that succeeds; on
  refresh failure → `Error(SignalingError.AuthExpired)` and `state = Error`.
  Traces: AC-6.

- **TC-AND-290-08 — Typed error decoding (`CallSignalingErrorOut`).**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: MWS returns `404` `{code, message}` (unknown call) and, in
  sub-cases, `403`, `409`, `429`, `503`, and `422 HTTPValidationError`.
  Steps: call `send()`.
  Expected: `404` → `SignalingError.RoomNotFound`; others → `Transport(httpCode)`
  carrying the code; `422` decoded via the shared FastAPI `detail` decoder; no
  blind retry of `POST` on a received 4xx body. Traces: AC-2 (error path), AC-6.

- **TC-AND-290-09 — Malformed frame is skipped, stream survives.**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: stream contains a malformed `data:` line between two valid
  `webrtc.*` events.
  Steps: collect `incoming`.
  Expected: malformed line logged + skipped (`SignalingError.Decode` telemetry,
  no crash); both valid events still emitted. Traces: AC-7.

- **TC-AND-290-10 — No persistence; redacted logging.**
  Type: unit + integration. Target: JVM (+ inspection).
  Preconditions: run a full send+receive cycle with logging at DEBUG.
  Steps: assert no Room/DataStore writes of envelopes; inspect captured logs.
  Expected: nothing written to the `core-data` Room cache or disk; logs contain
  only `type/seq/messageId`/lengths — never `payload.sdp` or `payload.candidate`
  contents. Traces: AC-8.

- **TC-AND-290-11 — Lifecycle pause/resume (process & call scope).**
  Type: instrumented/Compose-host. Target: emu35.
  Preconditions: active SSE transport bound to a lifecycle scope.
  Steps: drive `ON_STOP` then `ON_START`; cancel the call scope.
  Expected: stream pauses on `ON_STOP`, resumes on `ON_START` (inherits AND-143);
  `close()` is idempotent and releases the SSE/poll resource. Traces: AC-4
  (state observability), AC-8 (no leak).

- **TC-AND-290-12 — Cleartext gating (security).**
  Type: instrumented. Target: emu35.
  Preconditions: `network_security_config.xml` permits cleartext only for the dev
  host.
  Steps: attempt a cleartext POST to the dev host, then to an arbitrary other
  cleartext host.
  Expected: dev-host cleartext succeeds; any other cleartext host is blocked by
  the platform. Traces: AC-8 (security posture); supports §8.

- **TC-AND-290-13 — Flaky-dev-host / offline resilience.**
  Type: integration. Target: device (real cellular/Wi-Fi flakiness on API 34
  arm64 — must run on the physical device to exercise true radio loss; emu35 only
  approximates via airplane-mode toggles).
  Preconditions: app pointed at the unreliable dev host `18.222.237.167:8000`.
  Steps: start a session; toggle the device to airplane mode for ~10s during an
  ICE burst; restore connectivity.
  Expected: client surfaces `Reconnecting`/`Degraded`, does not crash or drop
  SDP (non-lossy SDP path), and resumes delivery on reconnect with dedup
  preventing duplicate ICE application. Traces: AC-4, AC-5, AC-7.

- **TC-AND-290-14 — Staged two-peer end-to-end exchange.**
  Type: instrumented/e2e (staged). Target: device + emu35 (or device + web
  reference app) — **must include the physical device** so real WebRTC/network
  behavior and arm64/API-34 vs x86/API-35 differences are exercised.
  Preconditions: AND-289 PeerConnection wrapper + AND-291 TURN available; both
  peers authenticated; staged backend reachable.
  Steps: peer A (device) calls peer B (emu35/web); exchange OFFER → ANSWER → ≥1
  ICE each direction through `…/signal` + `…/events/stream`.
  Expected: both peers consume the remote OFFER/ANSWER and ≥1 ICE candidate each
  direction; AND-289's harness reports a connected PeerConnection. Traces: AC-1.

(Accessibility note: AND-290 has **no UI surface** — a11y/TalkBack checks are
N/A here and owned by `feature-call`; this plan therefore has no Compose-UI a11y
case. The only UI-adjacent obligation, exposing status/error as string-resource
keys, is covered structurally by review, not a runtime test.)

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (two-peer staged exchange) | TC-02, TC-14 |
| AC-2 (send body/headers → Success) | TC-01, TC-08 |
| AC-3 (ordered, deduped, self-filtered incoming) | TC-02, TC-03, TC-04 |
| AC-4 (SSE drop → backoff reconnect + resume, observable state) | TC-05, TC-11, TC-13 |
| AC-5 (degrade to poll, then re-probe) | TC-06, TC-13 |
| AC-6 (401 → one refresh + retry; failure → AuthExpired) | TC-07, TC-08 |
| AC-7 (malformed frames skipped) | TC-09, TC-13 |
| AC-8 (no persistence; payloads never logged) | TC-10, TC-11, TC-12 |
