---
id: AND-171
title: Playback analytics/heartbeat
milestone: M4
epic: E23
priority: P2
size: M
depends_on: [AND-166]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-171 — Playback analytics/heartbeat

## 1. Overview & Goal

This ticket delivers the client-side **playback analytics and heartbeat reporting**
layer for the TestLogon native Android app. The single observable requirement from
the backlog is: *"Heartbeats emit at intervals while playing."* Concretely, while a
Media3/ExoPlayer instance (introduced in AND-166) is actively rendering a piece of
content or a live broadcast, the app must emit periodic, deduplicated **view/heartbeat
events** to the backend describing what is being watched, for how long, and at what
position, plus lifecycle markers for the start and end of a viewing session.

The goal is a self-contained, lifecycle-aware reporting component (`PlaybackReporter`)
that any player surface can attach to without re-implementing timing, batching, retry,
or cookie/CSRF plumbing. It must be resilient to the unreliable dev backend (drop
events rather than block playback), correct around process death and backgrounding,
and free of PII leakage in logs.

Non-goals: the player itself, HLS adaptation, player UI controls, watermarking, and
DRM (AND-166/AND-167/AND-168/AND-169). This ticket consumes the `PlayerManager` wrapper
and the player's listener/position callbacks; it does not modify rendering behaviour.
Server-side analytics dashboards (E52) are out of scope.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Retrofit 2.11 + OkHttp 4.12
  + Moshi 1.15, Media3/ExoPlayer 1.4. Module layering `app -> feature-* -> core-*`.
- **Dependency AND-166 (Media3/ExoPlayer integration):** provides
  `core-media:PlayerManager` (single reused `ExoPlayer`, lifecycle-aware release) and a
  Compose `PlayerSurface`. This ticket attaches to that player. `PlayerManager` already
  exposes the active `Player` and a `currentMediaId`.
- **Auth/transport (M1):** cookie-based session with `ui_csrf` echoed as
  `X-CSRF-Token` (AND-012), persistent cookie jar (AND-011), single 401→
  `POST /ui/session/refresh` retry (AND-013), `ApiResult<T>` (AND-018), error `detail`
  mapping (AND-015). The heartbeat `ApiService` reuses the shared authenticated OkHttp
  client; no bespoke transport.
- **Resilience baseline:** ~20 s timeouts, bounded backoff for idempotent GETs only
  (AND-016). Heartbeats are non-idempotent POSTs and therefore are **not** auto-retried
  by the global interceptor; this ticket defines its own narrow, bounded retry policy.
- **Prior art for cadence:** AND-145 (presence heartbeat) establishes the
  interval-emit-while-active pattern and the "drop on failure, never block UI" stance;
  follow the same conventions.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). OpenAPI at `/openapi.json`. Web reference under `frontend/src/api/`.
- **Epic E23** (Media playback foundation), milestone **M4** (Content Consumption).

## 3. Functional Requirements

FR-1. While the attached player is in `STATE_READY` **and** `playWhenReady == true`
(i.e. actually playing, not buffering/paused), the component emits a heartbeat every
**N seconds** (default `N = 10`). ~~server-overridable~~ — **CORRECTED (2026-06-06):** the
interval is **client-side only**; no server response carries a cadence override (the
`next_interval_ms` field assumed in §6 does not exist — see §16). Note also that periodic
heartbeats apply only to **live broadcast** targets; for VOD/content the verified contract
is a single one-shot `POST /ui/videos/{id}/view` per session (see §5), so FR-1's interval
loop drives only the broadcast `viewerHeartbeat` call.

FR-2. On the first transition into the playing state for a given media item, emit a
**`start`** event before the first periodic heartbeat.

FR-3. On leaving the playing state — pause, stop, end of media, error, surface detach,
or app backgrounding — emit a final **`stop`** event carrying the last known position
and the accumulated watched duration since the last report.

FR-4. Each event identifies the content via a `PlaybackTarget` (one of
`content:{id}` or `broadcast:{id}`), the player session id, the current position
(ms), total duration (ms, `null`/`-1` for live), and whether the stream is live.

FR-5. Heartbeats must **not** fire while paused, while buffering with playback intent
off, while seeking-stalled, or while the app is backgrounded (`Lifecycle` below
`STARTED`). When playback resumes, the cadence resumes from a fresh interval.

FR-6. Position/elapsed accounting must be monotonic per session: report *watched*
wall-clock time during the interval (clamped to the interval length) so seeks/scrubs do
not inflate watch time.

FR-7. Switching the player to a new media item ends the current session (`stop`) and
begins a new one (`start`) with a new session id.

FR-8. Reporting failures (network, 4xx/5xx, timeout) must never surface to the user or
interrupt playback. Failed events are dropped after a bounded retry (§7).

FR-9. The reporter is opt-in per surface: a screen attaches via
`PlaybackReporter.attach(player, target)` and detaches in `onDispose`. Multiple
sequential attaches are supported; only one active session exists at a time.

## 4. Technical Design

New code lives in `core-media` (alongside `PlayerManager`) so every feature player
reuses it. Network DTOs/service live in `core-network`/`core-data` per layering.

### 4.1 Public API (core-media)

```kotlin
sealed interface PlaybackTarget {
    val kind: String   // "content" | "broadcast"
    val id: String
    data class Content(override val id: String) : PlaybackTarget { override val kind = "content" }
    data class Broadcast(override val id: String) : PlaybackTarget { override val kind = "broadcast" }
}

enum class HeartbeatPhase { START, HEARTBEAT, STOP }

data class PlaybackSnapshot(
    val sessionId: String,        // UUID v4, one per viewing session
    val target: PlaybackTarget,
    val phase: HeartbeatPhase,
    val positionMs: Long,         // current playhead
    val durationMs: Long?,        // null for live/unknown
    val watchedMsDelta: Long,     // watched wall-clock since previous report, clamped
    val isLive: Boolean,
    val playbackSpeed: Float,
    val clientEventId: String,    // UUID for idempotency/dedup
    val occurredAtEpochMs: Long,
)

interface PlaybackReporter {
    /** Begins observing [player] for [target]; cancels any prior session. */
    fun attach(player: Player, target: PlaybackTarget, owner: LifecycleOwner)
    /** Emits a final STOP for the active session and stops observing. */
    fun detach()
}
```

### 4.2 Implementation

```kotlin
@Singleton
class DefaultPlaybackReporter @Inject constructor(
    private val sink: HeartbeatSink,
    private val config: HeartbeatConfigStore,   // interval, enabled (DataStore/remote)
    private val clock: Clock,
    @ApplicationScope private val scope: CoroutineScope,
) : PlaybackReporter, Player.Listener {
    // single-session state guarded by the main thread (Player API is main-thread bound)
    private var session: SessionState? = null
    private var tickerJob: Job? = null
    private var lifecycleJob: Job? = null
    ...
}
```

Key mechanics:

- **Listener:** implement `onPlaybackStateChanged`, `onPlayWhenReadyChanged`,
  `onMediaItemTransition`, `onPlayerError`, `onPositionDiscontinuity`. Derive a single
  boolean `isPlaying = state == STATE_READY && playWhenReady` and react to its edges.
- **Ticker:** a coroutine on `Dispatchers.Main.immediate` running
  `while (isActive) { delay(intervalMs); emit(HEARTBEAT) }`, started on rising edge of
  `isPlaying`, cancelled on falling edge. Using `delay` (not a fixed-rate timer) avoids
  catch-up bursts after long stalls.
- **Lifecycle:** observe `owner.lifecycle` via `repeatOnLifecycle(STARTED)`; on STOP
  emit a `stop` and pause the ticker, on START re-evaluate `isPlaying`.
- **Watched-time accounting:** track `lastReportPositionMs` and `lastReportWallMs`;
  `watchedMsDelta = min(wallElapsed, intervalMs * speed)` and additionally clamp to the
  position delta when not live, so background scrubbing/seeks cannot inflate watch time.
- **Threading:** all Player reads happen on main; the actual network send is dispatched
  off the main thread inside `HeartbeatSink`.

### 4.3 Sink + queueing

```kotlin
interface HeartbeatSink { fun enqueue(snapshot: PlaybackSnapshot) }

@Singleton
class CoroutineHeartbeatSink @Inject constructor(
    private val api: PlaybackAnalyticsApi,
    @ApplicationScope private val scope: CoroutineScope,
) : HeartbeatSink {
    private val channel = Channel<PlaybackSnapshot>(capacity = 64, onBufferOverflow = DROP_OLDEST)
    // single consumer coroutine posts events FIFO; failures retried per §7 then dropped
}
```

`DROP_OLDEST` with a bounded buffer guarantees the reporter never applies backpressure
to playback. `START`/`STOP` events are tagged `priority` and exempt from drop where
possible (kept ahead of `HEARTBEAT` in a small priority pre-buffer).

## 5. API Contract

> **REVIEW CORRECTION (2026-06-06):** The originally-assumed single endpoint
> `POST /ui/playback/heartbeat` with a rich JSON body and a `{accepted, next_interval_ms,
> stop}` response **does not exist** in the backend OpenAPI spec and is not used by the web
> reference client. There is no unified "playback heartbeat" endpoint. The verified contract
> is **two distinct, much thinner mechanisms** keyed on target kind. The DTO/adapter layer
> still isolates the rest of the app, but the design in §4 must be reduced to match these
> real shapes (no per-event JSON telemetry body, no server cadence/stop directive).

There are **two** real endpoints, selected by `PlaybackTarget` kind. Both reuse the
shared authenticated transport (cookies + `X-CSRF-Token` via AND-012). Neither accepts a
JSON telemetry body; do **not** send `position_ms`/`duration_ms`/`watched_ms`/`phase`/
`client_event_id` — those fields are not part of any verified server schema.

**(a) Content / VOD — one-shot view record (NOT a periodic body):**

```
POST /ui/videos/{video_id}/view      → 200: ViewRecordOut ; 422: HTTPValidationError
```

- No request body. The web client (`src/pages/gallery/VideoDetailPage.tsx`) fires
  `recordView(videoId)` exactly **once on mount**, not on an interval.
- Response `ViewRecordOut`: `{ "view_count": <int>, "is_new_view": <bool> }`.
- Server-side X-SESSION-ID and impersonation headers are listed params; on Android the
  session cookie jar covers session identity (no explicit `X-SESSION-ID` body field).

**(b) Broadcast / live — viewer presence heartbeat (join → heartbeat → leave):**

```
POST /broadcast/sessions/{session_id}/viewers/join                  → 200: ViewerJoinOut
POST /broadcast/sessions/{session_id}/viewers/heartbeat?viewer_id=  → 200: ViewerHeartbeatOut
POST /broadcast/sessions/{session_id}/viewers/leave?viewer_id=      → 200: {ok, viewer_count}
```

- `viewer_id` is a **query parameter**, not a JSON body field (web:
  `src/api/endpoints/broadcast.ts: viewerHeartbeat` posts with `null` body and
  `params: { viewer_id }`).
- `join` returns `ViewerJoinOut`: `{ "viewer_id", "session_id", "viewer_count" }` — the
  client mints/obtains its `viewer_id` from `join`, then heartbeats with it, then `leave`s.
- `heartbeat` returns `ViewerHeartbeatOut`: `{ "ok": <bool>, "viewer_count": <int> }`.
- There is **no** `next_interval_ms` and **no** `stop` field anywhere in these responses;
  cadence is purely client-side, and there is no server "stop reporting" directive.

**(c) Broadcast clips (if a clip surface attaches):** `POST /broadcast/clips/{clip_id}/view`
(one-shot, empty 200 body; public variant `POST /broadcast/public/clips/{clip_id}/view`).

**Headers (all of the above):** session cookies (auto via jar), `X-CSRF-Token: {ui_csrf}`
(auto via AND-012 interceptor). `Content-Type: application/json` is irrelevant for the
no-body POSTs.

**Error `4xx/5xx`:** FastAPI validation errors surface as `422: HTTPValidationError`
(`{"detail": [{"loc","msg","type"}]}`); other errors use the standard FastAPI `detail`
shape (string | `[{msg}]` | `{code,...}`), mapped via AND-015 to `ApiError`. `401` is
handled by the global authenticator (one refresh via `POST /ui/session/refresh` + retry,
AND-013 — verified present). All other errors → drop after bounded retry.

### 5.1 Retrofit + DTOs

> **REVIEW CORRECTION (2026-06-06):** Interface and DTOs rewritten to the verified
> server contract. The `HeartbeatRequestDto`/`HeartbeatResponseDto` above were fabricated.
> There is no JSON request body; `viewer_id` is a query param; responses are the thin
> `ViewRecordOut` / `ViewerJoinOut` / `ViewerHeartbeatOut` shapes.

```kotlin
interface PlaybackAnalyticsApi {
    // Content / VOD — one-shot, no body
    @POST("ui/videos/{videoId}/view")
    suspend fun recordVideoView(@Path("videoId") videoId: String): Response<ViewRecordDto>

    // Live broadcast viewer lifecycle — viewer_id is a QUERY param, no body
    @POST("broadcast/sessions/{sessionId}/viewers/join")
    suspend fun viewerJoin(@Path("sessionId") sessionId: String): Response<ViewerJoinDto>

    @POST("broadcast/sessions/{sessionId}/viewers/heartbeat")
    suspend fun viewerHeartbeat(
        @Path("sessionId") sessionId: String,
        @Query("viewer_id") viewerId: String,
    ): Response<ViewerHeartbeatDto>

    @POST("broadcast/sessions/{sessionId}/viewers/leave")
    suspend fun viewerLeave(
        @Path("sessionId") sessionId: String,
        @Query("viewer_id") viewerId: String,
    ): Response<ViewerLeaveDto>
}

@JsonClass(generateAdapter = true)
data class ViewRecordDto(           // ViewRecordOut
    @Json(name = "view_count") val viewCount: Int,
    @Json(name = "is_new_view") val isNewView: Boolean,
)

@JsonClass(generateAdapter = true)
data class ViewerJoinDto(           // ViewerJoinOut
    @Json(name = "viewer_id") val viewerId: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "viewer_count") val viewerCount: Int,
)

@JsonClass(generateAdapter = true)
data class ViewerHeartbeatDto(      // ViewerHeartbeatOut
    val ok: Boolean,
    @Json(name = "viewer_count") val viewerCount: Int,
)

@JsonClass(generateAdapter = true)
data class ViewerLeaveDto(
    val ok: Boolean,
    @Json(name = "viewer_count") val viewerCount: Int,
)
```

Implications for §4: the `PlaybackSnapshot`/`HeartbeatRequestDto` rich-telemetry model is
**not** sent to the server — it can survive only as an *internal* representation feeding
local debug logs/counters (§10). The network layer maps `PlaybackTarget.Content` →
`recordVideoView` (fired once per session) and `PlaybackTarget.Broadcast` → the
join/heartbeat/leave lifecycle (heartbeat fired on the client interval). `START` ≈
join/first-view; `HEARTBEAT` ≈ `viewerHeartbeat` (broadcast only — VOD has no periodic
server call); `STOP` ≈ `viewerLeave` (broadcast) or no-op (VOD).

## 6. Data & State Management

- **Configuration:** `HeartbeatConfigStore` exposes `intervalMs: StateFlow<Long>`
  (default 10_000, bounds 5_000–60_000) and `enabled: StateFlow<Boolean>`. Defaults
  from `BuildConfig`/DataStore. **CORRECTED (2026-06-06):** there is no `next_interval_ms`
  in any server response, so there is **no runtime server-driven override**; the interval
  is configured only locally. Re-reading the interval on each tick is still useful for
  picking up a local/remote-config (Firebase/DataStore) change, but not for a per-response
  server directive.
- **Session state (in-memory only):**

```kotlin
private data class SessionState(
    val sessionId: String,
    val target: PlaybackTarget,
    var lastReportPositionMs: Long,
    var lastReportWallMs: Long,
    var startSent: Boolean,
)
```

- **No persistence of events.** Heartbeats are ephemeral telemetry; nothing is written
  to Room. Process death simply ends the session (the queued buffer is best-effort and
  lost on kill, which is acceptable for view counting — the next foreground play starts a
  fresh session). This avoids stale/duplicated counts after restart.
- **Session id** is a `UUID.randomUUID()` minted at `attach`/media-transition;
  `client_event_id` is a fresh UUID per event for server-side dedup/idempotency.
- **No `StateFlow<UiState>`** is exposed to UI: this is a background reporter, not a
  screen. **CORRECTED (2026-06-06):** there is no server `stop` directive in any verified
  response, so the "surface `stop` back to `PlayerManager`" callback has no real trigger
  from the network. The only optionally-observable signal is `ViewerHeartbeatOut.viewer_count`
  (live viewer count), which a broadcast surface may choose to display; the reporter can
  expose it via an optional callback. Any future "watching limit reached"/entitlement-revoked
  behaviour would require a new backend field and is out of scope here.

## 7. Error Handling & Resilience

- **Never block playback.** All sends are fire-and-forget through the bounded channel;
  the player thread never awaits a network result.
- **Retry policy (narrow):** because heartbeats are non-idempotent POSTs, the global
  GET-only backoff (AND-016) does not apply. The sink retries an event at most **2**
  times with jittered backoff (~1 s, ~3 s) **only** on transport/IO errors and `5xx`;
  `4xx` (except `401`) is dropped immediately. After exhaustion the event is dropped and
  counted in telemetry. `client_event_id` makes a retry that actually reached the server
  harmless (server dedups).
- **Timeout:** rely on the shared OkHttp ~20 s timeouts; a slow dev host stalls only the
  single consumer coroutine, while new events keep flowing into the bounded channel
  (`DROP_OLDEST`), so backlog cannot grow unbounded.
- **Offline:** if connectivity probe (AND-017) reports offline, the sink short-circuits
  (no send attempt) and drops `HEARTBEAT` events but still attempts `START`/`STOP` once
  when connectivity returns within the session — best effort, no queueing across kills.
- **Player errors:** on `onPlayerError`, emit a `STOP` with the last known position and
  cancel the ticker; resumption is governed by AND-166's error recovery.
- **Clock skew:** `occurred_at` uses device time; server is source of truth for
  ordering. Watched-time deltas are device-measured and clamped (§4.2) to resist skew.

## 8. Security & Privacy

- **Transport:** reuses the authenticated OkHttp stack — cookies + `X-CSRF-Token`. No
  separate credentials. Dev host is plaintext HTTP (known dev constraint); production
  base URL is HTTPS via build flavor (AND-006).
- **No PII in payload:** body contains only opaque content/broadcast/session ids,
  positions, and timestamps — no username, no auth tokens.
- **Logging redaction:** event logs must never include cookie/CSRF values or full
  request bodies at non-debug levels; only `phase`, `target_kind`, truncated ids, and
  outcome. Follow the redacted-telemetry convention from AND-052.
- **CSRF:** POSTs require the `X-CSRF-Token` header; the interceptor (AND-012) supplies
  it. A missing CSRF cookie results in the event being dropped (logged), never a crash.
- **Consent/DNT:** if a future privacy/analytics-consent flag exists, `enabled` gates
  all emission. Default in dev is enabled; flag wiring deferred to E52 if required (OQ-2).

## 9. Accessibility & i18n

Not applicable as a user-facing surface — this component renders no UI and presents no
strings. Accessibility and localization for the surrounding player are owned by AND-168
(reusable player UI). Any future user-visible "watching limit reached" message arising
from a server `stop` directive will be a player-UI string owned by AND-166/AND-168 and
localized via the i18n plumbing (AND-111/AND-112).

## 10. Telemetry & Logging

This ticket *is* telemetry, but it also needs operational diagnostics for itself:

- **Structured debug logs** (debug builds only): `pb_hb phase=heartbeat target=content
  id=ct_01… pos=42000 watched=10000 result=200 latencyMs=…`.
- **Drop counters:** increment in-memory counters for `dropped_offline`,
  `dropped_overflow`, `dropped_4xx`, `dropped_retry_exhausted`, exposed via a debug
  inspector / surfaced to the existing logging facade for later wiring to a real sink.
- **Session lifecycle markers:** log `start`/`stop` with `sessionId` and total session
  watched-ms for QA verification of FR-2/FR-3.
- **Redaction:** per §8, no secrets; ids may be truncated. No network bodies logged
  above DEBUG. Reuse the app's `Logger` abstraction rather than `android.util.Log`
  directly.

## 11. Testing Strategy

Unit/JVM tests (`core-testing`, JUnit + Turbine + a fake `Player`/`TestScope`):

- **T-1 cadence (FR-1):** with a fake player in playing state and a virtual clock,
  advancing time by `N` emits exactly one `HEARTBEAT`; advancing `3N` emits three.
- **T-2 start/stop (FR-2/3):** entering playing emits `START` then heartbeats; pausing
  emits a single `STOP` carrying last position and accumulated `watched_ms`.
- **T-3 gating (FR-5):** buffering / paused / backgrounded states emit **no**
  heartbeats; resuming restarts a fresh interval (no catch-up burst).
- **T-4 media transition (FR-7):** `onMediaItemTransition` produces `STOP(old)` +
  `START(new)` with distinct `session_id`s.
- **T-5 watched-time clamping (FR-6):** a forward seek during an interval does not
  inflate `watched_ms` beyond the interval bound.
- **T-6 server override:** ~~`next_interval_ms` in a response changes subsequent cadence;
  `stop:true` ends the session.~~ **CORRECTED (2026-06-06):** these server fields do not
  exist. Repurpose T-6 to verify a **local** interval change (via `HeartbeatConfigStore`)
  is picked up on the next tick, and that the broadcast `viewer_count` from
  `ViewerHeartbeatOut` is surfaced via the optional callback. (See TC-AND-171-08/09.)
- **T-7 resilience (FR-8):** sink under `5xx` retries ≤2 then drops, increments
  `dropped_retry_exhausted`, and never throws into the player thread; channel overflow
  drops oldest `HEARTBEAT` and increments `dropped_overflow`.

Network contract test (MockWebServer harness, AND-046): verifies request path, JSON
field names (snake_case via Moshi), presence of `X-CSRF-Token`, and parsing of
`HeartbeatResponseDto` including optional fields. CI runs JVM tests (AND-050); no
instrumented test required (no UI).

## 12. Dependencies & Sequencing

- **Depends on AND-166** (Media3/ExoPlayer integration / `PlayerManager`) — provides the
  `Player` instance, single-player reuse, and lifecycle-aware release this reporter
  attaches to. Hard blocker.
- **Relies on M1 transport:** AND-011 (cookie jar), AND-012 (CSRF), AND-013 (401
  refresh), AND-015 (error mapping), AND-018 (`ApiResult`), AND-016/AND-017
  (resilience/connectivity). All already landed before M4.
- **Pattern reference:** AND-145 (presence heartbeat) — share cadence/drop conventions.
- **Consumers:** AND-167 (HLS playback) and the player surfaces in E26 (VOD detail/clip
  viewer) and E38 (broadcast viewer) attach this reporter; broadcast viewing supplies
  `PlaybackTarget.Broadcast`. Those tickets depend on this one but are not blocked from
  starting (reporter attach is additive).

## 13. Risks & Open Questions

- **OQ-1 (endpoint shape) — RESOLVED (2026-06-06):** verified against the OpenAPI index
  and the web reference. There is **no** `/ui/playback/heartbeat` endpoint and no unified
  analytics POST body. Reality (see §5/§16): VOD → one-shot `POST /ui/videos/{id}/view`
  (`ViewRecordOut`); live broadcast → `viewers/join` → `viewers/heartbeat?viewer_id=` →
  `viewers/leave?viewer_id=` (`ViewerJoinOut`/`ViewerHeartbeatOut`); clips →
  `POST /broadcast/clips/{clip_id}/view`. The §4 rich-telemetry snapshot stays internal
  only. **No** server cadence override and **no** server stop directive exist.
- **OQ-2 (consent gating):** whether an analytics/DNT consent flag must gate emission is
  TBD; `enabled` flag is in place but defaults on. Owner: E52.
- **Risk — live duration:** live broadcasts report `duration_ms = null`; ensure server
  accepts null. Mitigation: omit field or send `-1` per contract confirmation.
- **Risk — battery/network on flaky host:** frequent POSTs to a slow host could waste
  battery. Mitigation: bounded channel + `DROP_OLDEST` + offline short-circuit; consider
  batching multiple heartbeats per request as a follow-up if server supports it.
- **Risk — double counting across process death:** acceptable for v1 (no cross-kill
  persistence); revisit if server requires exact dedup beyond `client_event_id`.

## 14. Acceptance Criteria

- **AC-1 (backlog):** While content/broadcast is actively playing, heartbeat events are
  emitted at the configured interval (default 10 s) — verified by T-1 and by an
  integration check against MockWebServer counting requests over elapsed virtual time.
- **AC-2:** A `START` event precedes the first heartbeat and a `STOP` event is emitted on
  pause/stop/end/transition/background, carrying last position and watched duration
  (T-2/T-3/T-4).
- **AC-3:** No heartbeats are emitted while paused, buffering-without-intent, or
  backgrounded; cadence resumes cleanly on resume with no catch-up burst (T-3).
- **AC-4:** Each event carries a stable `session_id` per session and a unique
  `client_event_id`; a new media item yields a new session (T-4).
- **AC-5:** Requests include cookies + `X-CSRF-Token`; `401` triggers exactly one refresh
  retry via the global authenticator; other failures are retried ≤2 then dropped without
  affecting playback (T-7, contract test).
- **AC-6:** ~~A server `next_interval_ms` adjusts cadence and `stop:true` ends reporting
  for the session (T-6).~~ **CORRECTED (2026-06-06):** no such server fields exist.
  Revised AC-6: a **local** interval change (`HeartbeatConfigStore`) takes effect on the
  next tick, and the live `viewer_count` from `ViewerHeartbeatOut` is exposed to an
  optional surface callback without affecting playback (T-6).
- **AC-7:** Reporting never throws into, blocks, or stalls the player thread under any
  network condition (T-7).

## 15. Definition of Done

- `PlaybackReporter`/`DefaultPlaybackReporter`, `HeartbeatSink`/`CoroutineHeartbeatSink`,
  `PlaybackTarget`, DTOs, `PlaybackAnalyticsApi`, and `HeartbeatConfigStore` implemented
  under `com.testlogon.android` in `core-media`/`core-network`, wired via Hilt (KSP).
- A player surface (e.g. AND-166's `PlayerSurface` demo or AND-167 HLS screen) attaches
  the reporter and detaches on dispose; manual run against the dev backend shows
  heartbeat POSTs at the configured interval.
- All unit + contract tests (T-1…T-7, MockWebServer) implemented and green in CI
  (AND-050).
- Lint/detekt/ktlint clean (AND-005); no secrets or full bodies logged above DEBUG.
- Endpoint/path confirmed against `/openapi.json` (OQ-1 resolved) or, if unresolved, the
  assumption documented with a follow-up ticket referenced in the PR.
- Code reviewed and merged to `android-port`; spec linked from the PR.

## 16. Citations & Assumption Audit

Each key technical claim from the spec, its verdict, and the exact source pointer.

1. **Claim:** Heartbeat endpoint is `POST /ui/playback/heartbeat`.
   **VERDICT: Corrected** — endpoint does not exist.
   **Source:** OpenAPI index `reference/openapi.index.txt` (grep for `heartbeat`/`/view`
   returns no such path). Real endpoints below.
2. **Claim:** Content/VOD view reporting path.
   **VERDICT: Corrected** → `POST /ui/videos/{video_id}/view`, no body, returns
   `ViewRecordOut`.
   **Source:** OpenAPI `POST /ui/videos/{video_id}/view` (`op=record_view_endpoint…`,
   `resp=200:ViewRecordOut`); frontend `src/api/endpoints/gallery.ts: recordView`.
3. **Claim:** `ViewRecordOut` shape.
   **VERDICT: Verified** → `{ view_count: int, is_new_view: bool }` (both required).
   **Source:** `openapi.pretty.json` `components.schemas.ViewRecordOut`;
   `src/api/endpoints/gallery.ts: ViewRecordResponse`.
4. **Claim:** VOD view is recorded periodically.
   **VERDICT: Corrected** — the web client fires it **once on mount**, not on an interval.
   **Source:** `src/pages/gallery/VideoDetailPage.tsx` (`// Fire view recording once on
   mount`, `viewMut.mutate()` in a one-time `useState` initializer).
5. **Claim:** Live broadcast periodic heartbeat path.
   **VERDICT: Verified (path) / Corrected (shape)** →
   `POST /broadcast/sessions/{session_id}/viewers/heartbeat` with `viewer_id` as a **query
   param**, no JSON body, returns `ViewerHeartbeatOut`.
   **Source:** OpenAPI `POST /broadcast/sessions/{session_id}/viewers/heartbeat`
   (`params=session_id,viewer_id,…`, `resp=200:ViewerHeartbeatOut`);
   `src/api/endpoints/broadcast.ts: viewerHeartbeat` (posts `null` body,
   `params: { viewer_id }`).
6. **Claim:** Broadcast viewer lifecycle requires join/leave around heartbeats.
   **VERDICT: Verified** → `viewers/join` (→ `ViewerJoinOut{viewer_id,session_id,
   viewer_count}`) and `viewers/leave?viewer_id=`.
   **Source:** OpenAPI `…/viewers/join`, `…/viewers/leave`;
   `src/api/endpoints/broadcast.ts: viewerJoin/viewerLeave`;
   `openapi.pretty.json components.schemas.ViewerJoinOut`.
7. **Claim:** `ViewerHeartbeatOut` shape.
   **VERDICT: Verified** → `{ ok: bool, viewer_count: int }` (both required).
   **Source:** `openapi.pretty.json components.schemas.ViewerHeartbeatOut`;
   `src/api/endpoints/broadcast.ts: ViewerHeartbeatResponse`.
8. **Claim:** Request body carries `session_id/target_kind/position_ms/duration_ms/
   watched_ms/phase/playback_speed/client_event_id/occurred_at`.
   **VERDICT: Corrected** — no verified endpoint accepts such a body; the periodic
   broadcast call takes only `viewer_id` (query), and the VOD call takes nothing. These
   fields can exist only as internal state for local debug logging.
   **Source:** OpenAPI `req=` empty for both `…/viewers/heartbeat` and
   `…/videos/{id}/view`; `src/api/endpoints/broadcast.ts: viewerHeartbeat` (null body).
9. **Claim:** Success response `{ accepted, next_interval_ms, stop }` with server-driven
   cadence override and a server stop directive.
   **VERDICT: Corrected** — none of these fields exist in any response schema. Cadence is
   client-only; there is no server stop directive.
   **Source:** grep for `next_interval`/`"accepted"` in `openapi.index.txt` → no match;
   verified schemas in items 3/7 contain no such fields.
10. **Claim:** Clip view path `POST /broadcast/clips/{clip_id}/view` (and public variant).
    **VERDICT: Verified.**
    **Source:** OpenAPI `POST /broadcast/clips/{clip_id}/view`,
    `POST /broadcast/public/clips/{clip_id}/view`.
11. **Claim:** Auth is cookie-based session with `ui_csrf` echoed as `X-CSRF-Token`
    (AND-012).
    **VERDICT: Verified.**
    **Source:** `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token",
    csrf)`; `credentials: "include"`).
12. **Claim:** Single 401 → refresh + retry via `POST /ui/session/refresh` (AND-013).
    **VERDICT: Verified.**
    **Source:** `src/api/client.ts` (401 branch calls `refreshSession()` then re-fetches
    once); `refreshSession()` → `fetch(withApiBase("/ui/session/refresh"))`;
    `src/api/endpoints/auth.ts: refreshSession` → `POST /ui/session/refresh`; OpenAPI
    `POST /ui/session/refresh` present.
13. **Claim:** 4xx validation surfaces as FastAPI `HTTPValidationError` `{detail:[{loc,msg,
    type}]}`.
    **VERDICT: Verified.**
    **Source:** OpenAPI lists `422:HTTPValidationError` on all of `…/view`,
    `…/viewers/heartbeat`, `…/viewers/join`.
14. **Claim:** AND-145 presence heartbeat exists as cadence prior art.
    **VERDICT: Verified** → `POST /messaging/presence/heartbeat` (`req=PresenceHeartbeatIn`).
    **Source:** OpenAPI index line for `/messaging/presence/heartbeat`.
15. **Claim (framework):** Media3/ExoPlayer `Player.Listener` callbacks
    (`onPlaybackStateChanged`, `onPlayWhenReadyChanged`, `onMediaItemTransition`,
    `onPlayerError`, `onPositionDiscontinuity`) and `STATE_READY`/`playWhenReady` semantics.
    **VERDICT: Unverified-assumption (framework ref)** — not checkable from backend/web
    sources; standard Media3 API per AND-166.
    **Source (framework ref):** https://developer.android.com/media/media3/exoplayer/listening-to-player-events
16. **Claim (framework):** Lifecycle gating via `repeatOnLifecycle(STARTED)`.
    **VERDICT: Unverified-assumption (framework ref).**
    **Source (framework ref):** https://developer.android.com/topic/libraries/architecture/coroutines#restart
17. **Claim:** Endpoints additionally take `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` header
    params.
    **VERDICT: Verified (present) / Assumption (handling)** — they are listed params; the
    Android client is assumed to satisfy session identity via the cookie jar rather than an
    explicit `X-SESSION-ID` field. Confirm during contract testing.
    **Source:** OpenAPI `params=…,X-SESSION-ID,X-IMPERSONATION-TOKEN` on the broadcast
    viewer endpoints.

### Corrections made

- Replaced the fabricated single `POST /ui/playback/heartbeat` endpoint with the two real
  mechanisms: VOD one-shot `POST /ui/videos/{id}/view` (`ViewRecordOut`) and live
  broadcast `viewers/join → viewers/heartbeat?viewer_id= → viewers/leave` (`ViewerJoinOut`/
  `ViewerHeartbeatOut`). (§5, §5.1, §13/OQ-1)
- Removed the fabricated JSON telemetry request body; `viewer_id` is a query param and VOD
  takes no body. The rich `PlaybackSnapshot`/DTO becomes internal-only. (§5.1)
- Removed the fabricated `{accepted, next_interval_ms, stop}` response and all
  server-driven cadence-override / server-stop-directive behaviour. (§5, §6, FR-1, T-6,
  AC-6)
- Clarified that periodic heartbeats apply to **broadcast** only; VOD is one-shot. (FR-1, §5.1)
- Rewrote the Retrofit `PlaybackAnalyticsApi` and DTOs to the verified shapes. (§5.1)

### Open assumptions

- **Internal snapshot model vs server:** the position/duration/watched-time accounting in
  §4/§6 is retained as *internal* telemetry for local debug logs/counters only; no backend
  consumes it. Unverifiable because no server schema accepts those fields.
- **`X-SESSION-ID` handling:** assumed covered by the cookie jar on Android; the web client
  relies on cookies (`credentials: "include"`) and does not set `X-SESSION-ID` explicitly.
  Needs confirmation against a live dev host during contract testing.
- **Whether the Android app should call VOD `view` once-per-session or once-per-resume:**
  web fires once on mount; mapping "session" to "first play of a media item" is an
  assumption (see FR-7). Unverifiable from sources.
- **Consent/DNT gating (OQ-2):** no analytics-consent endpoint/flag found; ownership E52.
- **Media3 listener/lifecycle framework behaviour:** assumed per AND-166 and Android docs;
  not verifiable from backend/web sources.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **MWS** =
contract test on MockWebServer (JVM); **emu35** = headless emulator AVD `test35`
(x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a).
Hardware-dependent cases prefer A15.

- **TC-AND-171-01 — Broadcast heartbeat cadence (happy path).**
  Type: unit (JVM). Target: `DefaultPlaybackReporter` + fake `Player` + `TestScope`
  virtual clock. Preconditions: reporter attached with `PlaybackTarget.Broadcast`,
  interval = 10 s, player `STATE_READY` & `playWhenReady=true`. Steps: advance virtual
  time 10 s, then 30 s. Expected: exactly 1 `viewerHeartbeat` after first 10 s; 3 more
  after the next 30 s (no catch-up bursts); `viewer_id` from the prior `join` is reused.
  Traces: AC-1.

- **TC-AND-171-02 — Start/stop lifecycle (broadcast = join/leave, VOD = one-shot view).**
  Type: unit (JVM). Target: reporter + fake `Player`. Preconditions: attached. Steps:
  enter playing → pause. Expected: for Broadcast, `viewers/join` precedes the first
  heartbeat and a `viewers/leave` is emitted on pause; for Content, a single
  `POST /ui/videos/{id}/view` is emitted at start and **no** periodic/stop calls.
  Traces: AC-2.

- **TC-AND-171-03 — Gating: no heartbeats while paused/buffering/backgrounded.**
  Type: unit (JVM). Target: reporter + fake `Player` + fake `LifecycleOwner`.
  Preconditions: attached, broadcast target. Steps: drive states buffering (intent off),
  paused, and lifecycle below STARTED; then resume. Expected: zero heartbeats during
  gated states; on resume cadence restarts from a fresh interval (first heartbeat at
  +interval, no immediate catch-up). Traces: AC-3.

- **TC-AND-171-04 — Media transition yields new session.**
  Type: unit (JVM). Target: reporter. Preconditions: broadcast session A active. Steps:
  fire `onMediaItemTransition` to broadcast B. Expected: `viewers/leave` for A then
  `viewers/join` for B; new `sessionId` and new server `viewer_id`; distinct
  `client_event_id`s in internal log. Traces: AC-4.

- **TC-AND-171-05 — Contract: request shape, headers, response parse (broadcast).**
  Type: contract/MockWebServer (MWS). Target: `PlaybackAnalyticsApi` + OkHttp/CSRF
  interceptor. Preconditions: `ui_csrf` cookie set in jar. Steps: call `viewerJoin` then
  `viewerHeartbeat`. Expected: heartbeat request path is
  `/broadcast/sessions/{id}/viewers/heartbeat?viewer_id=…` with **no JSON body**, carries
  cookie + `X-CSRF-Token`; response `{ok,viewer_count}` parses into `ViewerHeartbeatDto`;
  `join` parses `{viewer_id,session_id,viewer_count}`. Traces: AC-5.

- **TC-AND-171-06 — Contract: VOD one-shot view shape + parse.**
  Type: contract/MockWebServer (MWS). Target: `PlaybackAnalyticsApi.recordVideoView`.
  Steps: enqueue `{ "view_count": 42, "is_new_view": true }`; call once. Expected: path
  `/ui/videos/{id}/view`, POST with empty body, `X-CSRF-Token` present; parses into
  `ViewRecordDto(viewCount=42, isNewView=true)`. Traces: AC-1, AC-5.

- **TC-AND-171-07 — 401 triggers exactly one refresh + retry.**
  Type: contract/MockWebServer (MWS). Target: shared authenticator + `PlaybackAnalyticsApi`.
  Steps: enqueue 401, then 200 `{ok,viewer_count}` for the heartbeat; ensure
  `POST /ui/session/refresh` is enqueued 200. Expected: exactly one refresh call then one
  retried heartbeat that succeeds; no infinite loop; player thread untouched.
  Traces: AC-5.

- **TC-AND-171-08 — Validation/error responses are dropped without throwing.**
  Type: contract/MockWebServer (MWS). Target: `CoroutineHeartbeatSink`. Steps: enqueue
  `422 HTTPValidationError` `{"detail":[{"loc":["query","viewer_id"],"msg":"field
  required","type":"value_error.missing"}]}`, then a `500`. Expected: 422 dropped
  immediately (no retry, `dropped_4xx++`); 500 retried ≤2 with jitter then dropped
  (`dropped_retry_exhausted++`); no exception escapes to the player thread. Traces:
  AC-5, AC-7.

- **TC-AND-171-09 — Local interval change takes effect; viewer_count surfaced (revised T-6).**
  Type: unit (JVM). Target: reporter + `HeartbeatConfigStore` + fake clock. Steps: run
  with interval 10 s for two ticks, change config to 5 s, advance. Expected: subsequent
  ticks use 5 s; each `ViewerHeartbeatOut.viewer_count` is delivered to the optional
  surface callback. Confirms no reliance on a (non-existent) server cadence/stop field.
  Traces: AC-6.

- **TC-AND-171-10 — Watched-time clamping resists seeks.**
  Type: unit (JVM). Target: reporter accounting. Steps: during one interval, fire a large
  forward `onPositionDiscontinuity` (seek). Expected: internal `watchedMsDelta` clamped to
  ≤ interval·speed and to the position delta when not live; seek does not inflate
  internal watch accounting. (Internal-only; not sent to server — see §16.) Traces:
  AC-2.

- **TC-AND-171-11 — Flaky/offline dev host: never blocks playback, best-effort START/STOP.**
  Type: integration (JVM + MWS with throttling/dispatcher delays). Target: sink + reporter.
  Steps: set MWS to delay ~25 s (> 20 s timeout) and toggle the AND-017 connectivity probe
  to offline mid-session. Expected: heartbeats short-circuit/drop while offline
  (`dropped_offline++`); the single consumer stalls on the slow request while new events
  keep entering the bounded `DROP_OLDEST` channel (no unbounded backlog); player thread is
  never awaited; `START`/`STOP`(join/leave) attempted once when connectivity returns.
  Traces: AC-7.

- **TC-AND-171-12 — Channel overflow drops oldest, not newest START/STOP.**
  Type: unit (JVM). Target: `CoroutineHeartbeatSink` channel (capacity 64, DROP_OLDEST).
  Steps: enqueue >64 events with the consumer paused. Expected: oldest `HEARTBEAT`s
  dropped (`dropped_overflow++`); priority `START`/`STOP` retained; no backpressure to
  caller. Traces: AC-7.

- **TC-AND-171-13 — Security: CSRF/cookie required; redaction; no PII/secret logging.**
  Type: contract/MockWebServer (MWS) + log assertion. Target: interceptor + `Logger`.
  Steps: (a) with `ui_csrf` cookie absent, attempt a heartbeat; (b) inspect debug logs.
  Expected: (a) event is dropped+logged, never crashes (missing CSRF); (b) logs contain
  only `phase`, `target_kind`, truncated id, outcome — no cookie/CSRF value, no full
  request body above DEBUG. Traces: AC-5, AC-7.

- **TC-AND-171-14 — Instrumented end-to-end against a live broadcast on a real device.**
  Type: instrumented/e2e. Target: a player surface (AND-166/167) attaching the reporter,
  pointed at the dev backend `http://18.222.237.167:8000`. **MUST run on A15 (physical
  device)** — real-network HLS/streaming behaviour and arm64-v8a/API-34 path differ from
  the x86_64/API-35 emulator. Preconditions: authenticated session, a live broadcast
  session id. Steps: start playback, watch ≥3 intervals, background the app, foreground,
  stop. Expected: `viewers/join` once, periodic `viewers/heartbeat` at the configured
  interval while foreground+playing, paused during background, `viewers/leave` on stop;
  playback never stalls; battery/network within bounded-channel expectations. Smoke-run
  the UI-less path on **emu35** in CI first; the network-timing assertions are
  authoritative only on **A15**. Traces: AC-1, AC-2, AC-3, AC-7.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 (interval emission while playing) | TC-01, TC-06, TC-14 |
| AC-2 (START precedes, STOP on exit; watched duration) | TC-02, TC-10, TC-14 |
| AC-3 (no emission while paused/buffering/backgrounded; clean resume) | TC-03, TC-14 |
| AC-4 (stable session id; new media → new session) | TC-04 |
| AC-5 (cookies+CSRF; one 401 refresh; bounded retry/drop) | TC-05, TC-06, TC-07, TC-08, TC-13 |
| AC-6 (revised: local interval change; viewer_count surfaced) | TC-09 |
| AC-7 (never throws/blocks/stalls player thread) | TC-08, TC-11, TC-12, TC-13, TC-14 |
