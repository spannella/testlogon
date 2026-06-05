---
id: AND-171
title: Playback analytics/heartbeat
milestone: M4
epic: E23
priority: P2
size: M
status: draft
depends_on: [AND-166]
blocks: []
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
**N seconds** (default `N = 10`, server-overridable — see §6).

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

The exact endpoint must be confirmed against `/openapi.json` and `frontend/src/api/`
(see Open Questions OQ-1). The design below is the assumed contract; the DTO/adapter
layer isolates the rest of the app from drift.

**Endpoint:** `POST /ui/playback/heartbeat`
(fallback per-target form: `POST /ui/{content|broadcast}/{id}/view`).

**Headers:** session cookies (auto via jar), `X-CSRF-Token: {ui_csrf}` (auto via
AND-012 interceptor), `Content-Type: application/json`.

**Request body:**

```json
{
  "session_id": "0f1c8b2a-...-uuid",
  "target_kind": "content",
  "target_id": "ct_01HZX...",
  "phase": "heartbeat",
  "position_ms": 42000,
  "duration_ms": 360000,
  "watched_ms": 10000,
  "is_live": false,
  "playback_speed": 1.0,
  "client_event_id": "8a3d...-uuid",
  "occurred_at": "2026-06-05T12:00:00.000Z"
}
```

**Success `200`:**

```json
{ "accepted": true, "next_interval_ms": 15000, "stop": false }
```

- `next_interval_ms` (optional): server-driven cadence override → fed to
  `HeartbeatConfigStore` for the live session.
- `stop` (optional): if `true`, the client ends reporting for this session (e.g.
  entitlement revoked / concurrency limit). Playback decisions remain with AND-166.

**Error `4xx/5xx`:** FastAPI `detail` shape (string | `[{msg}]` | `{code,...}`), mapped
via AND-015 to `ApiError`. `401` is handled by the global authenticator (one refresh +
retry, AND-013). All other errors → drop after bounded retry.

### 5.1 Retrofit + DTOs

```kotlin
interface PlaybackAnalyticsApi {
    @POST("ui/playback/heartbeat")
    suspend fun heartbeat(@Body body: HeartbeatRequestDto): Response<HeartbeatResponseDto>
}

@JsonClass(generateAdapter = true)
data class HeartbeatRequestDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "target_kind") val targetKind: String,
    @Json(name = "target_id") val targetId: String,
    val phase: String,
    @Json(name = "position_ms") val positionMs: Long,
    @Json(name = "duration_ms") val durationMs: Long?,
    @Json(name = "watched_ms") val watchedMs: Long,
    @Json(name = "is_live") val isLive: Boolean,
    @Json(name = "playback_speed") val playbackSpeed: Float,
    @Json(name = "client_event_id") val clientEventId: String,
    @Json(name = "occurred_at") val occurredAt: String,
)

@JsonClass(generateAdapter = true)
data class HeartbeatResponseDto(
    val accepted: Boolean = true,
    @Json(name = "next_interval_ms") val nextIntervalMs: Long? = null,
    val stop: Boolean = false,
)
```

## 6. Data & State Management

- **Configuration:** `HeartbeatConfigStore` exposes `intervalMs: StateFlow<Long>`
  (default 10_000, bounds 5_000–60_000) and `enabled: StateFlow<Boolean>`. Defaults
  from `BuildConfig`/DataStore; runtime override from `next_interval_ms`. The live
  session re-reads interval on each tick so server overrides take effect immediately.
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
  screen. The only externally observable signal is the optional `stop` directive, which
  is surfaced back to `PlayerManager` via a callback for AND-166 to act on if desired.

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
- **T-6 server override:** `next_interval_ms` in a response changes subsequent cadence;
  `stop:true` ends the session.
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

- **OQ-1 (endpoint shape):** the exact analytics endpoint(s) and payload field names are
  unverified offline. Must be confirmed against `/openapi.json` and
  `frontend/src/api/endpoints/*.ts` before merge. The DTO/adapter isolation limits blast
  radius if the path is `/ui/{kind}/{id}/view` or a batch endpoint instead.
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
- **AC-6:** A server `next_interval_ms` adjusts cadence and `stop:true` ends reporting
  for the session (T-6).
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
