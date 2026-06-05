---
id: AND-285
title: Viewer join/leave/heartbeat
milestone: M6
epic: E38
priority: P1
size: M
status: draft
depends_on: [AND-280]
blocks: []
---

# AND-285 — Viewer join/leave/heartbeat

## 1. Overview & Goal

When an authorized viewer opens a live stream (the HLS player delivered by
AND-280), the backend must learn that the viewer is present, keep that presence
fresh for the duration of the watch session, and learn when the viewer leaves.
This ticket implements the client side of viewer **presence**: a `join` call on
session start, a periodic **heartbeat** while the player is active, and a `leave`
call on teardown, plus surfacing the live **viewer count** in the player UI.

Goal: while a viewer watches a stream the server-side presence record stays
alive (heartbeat runs on schedule and survives transient network failure), the
displayed viewer count reflects server state within one poll/heartbeat interval,
and presence is reliably released when the viewer leaves, backgrounds the app, or
the process is killed. Presence must be lifecycle-correct (no duplicate joins, no
leaked sessions) and resilient against the unreliable dev backend.

Out of scope: HLS playback itself, `playback-url` / `playback/verify`
authorization (AND-280); broadcaster-side presence; chat; reactions.

## 2. Context & References

- Builds directly on **AND-280** (Viewer playback / HLS). AND-280 owns the
  `ViewerPlaybackScreen`, its `ViewerPlaybackViewModel`, the ExoPlayer/Media3
  pipeline, and the `playback/verify` authorization gate. AND-285 attaches the
  presence lifecycle to that screen and ViewModel.
- Auth is cookie-based per project context: the OkHttp client carries the
  persistent cookie jar and echoes the `ui_csrf` cookie as the `X-CSRF-Token`
  header; on `401` the network layer calls `POST /ui/session/refresh` once then
  retries. Presence calls are authenticated UI calls and ride the same client.
- Module layering: `feature-viewer` (screen + ViewModel) → `core-data`
  (`PresenceRepository`) → `core-network` (`PresenceApi`, shared OkHttp/Retrofit,
  `ApiResult<T>`) → `core-model` (presence DTOs/domain). Telemetry via the
  existing logging facade in `core-data`.
- Backend is FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is
  plaintext HTTP and unreliable; design for ~20 s timeouts, bounded backoff retry
  for idempotent GETs only, and offline/stale UI. OpenAPI at `/openapi.json`;
  the dev host was unreachable from the spec authoring environment, so the
  contract in §5 is derived from the documented `/ui/*` conventions and the web
  reference app (`frontend/src/api/endpoints/*.ts`) and MUST be reconciled against
  live `/openapi.json` during implementation (see §13).
- Web reference: presence wiring lives alongside the viewer endpoints in
  `frontend/src/api/endpoints/streams.ts` (or `presence.ts`) and shared types in
  `frontend/src/api/types.ts`.

## 3. Functional Requirements

FR-1 **Join on play start.** When AND-280's `playback/verify` succeeds and the
ExoPlayer reaches a startable state for stream `streamId`, the client issues a
single `join` for that `(streamId, sessionId)` and obtains a presence
`session_token` and the current `viewer_count`.

FR-2 **Heartbeat while active.** While the screen is in the foreground and the
join succeeded, the client sends a heartbeat every `heartbeat_interval_s`
(server-provided, default 15 s). Each heartbeat refreshes the presence TTL and
returns the latest `viewer_count`.

FR-3 **Leave on teardown.** On any of: navigating away, player release, app
backgrounding beyond a grace window, or explicit close, the client issues a
`leave` for the active `session_token`. Leave is best-effort and idempotent.

FR-4 **Viewer count display.** The current `viewer_count` is rendered as a live
badge overlay on the player. It updates from every join/heartbeat response and,
when offline/stale, shows the last-known value with a stale indicator rather than
zero.

FR-5 **No duplicate sessions.** A given `ViewerPlaybackViewModel` instance holds
at most one active presence session. Re-entering play (e.g. recover from error)
reuses the existing token if still valid, otherwise re-joins.

FR-6 **Background/foreground.** On `ON_STOP` the heartbeat loop pauses and a
short grace timer (default 30 s) starts; if the app returns to foreground within
grace the loop resumes (re-joining if the token expired); if grace elapses the
client sends `leave` and tears down the session.

FR-7 **Resilience.** A failed heartbeat does not immediately drop the session;
the client retries with bounded backoff up to the TTL window before treating the
session as lost (see §7).

## 4. Technical Design

### 4.1 Domain & DTO models (`core-model`)

```kotlin
data class PresenceSession(
    val streamId: String,
    val sessionToken: String,
    val viewerCount: Int,
    val heartbeatIntervalMs: Long,
    val ttlMs: Long,
)

@JsonClass(generateAdapter = true)
data class JoinRequest(@Json(name = "client_session_id") val clientSessionId: String)

@JsonClass(generateAdapter = true)
data class PresenceResponse(
    @Json(name = "session_token") val sessionToken: String,
    @Json(name = "viewer_count") val viewerCount: Int,
    @Json(name = "heartbeat_interval_s") val heartbeatIntervalS: Int = 15,
    @Json(name = "ttl_s") val ttlS: Int = 45,
)

@JsonClass(generateAdapter = true)
data class HeartbeatRequest(@Json(name = "session_token") val sessionToken: String)

@JsonClass(generateAdapter = true)
data class HeartbeatResponse(
    @Json(name = "viewer_count") val viewerCount: Int,
    @Json(name = "ttl_s") val ttlS: Int = 45,
)
```

`clientSessionId` is a per-watch-session UUID generated by the ViewModel so the
server can de-duplicate retried joins.

### 4.2 Network (`core-network`)

```kotlin
interface PresenceApi {
    @POST("ui/streams/{id}/presence/join")
    suspend fun join(
        @Path("id") streamId: String,
        @Body body: JoinRequest,
    ): Response<PresenceResponse>

    @POST("ui/streams/{id}/presence/heartbeat")
    suspend fun heartbeat(
        @Path("id") streamId: String,
        @Body body: HeartbeatRequest,
    ): Response<HeartbeatResponse>

    @POST("ui/streams/{id}/presence/leave")
    suspend fun leave(
        @Path("id") streamId: String,
        @Body body: HeartbeatRequest,
    ): Response<Unit>
}
```

`X-CSRF-Token`, cookies, the 20 s timeout, and the single `401 → refresh →
retry` interceptor are provided by the shared OkHttp client; `PresenceApi` adds
nothing of its own. The shared `ApiResult<T>` wrapper and `detail` error mapper
(string | `[{msg}]` | `{code,...}`) are applied in the repository.

### 4.3 Repository (`core-data`)

```kotlin
interface PresenceRepository {
    suspend fun join(streamId: String, clientSessionId: String): ApiResult<PresenceSession>
    suspend fun heartbeat(streamId: String, token: String): ApiResult<PresenceHeartbeat>
    suspend fun leave(streamId: String, token: String)   // best-effort, never throws
}
```

`leave` swallows all exceptions (logs and returns) so teardown paths can call it
without try/catch. `join`/`heartbeat` return `ApiResult` mapped from `Response`.

### 4.4 Presence controller (the lifecycle engine)

The heartbeat loop and lifecycle are encapsulated in a `PresenceController`
created by the `ViewerPlaybackViewModel` and bound to `viewModelScope`:

```kotlin
class PresenceController(
    private val repo: PresenceRepository,
    private val scope: CoroutineScope,
    private val clock: Clock = Clock.System,
    private val gracePeriodMs: Long = 30_000L,
) {
    val state: StateFlow<PresenceUiState>        // count + stale flag + connection state
    fun start(streamId: String)                  // join + launch heartbeat loop (idempotent)
    fun onForeground()
    fun onBackground()                           // pause loop, arm grace timer
    fun stop()                                   // cancel loop, fire best-effort leave
}
```

Heartbeat loop (single coroutine, `delay(interval)` between ticks; jittered ±10%
to avoid thundering herd). The loop is the *only* writer of presence state. The
grace timer is a separate cancellable child job.

### 4.5 ViewModel & UI integration (`feature-viewer`)

`ViewerPlaybackViewModel` (from AND-280) gains a `PresenceController`. It calls
`start(streamId)` after `playback/verify` + first ExoPlayer `STATE_READY`, wires
`onForeground`/`onBackground` from a `DefaultLifecycleObserver` collected by the
Composable, and calls `stop()` in `onCleared()`. The viewer count is merged into
the existing `ViewerPlaybackUiState` (or exposed as a sibling `StateFlow`) and
rendered by a `ViewerCountBadge` composable overlaid on the player surface.

```kotlin
@Composable
fun ViewerCountBadge(count: Int, isStale: Boolean, modifier: Modifier = Modifier)
```

A `DisposableEffect(lifecycleOwner)` registers the observer and ensures `leave`
fires on disposal.

## 5. API Contract

All paths are relative to the API base; all calls are cookie-authenticated and
send `X-CSRF-Token`. Paths in §4.2 are the working assumption and MUST be
verified against live `/openapi.json` and the web reference before merge (§13);
if the backend uses a flat `/ui/presence/*` shape with `stream_id` in the body,
adjust `PresenceApi` accordingly — the repository/controller contract is stable.

**Join** — `POST /ui/streams/{id}/presence/join`
```json
// request
{ "client_session_id": "8f3c...uuid" }
// 200
{ "session_token": "ps_01H...", "viewer_count": 42,
  "heartbeat_interval_s": 15, "ttl_s": 45 }
```

**Heartbeat** — `POST /ui/streams/{id}/presence/heartbeat`
```json
// request
{ "session_token": "ps_01H..." }
// 200
{ "viewer_count": 43, "ttl_s": 45 }
```

**Leave** — `POST /ui/streams/{id}/presence/leave`
```json
// request
{ "session_token": "ps_01H..." }
// 204 No Content
```

Status handling: `200/204` success; `401` → handled by shared refresh-once
interceptor; `404`/`410` on heartbeat/leave → token expired/unknown → treat as
session lost (re-join allowed if screen still active); `403` → not authorized
(should not occur post-verify; surface as fatal); `5x`/timeout → retryable per
§7. Errors carry FastAPI `detail` mapped by the shared mapper.

## 6. Data & State Management

```kotlin
data class PresenceUiState(
    val viewerCount: Int = 0,
    val isStale: Boolean = false,          // last successful heartbeat older than 1 interval
    val connection: ConnectionState = ConnectionState.Idle,
    val hasSession: Boolean = false,
)
enum class ConnectionState { Idle, Joining, Live, Reconnecting, Lost }
```

- The active `session_token`, `clientSessionId`, `heartbeatIntervalMs`, and
  `lastHeartbeatAt` live **in memory only** in the `PresenceController`; they are
  watch-session scoped and intentionally NOT persisted (a presence session does
  not survive process death — the server TTL reaps it).
- No Room or DataStore writes are required for presence. (Room/cache and DataStore
  prefs remain owned by their respective tickets.)
- `state` is a `MutableStateFlow` updated only by the heartbeat loop coroutine,
  giving single-writer semantics and avoiding races. `isStale` is recomputed each
  tick from `clock.now() - lastHeartbeatAt`.
- Count never resets to 0 on transient failure: on error the loop keeps the last
  `viewerCount` and flips `isStale = true` / `connection = Reconnecting`.

## 7. Error Handling & Resilience

- **Join failure:** retry up to 3 attempts with backoff (1 s, 2 s, 4 s, full
  jitter, cap 8 s). The 20 s client timeout applies per attempt. If all fail,
  `connection = Lost`; playback (AND-280) continues unaffected — presence is
  non-blocking. A manual "reconnect" is implied by returning to foreground.
- **Heartbeat failure:** do NOT drop on first failure. Retry the tick with
  bounded backoff; keep retrying until the cumulative time since the last success
  exceeds `ttlMs` (server TTL, ~45 s), then mark `connection = Lost` and stop the
  loop. While retrying, `connection = Reconnecting`, `isStale = true`. A `404/410`
  means the server already reaped us → stop retrying, mark Lost, allow re-join.
- **Idempotency:** join carries `client_session_id` so a retried join after a
  successful-but-lost response does not create a second presence record. Heartbeat
  and leave are naturally idempotent on `session_token`.
- **Retry scope:** presence POSTs are not idempotent GETs, so they do NOT use the
  global GET backoff layer; the controller owns its own bounded retry with the
  idempotency key above. Leave is single-shot best-effort (one attempt, 5 s
  timeout) so teardown is never blocked.
- **Process death:** no leave is sent; the server TTL expires the record. This is
  acceptable and is the reason TTL is short.
- **Offline:** if the device is offline at join, `connection = Lost`, count badge
  hidden or shows last-known with stale styling; loop resumes on connectivity via
  the lifecycle resume path.

## 8. Security & Privacy

- All presence calls reuse the authenticated cookie jar + `X-CSRF-Token`; no new
  credentials or storage are introduced. The 401-refresh-once flow is inherited.
- `session_token` is server-issued, opaque, in-memory only, and never logged in
  full (see §10) nor written to disk.
- `client_session_id` is a random UUIDv4 with no PII; not persisted.
- Viewer count is aggregate; the client neither receives nor displays identities
  of other viewers, so no other-user PII is handled.
- Plaintext HTTP on the dev host is a known environment constraint; presence adds
  no secrets beyond the existing session cookie already sent on every UI call.

## 9. Accessibility & i18n

- `ViewerCountBadge` exposes a `contentDescription` via
  `stringResource(R.string.viewer_count_cd, count)` ("N watching"), using a
  plural resource (`<plurals name="viewer_count">`). The stale state adds a
  distinct description ("N watching, reconnecting").
- Color is not the sole signal for the stale state: an icon/opacity change
  accompanies any color change; contrast meets WCAG AA against the player surface
  (badge has a scrim background).
- Count digits are localized via the default number formatting; all visible
  strings are in `strings.xml` (no hardcoded text). Badge respects dynamic font
  scaling and does not truncate at large counts (formats 1.2K for ≥10000).
- Live count updates use `liveRegion = LiveRegionMode.Polite` so TalkBack
  announces changes without stealing focus from playback controls.

## 10. Telemetry & Logging

Events via the `core-data` logging facade (structured, no PII, token redacted to
last 4 chars):

- `presence_join` { stream_id, result, latency_ms, viewer_count }
- `presence_heartbeat_fail` { stream_id, attempt, http_status, reason }
- `presence_session_lost` { stream_id, reason: ttl_exceeded|reaped|offline }
- `presence_leave` { stream_id, trigger: navigate|background|cleared, result }

Debug-level logs around loop start/stop, grace timer arm/fire, and
foreground/background transitions to aid diagnosing leaked sessions. No full
`session_token`, no cookies, no `client_session_id` are logged.

## 11. Testing Strategy

Unit (`core-testing`, fake `PresenceRepository`, virtual-time `TestScope` +
`StandardTestDispatcher`, injectable `Clock`):

- Join success → `Live`, count set, loop scheduled at interval.
- Heartbeat tick advances `viewer_count` and resets `lastHeartbeatAt`.
- Single heartbeat failure → `Reconnecting`, count retained, retry occurs; success
  within TTL → back to `Live`.
- Failures past TTL window → `Lost`, loop stopped.
- `404/410` heartbeat → immediate `Lost`, no further retries, re-join permitted.
- `onBackground` arms grace; foreground within grace resumes without re-join;
  grace elapses → `leave` sent, session torn down.
- `stop()`/`onCleared` sends exactly one `leave`; double-stop sends none extra.
- No duplicate `join` for one controller instance; re-`start` reuses live token.
- Join retry uses `client_session_id` (same id across retried attempts).

Repository: `Response` → `ApiResult` mapping incl. `detail` shapes; `leave`
never throws on network error.

Instrumented/UI (Compose test): `ViewerCountBadge` renders count and stale
state; `contentDescription` correct; `DisposableEffect` fires `leave` on
disposal (verified via fake VM).

Coverage target: ≥85% on `PresenceController` and `PresenceRepository`.

## 12. Dependencies & Sequencing

- **Depends on AND-280** (Viewer playback / HLS) — provides the screen,
  `ViewerPlaybackViewModel`, ExoPlayer state to gate `join`, and the
  `playback/verify` authorization that must succeed before presence starts.
- Reuses the shared `core-network` OkHttp/Retrofit client, cookie jar, CSRF
  interceptor, `ApiResult`, and `detail` mapper (established by the auth/network
  foundation tickets); no new infrastructure.
- Sequencing: implement `core-model` DTOs → `PresenceApi` → `PresenceRepository`
  (+ tests) → `PresenceController` (+ virtual-time tests) → wire into AND-280
  ViewModel/screen + `ViewerCountBadge`. Backend `/openapi.json` reconciliation
  (§13) gates the `core-network`/contract step.

## 13. Risks & Open Questions

- **R1 (contract drift):** §5 paths/shapes were not verifiable against the live
  dev host (ECONNREFUSED). MUST confirm exact paths, body vs path placement of
  stream id, token field names, and whether count arrives via heartbeat polling
  vs a push/WebSocket channel before implementing `PresenceApi`. Mitigation:
  repository/controller boundary isolates churn.
- **R2 (count freshness):** if the backend only returns count on join/heartbeat,
  freshness is bounded by `heartbeat_interval_s`; if a dedicated count poll or
  realtime channel exists it should be preferred — open question.
- **R3 (background policy):** the 30 s grace and "leave on grace expiry" policy
  is a product decision; confirm desired behavior for picture-in-picture
  (if AND-280 enables PiP, presence should persist during PiP).
- **R4 (server TTL):** assumes server-side TTL reaps abandoned sessions; confirm
  `ttl_s` is authoritative and that no client leave is required for correctness on
  process death.
- **R5 (unreliable host):** frequent heartbeat failures on the dev backend may
  produce noisy `Reconnecting` UI; tune jitter/backoff after live testing.

## 14. Acceptance Criteria

- AC-1 Opening an authorized live stream triggers exactly one `join`; the viewer
  count badge appears with the server-provided count within one interval.
- AC-2 A heartbeat is sent every `heartbeat_interval_s` (±10% jitter) while the
  player is foregrounded; each updates the displayed count.
- AC-3 Navigating away, releasing the player, or `onCleared` sends exactly one
  `leave`; no presence session is leaked.
- AC-4 Backgrounding beyond the grace window sends `leave`; returning within grace
  resumes heartbeating (re-joining only if the token expired) with no duplicate
  active session.
- AC-5 A transient heartbeat failure does not zero the count or drop the session;
  the badge shows the last-known count with a stale indicator and recovers to
  Live on the next success within the TTL window.
- AC-6 Failures persisting past the TTL window (or `404/410`) move the session to
  Lost and stop the loop without crashing or affecting playback.
- AC-7 Join retries reuse the same `client_session_id` so no duplicate
  server-side presence record is created.
- AC-8 The badge has a correct localized `contentDescription`, announces updates
  politely to TalkBack, and conveys stale state by more than color.

## 15. Definition of Done

- All code under `com.testlogon.android.*` (`core-model`, `core-network`,
  `core-data`, `feature-viewer`); modules respect `app → feature-* → core-*`.
- `PresenceApi`, `PresenceRepository`, `PresenceController`, and
  `ViewerCountBadge` implemented and wired into AND-280's viewer screen/ViewModel.
- §5 contract reconciled against live `/openapi.json` and the web reference;
  any deviations recorded in the spec/PR.
- Unit + UI tests in §11 pass; `PresenceController`/`PresenceRepository` coverage
  ≥85%; tests use virtual time (no real delays) and run in CI.
- `./gradlew :feature-viewer:test :core-data:test ktlintCheck detekt assembleDebug`
  green; no new lint/detekt regressions.
- No `session_token`/cookies/PII in logs; telemetry events from §10 emitted.
- Strings localized; accessibility checks (AC-8) verified with TalkBack.
- All acceptance criteria (§14) demonstrably met on the dev backend; PR links
  this ticket and notes AND-280 dependency. Manual smoke: open stream, observe
  count change with a second viewer, background/foreground, navigate away, and
  confirm the server presence record is released.
