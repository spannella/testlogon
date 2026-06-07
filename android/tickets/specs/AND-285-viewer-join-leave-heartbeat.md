---
id: AND-285
title: Viewer join/leave/heartbeat
milestone: M6
epic: E38
priority: P1
size: M
depends_on: [AND-280]
blocks: []
status: reviewed
reviewed_on: 2026-06-07
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
- Auth (CORRECTED against `reference/src/api/client.ts`): the web client sends,
  on every call, **all** of: `Authorization: Bearer <accessToken>` (from the auth
  store), the persistent cookies (`credentials: include`), the `ui_csrf` cookie
  echoed as the `X-CSRF-Token` header, and — when impersonating — an
  `X-IMPERSONATION-TOKEN` header. The Android OkHttp client MUST replicate all of
  these (Bearer + cookie jar + CSRF + optional impersonation), not cookies+CSRF
  alone as an earlier draft stated. On `401` (only when already authenticated) the
  client calls `POST /ui/session/refresh` once then retries exactly one time;
  this matches `client.ts` and is Verified. Presence calls are authenticated and
  ride the same client. Note the backend also accepts `X-SESSION-ID` and
  `user_sub` as alternate identity inputs on these routes (see OpenAPI params),
  but the web reference relies on Bearer+cookies, so the Android port should too.
- Module layering: `feature-viewer` (screen + ViewModel) → `core-data`
  (`PresenceRepository`) → `core-network` (`PresenceApi`, shared OkHttp/Retrofit,
  `ApiResult<T>`) → `core-model` (presence DTOs/domain). Telemetry via the
  existing logging facade in `core-data`.
- Backend is FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is
  plaintext HTTP and unreliable; design for ~20 s timeouts, bounded backoff retry
  for idempotent GETs only, and offline/stale UI. OpenAPI at `/openapi.json`.
  The §5 contract has now been RECONCILED against the captured OpenAPI spec
  (`reference/openapi.index.txt` / `openapi.pretty.json`) and the web reference
  app; the earlier `/ui/streams/*` guesses were wrong and have been corrected in
  place (see §16 for the full audit).
- Web reference (CORRECTED): presence wiring lives in
  `reference/src/hooks/useViewerHeartbeat.ts` — it joins on mount, heartbeats
  every 30 s, and leaves on unmount/unload. The endpoints are under
  `/broadcast/sessions/{session_id}/viewers/*`, NOT `/ui/streams/*` and NOT a
  `streams.ts`/`presence.ts` endpoints module. The viewer-count poll uses
  `GET /broadcast/sessions/{session_id}/viewers/count`.

## 3. Functional Requirements

FR-1 **Join on play start.** When AND-280's playback authorization
(`GET /broadcast/playback/verify` + `POST /broadcast/sessions/{session_id}/playback-url`)
succeeds and ExoPlayer reaches a startable state for broadcast `sessionId`, the
client issues a single `join` (`POST /broadcast/sessions/{sessionId}/viewers/join`)
and obtains a server-issued **`viewer_id`** plus the current `viewer_count`.
(CORRECTED: the backend issues `viewer_id`, not a `session_token`; there is no
`session_token`/`client_session_id` concept in the contract.)

FR-2 **Heartbeat while active.** While the screen is in the foreground and the
join succeeded, the client sends a heartbeat every **30 s** (client-fixed
interval, matching `useViewerHeartbeat.ts` and the route's own description
"Call every 30s"; the server does NOT return a `heartbeat_interval_s`). Each
heartbeat (`POST .../viewers/heartbeat?viewer_id=...`) keeps the viewer session
alive and returns `{ ok, viewer_count }`.

FR-3 **Leave on teardown.** On any of: navigating away, player release, app
backgrounding beyond a grace window, or explicit close, the client issues a
`leave` (`POST .../viewers/leave?viewer_id=...`) for the active `viewer_id`.
Leave is best-effort and idempotent.

FR-4 **Viewer count display.** The current `viewer_count` is rendered as a live
badge overlay on the player. It updates from every join/heartbeat response and,
when offline/stale, shows the last-known value with a stale indicator rather than
zero.

FR-5 **No duplicate sessions.** A given `ViewerPlaybackViewModel` instance holds
at most one active presence session. Re-entering play (e.g. recover from error)
reuses the existing `viewer_id` if still believed live, otherwise re-joins.

FR-6 **Background/foreground.** On `ON_STOP` the heartbeat loop pauses and a
short grace timer (default 30 s) starts; if the app returns to foreground within
grace the loop resumes (re-joining if the `viewer_id` was reaped); if grace
elapses the client sends `leave` and tears down the session.

FR-7 **Resilience.** A failed heartbeat does not immediately drop the session;
the client retries with bounded backoff up to the TTL window before treating the
session as lost (see §7).

## 4. Technical Design

### 4.1 Domain & DTO models (`core-model`)

CORRECTED to the real backend shapes (`ViewerJoinOut`, `ViewerHeartbeatOut`,
`ViewerCountOut` in `openapi.pretty.json`). All three viewer mutations take **no
JSON body** — identity flows via path (`session_id`) and query
(`viewer_id`/`invite_token`). There is no `session_token`, no
`heartbeat_interval_s`, and no `ttl_s` in any response.

```kotlin
data class PresenceSession(
    val sessionId: String,       // broadcast session id (path param)
    val viewerId: String,        // server-issued identity for heartbeat/leave
    val viewerCount: Int,
)

// Join — POST /broadcast/sessions/{sessionId}/viewers/join  (optional ?invite_token=)
// No request body. Response = ViewerJoinOut:
@JsonClass(generateAdapter = true)
data class ViewerJoinOut(
    @Json(name = "viewer_id") val viewerId: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "viewer_count") val viewerCount: Int,
)

// Heartbeat — POST .../viewers/heartbeat?viewer_id=...  (no body). Response = ViewerHeartbeatOut:
@JsonClass(generateAdapter = true)
data class ViewerHeartbeatOut(
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "viewer_count") val viewerCount: Int,
)

// Count poll — GET .../viewers/count  → ViewerCountOut:
@JsonClass(generateAdapter = true)
data class ViewerCountOut(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "viewer_count") val viewerCount: Int,
)

// Leave — POST .../viewers/leave?viewer_id=...  → 200 with empty/ignored body.
```

Since the backend de-duplicates by the server-issued `viewer_id` (returned by
join) rather than a client-supplied idempotency key, there is **no
`client_session_id`** — the earlier draft invented one. To avoid creating a
second presence record, the controller must guard so that at most one join is
in flight / succeeded per controller instance (see §7).

### 4.2 Network (`core-network`)

CORRECTED Retrofit interface — broadcast paths, no `@Body`, `viewer_id` as a
query parameter (matching `useViewerHeartbeat.ts` and the OpenAPI `params`):

```kotlin
interface PresenceApi {
    @POST("broadcast/sessions/{sessionId}/viewers/join")
    suspend fun join(
        @Path("sessionId") sessionId: String,
        @Query("invite_token") inviteToken: String? = null,
    ): Response<ViewerJoinOut>

    @POST("broadcast/sessions/{sessionId}/viewers/heartbeat")
    suspend fun heartbeat(
        @Path("sessionId") sessionId: String,
        @Query("viewer_id") viewerId: String,
    ): Response<ViewerHeartbeatOut>

    @POST("broadcast/sessions/{sessionId}/viewers/leave")
    suspend fun leave(
        @Path("sessionId") sessionId: String,
        @Query("viewer_id") viewerId: String,
    ): Response<Unit>

    @GET("broadcast/sessions/{sessionId}/viewers/count")
    suspend fun count(
        @Path("sessionId") sessionId: String,
    ): Response<ViewerCountOut>
}
```

`Authorization: Bearer`, cookies, `X-CSRF-Token`, optional
`X-IMPERSONATION-TOKEN`, the 20 s timeout, and the single `401 → refresh →
retry` interceptor are provided by the shared OkHttp client; `PresenceApi` adds
nothing of its own. The shared `ApiResult<T>` wrapper and `detail` error mapper
(string | `[{msg}]` | `{code,...}`, per `normalizeErrorDetail` in `client.ts`)
are applied in the repository.

### 4.3 Repository (`core-data`)

```kotlin
interface PresenceRepository {
    suspend fun join(sessionId: String, inviteToken: String? = null): ApiResult<PresenceSession>
    suspend fun heartbeat(sessionId: String, viewerId: String): ApiResult<PresenceHeartbeat>
    suspend fun leave(sessionId: String, viewerId: String)   // best-effort, never throws
    suspend fun count(sessionId: String): ApiResult<Int>     // optional dedicated count poll
}
```

(CORRECTED: `clientSessionId` removed — no such field exists; `token` →
`viewerId`; `streamId` → broadcast `sessionId`. A `count` method is added since
the backend exposes a dedicated `GET .../viewers/count` endpoint, useful as an
out-of-band freshness poll — see §16 R2.) `leave` swallows all exceptions (logs
and returns) so teardown paths can call it without try/catch. `join`/`heartbeat`
return `ApiResult` mapped from `Response`.

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
    fun start(sessionId: String)                 // join + launch heartbeat loop (idempotent)
    fun onForeground()
    fun onBackground()                           // pause loop, arm grace timer
    fun stop()                                   // cancel loop, fire best-effort leave
}
```

(CORRECTED: `start(streamId)` → `start(sessionId)`.) Heartbeat loop is a single
coroutine using a **client-fixed 30 s** interval (`heartbeatIntervalMs = 30_000`,
matching `useViewerHeartbeat.ts`; the server does not supply one), `delay(interval)`
between ticks, jittered ±10% to avoid thundering herd. The loop is the *only*
writer of presence state. The grace timer is a separate cancellable child job.

### 4.5 ViewModel & UI integration (`feature-viewer`)

`ViewerPlaybackViewModel` (from AND-280) gains a `PresenceController`. It calls
`start(sessionId)` after playback authorization (`/broadcast/playback/verify` +
`/broadcast/sessions/{sessionId}/playback-url`) + first ExoPlayer `STATE_READY`, wires
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

All paths are relative to the API base; all calls send `Authorization: Bearer` +
cookies + `X-CSRF-Token` (+ optional `X-IMPERSONATION-TOKEN`). This contract is
VERIFIED against `reference/openapi.index.txt` / `openapi.pretty.json` and
`reference/src/hooks/useViewerHeartbeat.ts`. All three mutations take **no JSON
body**; identity is `session_id` (path) + `viewer_id`/`invite_token` (query). The
optional `user_sub` query param is server-side and not used by the web client.

**Join** — `POST /broadcast/sessions/{session_id}/viewers/join[?invite_token=...]`
(op `viewer_join_route...`, resp `ViewerJoinOut`)
```json
// request: (no body)
// 200 — ViewerJoinOut
{ "viewer_id": "v_01H...", "session_id": "sess_01H...", "viewer_count": 42 }
```

**Heartbeat** — `POST /broadcast/sessions/{session_id}/viewers/heartbeat?viewer_id=...`
(op `viewer_heartbeat_route...`, resp `ViewerHeartbeatOut`; route doc: "Call every 30s")
```json
// request: (no body)
// 200 — ViewerHeartbeatOut
{ "ok": true, "viewer_count": 43 }
```

**Leave** — `POST /broadcast/sessions/{session_id}/viewers/leave?viewer_id=...`
(op `viewer_leave_route...`, route doc: "Called on page unload via sendBeacon")
```json
// request: (no body)
// 200 — empty/ignored body (NOT 204)
```

**Count (optional poll)** — `GET /broadcast/sessions/{session_id}/viewers/count`
(op `viewer_count_route...`, resp `ViewerCountOut`)
```json
// 200 — ViewerCountOut
{ "session_id": "sess_01H...", "viewer_count": 44 }
```

Status handling: `200` success (leave returns 200, not 204); `401` → handled by
shared refresh-once interceptor (`POST /ui/session/refresh`); `422` →
`HTTPValidationError` with `detail: [{loc,msg,type}]` (e.g. missing/invalid
`viewer_id`) — for heartbeat/leave treat a 422 about an unknown `viewer_id` as
session lost (re-join allowed if screen still active); `403` → not authorized /
geo-blocked (`detail.code` may be `geo_blocked` or a role code) — should not
occur post-verify; surface as fatal; `5xx`/timeout → retryable per §7. NOTE: the
backend documents only `200`/`422` for these routes — `404`/`410` are NOT in the
OpenAPI for viewer endpoints, so the "session lost" trigger is `422`/`5xx`/timeout
rather than `404`/`410` (the earlier draft assumed `404`/`410`). Errors carry the
FastAPI `detail` mapped by the shared mapper (`normalizeErrorDetail`).

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

- The active `viewerId`, `sessionId`, the fixed `heartbeatIntervalMs` (30 s), and
  `lastHeartbeatAt` live **in memory only** in the `PresenceController`; they are
  watch-session scoped and intentionally NOT persisted (a presence session does
  not survive process death — the server reaps abandoned viewers server-side).
  (CORRECTED: `session_token`/`clientSessionId` → `viewerId`; the server TTL is
  not exposed to the client — see §16 R4.)
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
  bounded backoff; keep retrying until a client-side "lost window" elapses
  (CORRECTED: the server does not expose a TTL, so use a client constant —
  recommend `lostWindowMs ≈ 3 × interval = 90 s`), then mark `connection = Lost`
  and stop the loop. While retrying, `connection = Reconnecting`, `isStale = true`.
  A `422` referencing an unknown/invalid `viewer_id` means the server already
  reaped us → stop retrying, mark Lost, allow re-join. (Earlier draft cited
  `404/410`; those statuses are not in the OpenAPI for these routes.)
- **Idempotency:** there is no client-supplied idempotency key; the controller
  guards with a single-flight join (a `Mutex`/state check so only one join is in
  flight and a successful join is not repeated for a live `viewerId`). A
  successful-but-lost-response join can transiently leak one extra record server
  side; this is bounded by server reaping and is acceptable. Heartbeat and leave
  are idempotent on the server-issued `viewer_id`.
- **Retry scope:** presence POSTs are not idempotent GETs, so they do NOT use the
  global GET backoff layer; the controller owns its own bounded retry plus the
  single-flight guard above. Leave is single-shot best-effort (one attempt, 5 s
  timeout) so teardown is never blocked.
- **Process death:** no leave is sent; the server reaps the abandoned viewer
  server-side. This is acceptable (and why heartbeats are frequent).
- **Offline:** if the device is offline at join, `connection = Lost`, count badge
  hidden or shows last-known with stale styling; loop resumes on connectivity via
  the lifecycle resume path.

## 8. Security & Privacy

- All presence calls reuse the authenticated transport (`Authorization: Bearer` +
  cookie jar + `X-CSRF-Token` + optional `X-IMPERSONATION-TOKEN`); no new
  credentials or storage are introduced. The 401-refresh-once flow is inherited.
- `viewer_id` is server-issued, opaque, in-memory only, and never logged in
  full (see §10) nor written to disk. (CORRECTED: the identity is `viewer_id`,
  not a `session_token`.)
- There is no `client_session_id` (the earlier draft invented one); nothing
  client-generated is sent.
- Viewer count is aggregate; the client neither receives nor displays identities
  of other viewers, so no other-user PII is handled.
- Plaintext HTTP on the dev host is a known environment constraint; presence adds
  no secrets beyond the credentials already sent on every authenticated call.

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
- Failures past the client-side lost window (≈3×interval = 90 s) → `Lost`, loop stopped.
- `422` heartbeat referencing an unknown/invalid `viewer_id` → immediate `Lost`,
  no further retries, re-join permitted. (CORRECTED: the backend documents only
  `200`/`422` for these routes; `404`/`410` are NOT in the OpenAPI.)
- `onBackground` arms grace; foreground within grace resumes without re-join;
  grace elapses → `leave` sent, session torn down.
- `stop()`/`onCleared` sends exactly one `leave`; double-stop sends none extra.
- No duplicate `join` for one controller instance; re-`start` reuses the live
  `viewer_id`.
- Single-flight join guard: concurrent `start()` calls produce at most one
  `join` (no `client_session_id` exists — de-dup is on the server-issued
  `viewer_id`).

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
- AC-2 A heartbeat is sent every 30 s (client-fixed interval, ±10% jitter; the
  server does not return a `heartbeat_interval_s`) while the player is
  foregrounded; each updates the displayed count.
- AC-3 Navigating away, releasing the player, or `onCleared` sends exactly one
  `leave`; no presence session is leaked.
- AC-4 Backgrounding beyond the grace window sends `leave`; returning within grace
  resumes heartbeating (re-joining only if the token expired) with no duplicate
  active session.
- AC-5 A transient heartbeat failure does not zero the count or drop the session;
  the badge shows the last-known count with a stale indicator and recovers to
  Live on the next success within the lost window.
- AC-6 Failures persisting past the client lost window (≈90 s), or a `422`
  referencing an unknown `viewer_id`, move the session to Lost and stop the loop
  without crashing or affecting playback. (CORRECTED: not `404/410` — only
  `200`/`422` are in the OpenAPI for these routes.)
- AC-7 The single-flight join guard ensures concurrent/repeated `start()` for a
  live `viewer_id` issues at most one `join`, so no duplicate server-side
  presence record is created. (CORRECTED: there is no `client_session_id`;
  de-dup is on the server-issued `viewer_id`.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend =
`reference/src/...`.

1. **Join is `POST /broadcast/sessions/{session_id}/viewers/join`, optional
   `?invite_token=`, no body, resp `ViewerJoinOut`.** — **Verified.** OpenAPI
   `POST /broadcast/sessions/{session_id}/viewers/join`
   (op `viewer_join_route...`, `req=`, `resp=200:ViewerJoinOut;422:HTTPValidationError`,
   `params=session_id,invite_token,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`);
   frontend `src/api/endpoints/broadcast.ts: viewerJoin`;
   `src/hooks/useViewerHeartbeat.ts` (line 20).
2. **`ViewerJoinOut` = `{ viewer_id: string, session_id: string,
   viewer_count: int }`, all required.** — **Verified.** OpenAPI spec
   `components.schemas.ViewerJoinOut` (required: `viewer_id, session_id,
   viewer_count`). Matches the inline type at `useViewerHeartbeat.ts` line 20.
3. **Heartbeat is `POST .../viewers/heartbeat?viewer_id=...`, no body, resp
   `ViewerHeartbeatOut` = `{ ok: bool, viewer_count: int }`.** — **Verified.**
   OpenAPI `POST /broadcast/sessions/{session_id}/viewers/heartbeat`
   (`params=session_id,viewer_id,...`, `resp=200:ViewerHeartbeatOut;422:...`);
   schema `components.schemas.ViewerHeartbeatOut` (required: `ok, viewer_count`);
   frontend `broadcast.ts: viewerHeartbeat` (`viewer_id` passed as query param).
4. **Heartbeat interval is a client-fixed 30 s; the server returns NO
   `heartbeat_interval_s`.** — **Verified.** `useViewerHeartbeat.ts` line 4
   (`const HEARTBEAT_INTERVAL = 30_000`) + line 24 `setInterval`; the route doc/
   schema `ViewerHeartbeatOut` contains no interval field (OpenAPI spec).
5. **Leave is `POST .../viewers/leave?viewer_id=...`, no body, returns 200 with
   no declared schema (NOT 204).** — **Verified.** OpenAPI
   `POST /broadcast/sessions/{session_id}/viewers/leave`
   (`resp=200:;422:HTTPValidationError`); frontend `broadcast.ts: viewerLeave`.
   Note: `broadcast.ts` types the leave response as `{ ok, viewer_count }`, but
   the OpenAPI declares no response schema for the 200 — Android maps it to
   `Response<Unit>` and ignores the body, which is safe either way.
6. **Count poll is `GET .../viewers/count`, resp `ViewerCountOut` =
   `{ session_id: string, viewer_count: int }`.** — **Verified.** OpenAPI
   `GET /broadcast/sessions/{session_id}/viewers/count`
   (`resp=200:ViewerCountOut;422:HTTPValidationError`); schema
   `components.schemas.ViewerCountOut`; frontend `broadcast.ts: getViewerCount`.
7. **No JSON request body on any of join/heartbeat/leave; identity via path
   (`session_id`) + query (`viewer_id`/`invite_token`).** — **Verified.** All four
   index lines show `req=` (empty) and identity in `params=`; `useViewerHeartbeat.ts`
   posts with no body and `viewer_id` in the query string.
8. **No `session_token`, no `client_session_id`, no `ttl_s`, no
   `heartbeat_interval_s` anywhere in the contract.** — **Verified (absence).**
   None appear in any of the four viewer schemas (`ViewerJoinOut`,
   `ViewerHeartbeatOut`, `ViewerCountOut`, leave has none) nor in the frontend
   hook/endpoint module. De-dup identity is the server-issued `viewer_id`.
9. **Server reaps abandoned viewers via a server-side TTL (no client leave needed
   on process death).** — **Unverified-assumption.** No TTL field is exposed in
   the OpenAPI and the live dev host was unreachable; reaping is implied by the
   `useViewerHeartbeat.ts` design (best-effort leave, frequent heartbeat) but the
   exact reap window is not documented. Drives the client `lostWindowMs ≈ 90 s`.
10. **Auth: every call sends `Authorization: Bearer <accessToken>` + cookies
    (`credentials: include`) + `X-CSRF-Token` (from the `ui_csrf` cookie) +
    optional `X-IMPERSONATION-TOKEN`.** — **Verified.** `src/api/client.ts`
    lines 157-171 (Bearer from `useAuthStore`, impersonation header, CSRF from
    `getCookie("ui_csrf")` → `X-CSRF-Token`) and `credentials: "include"`
    (lines 183, 220).
11. **On `401`, only when already authenticated, the client calls
    `POST /ui/session/refresh` once then retries exactly one time.** —
    **Verified.** `client.ts` `refreshSession()` (line 122
    `withApiBase("/ui/session/refresh")`, `method: "POST"`) and the 401 handler
    (lines 194-231): unauthenticated 401 propagates; authenticated 401 refreshes
    once, retries once, logs out on a second 401.
12. **Error mapper handles `detail` as string | array of `{msg}` | object with a
    code (`normalizeErrorDetail`).** — **Verified.** `client.ts` lines 66-95
    (string short-circuit; array `.map(item.msg)`; object → `mapAuthorizationError`).
13. **Error statuses for viewer routes are `200`/`422` only (no `404`/`410`).** —
    **Verified.** All four index lines list only `resp=200:...;422:HTTPValidationError`.
    `422` carries `HTTPValidationError.detail: [{loc,msg,type}]` (OpenAPI spec
    `components.schemas.HTTPValidationError`).
14. **AND-280 authorization gate is `GET /broadcast/playback/verify`
    (resp `BroadcastPlaybackTokenVerifyOut`) + `POST
    /broadcast/sessions/{session_id}/playback-url` (resp `BroadcastPlaybackUrlOut`).**
    — **Verified.** OpenAPI index lines for both ops. (Implementation owned by
    AND-280; cited here only as the precondition for `join`.)
15. **Web presence wiring: join on mount, heartbeat every 30 s, leave on
    unmount/`beforeunload` via `sendBeacon`.** — **Verified.**
    `src/hooks/useViewerHeartbeat.ts` lines 13-57 (join then `setInterval`
    heartbeat; cleanup clears the timer and posts leave; `beforeunload` uses
    `navigator.sendBeacon`).
16. **Endpoints live in `broadcast.ts` + `useViewerHeartbeat.ts`, NOT a
    `streams.ts`/`presence.ts` module, and paths are `/broadcast/...` not
    `/ui/streams/...`.** — **Verified.** `src/api/endpoints/broadcast.ts`
    exports `viewerJoin/viewerHeartbeat/viewerLeave/getViewerCount`; no
    `streams.ts`/`presence.ts` endpoints module matched the grep.
17. **Framework choices — Retrofit/OkHttp + Moshi, Media3/ExoPlayer (AND-280),
    Compose, `viewModelScope` coroutines, `DefaultLifecycleObserver`.** —
    **Unverified-assumption (framework ref).** Standard modern-Android stack
    consistent with the rest of the port; see Android docs:
    https://developer.android.com/topic/libraries/architecture/coroutines and
    https://developer.android.com/jetpack/androidx/releases/lifecycle
    (`DefaultLifecycleObserver`). Not derivable from backend/frontend sources.

### Corrections made

- **§11 Testing Strategy:** replaced two stale bullets that still contradicted the
  already-corrected §5/§7: the `404/410` heartbeat case → `422` (unknown
  `viewer_id`) case, and the "Join retry uses `client_session_id`" bullet →
  single-flight join guard on the server-issued `viewer_id`. Also changed "TTL
  window" wording to the client-side lost window (≈90 s).
- **§14 Acceptance Criteria:** AC-2 changed from "every `heartbeat_interval_s`" to
  the client-fixed 30 s (server returns no interval); AC-6 changed from
  "`404/410`" to the client lost window / `422` trigger; AC-7 changed from
  "reuse the same `client_session_id`" to the single-flight join guard on
  `viewer_id`. These align the acceptance criteria with the corrected contract.
- The body of the spec (§§1-10, §12-13, §15) was already reconciled by a prior
  pass and re-verified here as accurate; no further factual edits were needed.

### Open assumptions

- **Server reap TTL (claim 9):** not in the OpenAPI and the dev host was
  unreachable, so the exact abandoned-viewer reap window is unknown. The client
  picks `lostWindowMs ≈ 3×30 s = 90 s` as a safe heuristic; tune after live
  testing (mirrors §13 R4/R5).
- **Framework stack (claim 17):** Retrofit/OkHttp/Moshi/Media3/Compose are
  project-convention choices, not specified by the backend or web reference.
- **Count delivery mechanism (§13 R2):** verified that a dedicated
  `GET .../viewers/count` exists and that join/heartbeat also return the count;
  no realtime/WebSocket push channel for viewer count was found in the sources,
  so polling is assumed sufficient (unverifiable without product confirmation).
- **PiP behavior (§13 R3):** whether AND-280 enables picture-in-picture, and the
  desired presence policy during PiP, is a product decision not resolvable from
  these sources.

## 17. Test Plan

Test targets: **JVM** = JVM/Robolectric unit (no device); **MWS** =
contract test against OkHttp MockWebServer (JVM); **emu** = headless emulator AVD
`test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U,
API 34, arm64-v8a). Most cases here are headless/JVM or emulator UI; physical
device is only required where real backgrounding/Doze and real-network behavior
matter (called out per case).

- **TC-AND-285-01 — Join happy path.** Type: unit (JVM). Target: `PresenceController` +
  fake `PresenceRepository`, virtual-time `TestScope`. Preconditions: AND-280 auth
  succeeded, ExoPlayer `STATE_READY`. Steps: call `start(sessionId)`; repo returns
  `ViewerJoinOut{viewer_id, session_id, viewer_count=42}`; advance time 0. Expected:
  exactly one `join`; `connection = Live`; `viewerCount = 42`; `hasSession = true`;
  heartbeat loop scheduled at 30 s. Traces: AC-1.
- **TC-AND-285-02 — Heartbeat cadence and count update.** Type: unit (JVM,
  virtual time). Target: `PresenceController`. Preconditions: joined (TC-01).
  Steps: advance virtual time 30 s ×3; each heartbeat returns
  `ViewerHeartbeatOut{ok=true, viewer_count=43,44,45}`. Expected: exactly 3
  heartbeats fire at ~30 s ±10% jitter; `viewerCount` tracks each response;
  `lastHeartbeatAt` resets each tick; stays `Live`. Traces: AC-2, AC-5.
- **TC-AND-285-03 — Contract: join/heartbeat/leave/count wire shapes.** Type:
  contract/MockWebServer (JVM). Target: `PresenceApi` (Retrofit + Moshi).
  Preconditions: MWS enqueues canned 200 bodies from the real schemas. Steps:
  invoke `join`, `heartbeat`, `leave`, `count`. Expected: requests use
  `POST /broadcast/sessions/{id}/viewers/join` (no body), `.../heartbeat?viewer_id=`,
  `.../leave?viewer_id=` (POST, no body), `GET .../viewers/count`; responses
  deserialize to `ViewerJoinOut`/`ViewerHeartbeatOut`/`Unit`/`ViewerCountOut` with
  correct field mapping (`viewer_id`,`session_id`,`viewer_count`,`ok`). Traces:
  AC-1, AC-2.
- **TC-AND-285-04 — Auth headers on presence calls.** Type: contract/MockWebServer
  (JVM). Target: shared OkHttp client + `PresenceApi`. Preconditions: auth store
  has accessToken; `ui_csrf` cookie present; impersonation active. Steps: issue a
  `join`. Expected: recorded request carries `Authorization: Bearer <token>`,
  the cookie jar cookies, `X-CSRF-Token` = `ui_csrf` value, and
  `X-IMPERSONATION-TOKEN`. Traces: AC-1 (security precondition; ties to §8).
- **TC-AND-285-05 — 401 refresh-once then retry.** Type: contract/MockWebServer
  (JVM). Target: shared client interceptor + `PresenceRepository`. Preconditions:
  user authenticated; MWS returns 401 on first heartbeat, 200 on
  `POST /ui/session/refresh`, 200 on the retried heartbeat. Steps: call
  `heartbeat`. Expected: exactly one refresh call to `/ui/session/refresh`,
  exactly one retry, final `ApiResult` success; a second 401 instead would surface
  as auth failure without a second refresh. Traces: AC-5 (resilience), §8.
- **TC-AND-285-06 — Transient heartbeat failure keeps count, recovers.** Type:
  unit (JVM, virtual time). Target: `PresenceController`. Preconditions: joined,
  `viewer_count = 50`. Steps: next heartbeat returns 500/timeout, then a later
  attempt returns 200 `viewer_count=51` within the 90 s lost window. Expected: on
  failure `connection = Reconnecting`, `isStale = true`, count stays 50 (never 0),
  bounded backoff retry occurs; on success → `Live`, count 51, `isStale = false`.
  Traces: AC-5.
- **TC-AND-285-07 — Failures past lost window → Lost.** Type: unit (JVM, virtual
  time). Target: `PresenceController`. Preconditions: joined. Steps: every
  heartbeat fails for > 90 s (≈3×interval). Expected: `connection = Lost`, loop
  stopped, count retained as last-known with stale styling, no crash, playback
  unaffected. Traces: AC-6.
- **TC-AND-285-08 — 422 unknown viewer_id → immediate Lost, re-join allowed.**
  Type: unit (JVM) + contract/MWS for the error body. Target: `PresenceController`
  + `PresenceRepository`. Preconditions: joined. Steps: heartbeat returns 422 with
  `HTTPValidationError.detail=[{loc:["query","viewer_id"],msg:"...",type:"..."}]`.
  Expected: mapper extracts the `msg`; controller stops retrying, marks `Lost`;
  if the screen is still active a fresh `start()` issues a new `join`. Confirms the
  trigger is `422` (not `404`/`410`, which the OpenAPI does not define). Traces:
  AC-6.
- **TC-AND-285-09 — Single-flight join (no duplicate sessions).** Type: unit (JVM).
  Target: `PresenceController`. Preconditions: none. Steps: call `start(sessionId)`
  twice concurrently / re-`start` while a `viewer_id` is live. Expected: at most
  one `join` request; the live `viewer_id` is reused; no `client_session_id` is
  generated or sent. Traces: AC-7, AC-3.
- **TC-AND-285-10 — Background grace: resume within grace (no re-join).** Type:
  unit (JVM, virtual time). Target: `PresenceController`. Preconditions: joined.
  Steps: `onBackground()`; advance 20 s (< 30 s grace); `onForeground()`. Expected:
  loop paused on background, grace timer armed, NO `leave` sent; on foreground loop
  resumes with the same `viewer_id`, no new `join`. Traces: AC-4.
- **TC-AND-285-11 — Background grace expiry → leave + teardown.** Type: unit (JVM,
  virtual time). Target: `PresenceController`. Preconditions: joined. Steps:
  `onBackground()`; advance > 30 s grace. Expected: exactly one `leave` for the
  active `viewer_id`; session torn down; subsequent `onForeground()` performs a
  fresh `join`. Traces: AC-4, AC-3.
- **TC-AND-285-12 — Exactly-one leave on teardown / best-effort.** Type: unit
  (JVM). Target: `PresenceController` + `PresenceRepository`. Preconditions:
  joined. Steps: call `stop()` (navigate/`onCleared`); then call `stop()` again;
  separately, make `leave` throw a network error. Expected: first `stop` sends
  exactly one `leave`; double-stop sends no extra; `leave` swallows the network
  error (never throws, logged), so teardown is not blocked. Traces: AC-3.
- **TC-AND-285-13 — Offline at join.** Type: unit (JVM) + emulator
  airplane-mode integration. Target: `PresenceController` end-to-end on **emu**.
  Preconditions: device offline. Steps: `start(sessionId)` while offline; later
  restore connectivity and return to foreground. Expected: join fails → bounded
  retry (1/2/4 s) → `connection = Lost`; badge hidden or shows last-known with
  stale styling, never 0; playback (AND-280) unaffected; on connectivity + resume
  the loop re-joins. Traces: AC-5, AC-6.
- **TC-AND-285-14 — Real process-death / Doze: no leave, server reaps.** Type:
  instrumented/e2e. Target: full app, **device (REQUIRED)** — must run on the
  physical A15 because emulator Doze/process-kill and real backgrounding differ
  from headless. Preconditions: live stream open, second viewer present so count
  is observable; dev backend reachable. Steps: open stream (count increments);
  force-stop the app (or let Doze kill it); observe the server `viewers/count`
  from a second client. Expected: no `leave` is sent on hard kill; the count
  decrements after the server reap window; on relaunch a fresh `join` is issued.
  Traces: AC-3, AC-4, AC-6.
- **TC-AND-285-15 — ViewerCountBadge UI + accessibility.** Type: Compose-UI.
  Target: `ViewerCountBadge`. Preconditions: run on **emu** (CI). Steps: render
  with `count=1234, isStale=false` then `isStale=true`; inspect semantics. Expected:
  displays localized count (1.2K formatting for ≥10000); `contentDescription` uses
  the `viewer_count` plurals ("N watching" / "N watching, reconnecting"); stale
  state signalled by icon/opacity not color alone; `liveRegion = Polite` set; no
  truncation at large counts. Traces: AC-8.
- **TC-AND-285-16 — DisposableEffect fires leave on disposal.** Type: Compose-UI
  /instrumented. Target: viewer screen + fake VM, **emu**. Preconditions: screen
  composed with an active presence session. Steps: navigate away so the
  composition is disposed. Expected: the `DisposableEffect`/lifecycle observer
  triggers exactly one `leave`; no leaked session. Traces: AC-3.

### Coverage matrix

| AC | Description | Covered by |
| --- | --- | --- |
| AC-1 | Single join + count badge within one interval | TC-01, TC-03, TC-04 |
| AC-2 | Heartbeat every 30 s (±10%), updates count | TC-02, TC-03 |
| AC-3 | Exactly one leave on teardown, no leak | TC-09, TC-11, TC-12, TC-14, TC-16 |
| AC-4 | Background grace: resume vs leave, no dup session | TC-10, TC-11, TC-14 |
| AC-5 | Transient failure keeps count, recovers to Live | TC-02, TC-05, TC-06, TC-13 |
| AC-6 | Past lost window / 422 → Lost, playback unaffected | TC-07, TC-08, TC-13, TC-14 |
| AC-7 | Single-flight join → no duplicate presence record | TC-09 |
| AC-8 | Localized a11y, polite announce, stale ≠ color-only | TC-15 |
