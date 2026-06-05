---
id: AND-145
title: Presence + heartbeat
milestone: M3
epic: E20
priority: P1
size: M
status: draft
depends_on: [AND-143]
blocks: []
---

# AND-145 — Presence + heartbeat

## 1. Overview & Goal

This ticket delivers real-time **presence** for the TestLogon Android app: a
client that (a) periodically reports the local user as online to the backend via
a **heartbeat** while the app is in the foreground, and (b) consumes
peer-presence updates so that conversation list rows, thread headers, and profile
surfaces show an accurate online indicator and a "last seen" timestamp.

Scope, verbatim from the backlog: *`/messaging/presence(+heartbeat)`; online
indicators.* Acceptance, verbatim: *Presence reflects online/last-seen;
heartbeat runs while foregrounded.*

The deliverable is a self-contained presence subsystem in `core-data`
(`PresenceRepository`, the heartbeat scheduler, an in-memory presence cache) plus
a thin `core-network` `PresenceApi`, the presence DTOs in `core-model`, a small
set of reusable `core-ui` indicator composables, and a process-lifecycle-bound
heartbeat that starts when the app is foregrounded and stops when it is
backgrounded. Presence-change events arrive over the existing SSE channel from
**AND-143** (the hard dependency); the heartbeat is the write side, the SSE
stream the read side, reconciled into a single `StateFlow<Map<UserId, Presence>>`
that feature screens observe.

This ticket owns: the presence write (`POST /messaging/presence/heartbeat`), the
presence read seeds (`GET /messaging/presence?user_ids=`), the SSE
`presence_update` event handler, the foreground-bound heartbeat coroutine, the
presence domain model and cache, and the indicator composables + their use in the
conversation list and thread header. It does **not** own the SSE transport itself
(AND-143), the conversation list/thread screens' layout (AND-121/AND-123 — this
ticket only adds the indicator into existing rows), or generic offline caching
(AND-116).

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`.
- **Canonical package:** `com.testlogon.android` everywhere. Code lands in:
  - `core-model` → `com.testlogon.android.core.model.presence`
  - `core-network` → `com.testlogon.android.core.network.presence[.di]`
  - `core-data` → `com.testlogon.android.core.data.presence`
  - `core-ui` → `com.testlogon.android.core.ui.presence`
- **Stack pins relevant here:** Kotlin 2.0.21, Coroutines/Flow, Retrofit 2.11.0,
  OkHttp 4.12.0, Moshi 1.15.x (KSP codegen), Hilt (KSP), Jetpack Compose +
  Material 3, AndroidX Lifecycle (`ProcessLifecycleOwner`,
  `lifecycle-process`), DataStore (no Room needed — presence is volatile),
  JDK 17, minSdk 24 / compileSdk 35, AGP 8.7.3, Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. `PresenceApi` in
  `core-network`, DTOs in `core-model`, `PresenceRepository` + scheduler in
  `core-data`, indicators in `core-ui`. The foreground hook is wired in `app`
  (process lifecycle observer) and/or `feature-messaging`. No `feature-*`/`app`
  symbols leak into `core-*`.
- **Hard dependency — AND-143 (SSE client core):** provides the lifecycle-aware
  OkHttp `EventSource` wrapper exposing a `Flow<SseEvent>` of typed events with
  auth cookies + reconnect/backoff. AND-145 subscribes to that flow and filters
  `event: presence_update`. AND-145 must not open its own SSE connection.
- **Pattern precedent — AND-120 (Messaging API + DTOs):** follow the same
  transport conventions — relative paths with no leading slash, `suspend` methods
  returning DTO bodies, `@Headers("Content-Type: application/json")` on JSON
  POSTs, `@Provides @Singleton` provider over the shared Retrofit (AND-010),
  Moshi codegen DTOs with snake_case `@Json(name=...)`, MockWebServer contract
  tests. `OkResp` is reused from AND-026 Appendix A.
- **Auth:** presence calls are authenticated; session rides on cookies + `ui_csrf`
  → `X-CSRF-Token` (AND-011/AND-012); a `401` triggers AND-013 refresh-then-retry
  once. `PresenceApi` is header-agnostic. The SSE channel (AND-143) carries the
  same cookies.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` is
  plaintext and unreliable (~20s timeouts; bounded backoff for idempotent GETs —
  AND-009/AND-016). OpenAPI at `/openapi.json`. Web reference:
  `frontend/src/api/endpoints/*.ts` (presence/messaging) and `types.ts` — source
  of truth for exact field names and the heartbeat/presence shapes (reconcile
  Q-1/Q-2/Q-3 before coding).

## 3. Functional Requirements

FR-1. **Heartbeat while foregrounded.** While the app process is in the
foreground (Lifecycle `RESUMED`/`STARTED`), a single coroutine posts a heartbeat
to `POST /messaging/presence/heartbeat` on a fixed cadence (default 25 s, derived
from a server-advertised TTL; see Q-3). When the app is backgrounded the
heartbeat coroutine is cancelled; on return to foreground it restarts and fires
immediately (no wait for the first interval).

FR-2. **Single heartbeat instance.** Exactly one heartbeat loop runs regardless
of how many screens are visible. It is owned by a `@Singleton`
`HeartbeatScheduler` bound to `ProcessLifecycleOwner`, not to any screen's
ViewModel.

FR-3. **Presence read seeds.** Given a set of peer user ids (the participants
visible in the conversation list / open thread / profile), the repository seeds
their current presence via `GET /messaging/presence?user_ids=a,b,c` so indicators
are correct on first paint, before any SSE event arrives.

FR-4. **Live presence updates over SSE.** The repository subscribes to AND-143's
event flow, filters `presence_update` events, parses their payload, and merges
each into the in-memory presence cache, updating any observing UI within one
event round-trip.

FR-5. **Presence model.** Each tracked user resolves to a `Presence` with a
`status` (`ONLINE`, `AWAY`, `OFFLINE`) and a nullable `lastSeen: Instant`. A user
is considered `ONLINE` if the server reports `online == true` **or** `last_seen`
is within the freshness window (default = 2 × heartbeat TTL); otherwise
`OFFLINE`. `AWAY` is surfaced only if the server sends it explicitly (Q-2).

FR-6. **Online indicator composables.** Provide reusable `core-ui` composables —
a presence dot (`PresenceDot`) and an avatar-with-dot overlay
(`AvatarPresenceBadge`) — plus a "last seen" formatter. Wire them into the
conversation list row (AND-121) and the thread header (AND-123) so a participant's
online state and last-seen are visible.

FR-7. **Self exclusion.** The local user's own id is never rendered as a peer
indicator and the local user is not seeded via the read endpoint (the local
heartbeat is authoritative for self).

FR-8. **Graceful degradation.** If the heartbeat POST fails (timeout/5xx) it is
logged and retried on the next tick — a failure never crashes or stops the loop.
If SSE is disconnected (AND-143 reconnecting), the last known presence is shown
as **stale** (the indicator does not flip everyone offline); on SSE reconnect the
repository re-seeds the currently-tracked ids (FR-3) to resync.

FR-9. **Subscription scoping.** Presence for a peer is tracked only while at
least one screen observes it; tracked ids are reference-counted, and a peer no
longer observed by any screen is eligible for eviction from the cache (bounded
memory).

## 4. Technical Design

### 4.1 Domain model (`core-model`, package `...core.model.presence`)

```kotlin
enum class PresenceStatus { ONLINE, AWAY, OFFLINE }

data class Presence(
    val userId: String,
    val status: PresenceStatus,
    val lastSeen: Instant?,      // null if never reported
    val stale: Boolean = false,  // true while SSE is disconnected
)

// Wire DTOs (Moshi codegen)
@JsonClass(generateAdapter = true)
data class HeartbeatReq(
    @Json(name = "client_ts") val clientTs: String? = null, // ISO-8601 UTC, optional
)

@JsonClass(generateAdapter = true)
data class HeartbeatResp(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "ttl_seconds") val ttlSeconds: Int? = null, // server-advertised cadence basis
)

@JsonClass(generateAdapter = true)
data class PresenceDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "online") val online: Boolean = false,
    @Json(name = "status") val status: String? = null,        // "online"|"away"|"offline"
    @Json(name = "last_seen") val lastSeen: String? = null,   // ISO-8601 UTC
)

@JsonClass(generateAdapter = true)
data class PresenceListDto(
    @Json(name = "items") val items: List<PresenceDto> = emptyList(),
)

// Payload of an SSE `presence_update` event (single user or batch)
@JsonClass(generateAdapter = true)
data class PresenceUpdateEvent(
    @Json(name = "items") val items: List<PresenceDto> = emptyList(),
)
```

`Instant` parsing from ISO-8601 strings happens in the `core-data` mapper, not in
the DTO (the DTO stays a faithful wire mirror — mirrors AND-120's timestamp
policy). A `PresenceDto -> Presence` mapper resolves `status`: explicit `status`
string wins; otherwise `online` + freshness window decides (FR-5).

### 4.2 `PresenceApi` (`core-network`, package `...core.network.presence`)

```kotlin
package com.testlogon.android.core.network.presence

import com.testlogon.android.core.model.presence.HeartbeatReq
import com.testlogon.android.core.model.presence.HeartbeatResp
import com.testlogon.android.core.model.presence.PresenceListDto
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

interface PresenceApi {

    /** Report the local user online. Mutating POST → CSRF attached globally. */
    @Headers("Content-Type: application/json")
    @POST("messaging/presence/heartbeat")
    suspend fun heartbeat(@Body body: HeartbeatReq = HeartbeatReq()): HeartbeatResp

    /** Seed presence for a set of peers. Idempotent GET. */
    @GET("messaging/presence")
    suspend fun getPresence(
        @Query("user_ids") userIds: String, // comma-joined ids
    ): PresenceListDto
}
```

Path prefix (`messaging/presence...`) is assumed from the backlog scope; reconcile
against `/openapi.json` + web reference (Q-1). Method names/signatures do not
change if the prefix differs.

Hilt provider mirrors AND-120's `MessagingApiModule`:

```kotlin
@Module @InstallIn(SingletonComponent::class)
object PresenceApiModule {
    @Provides @Singleton
    fun providePresenceApi(retrofit: Retrofit): PresenceApi =
        retrofit.create(PresenceApi::class.java)
}
```

### 4.3 `PresenceRepository` (`core-data`, package `...core.data.presence`)

```kotlin
@Singleton
class PresenceRepository @Inject constructor(
    private val api: PresenceApi,
    private val sse: SseClient,                 // AND-143
    private val authState: AuthStateStore,      // AND-029 — local user id
    private val moshi: Moshi,
    @ApplicationScope private val scope: CoroutineScope,
    private val clock: Clock = Clock.System,
) {
    private val cache = MutableStateFlow<Map<String, Presence>>(emptyMap())

    /** Hot, conflated view of all currently-tracked presence. */
    val presence: StateFlow<Map<String, Presence>> = cache.asStateFlow()

    /** Observe presence for one user (defaults to OFFLINE if untracked). */
    fun presenceOf(userId: String): Flow<Presence> =
        presence.map { it[userId] ?: Presence(userId, PresenceStatus.OFFLINE, null) }
            .distinctUntilChanged()

    /** Reference-counted tracking; returns a handle that untracks on close. */
    fun track(userIds: Set<String>): PresenceSubscription { /* refcount + seed */ }

    suspend fun seed(userIds: Set<String>) { /* GET, merge into cache */ }

    fun start() { /* collect sse.events filtered to presence_update; on (re)connect re-seed */ }
}
```

- `start()` is invoked once (from the Hilt-provided singleton init / app start). It
  collects `sse.events` (AND-143), decodes `presence_update` payloads with `moshi`,
  and merges into `cache`. On an SSE reconnect signal it marks current entries
  `stale = true`, then re-seeds tracked ids and clears `stale`.
- `track()` reference-counts ids; the first tracker of an id triggers a `seed`,
  the last untrack schedules eviction (debounced, FR-9).
- All mutations to `cache` go through a single coroutine/`update {}` to keep the
  merge atomic.

### 4.4 `HeartbeatScheduler` (`core-data`, foreground-bound)

```kotlin
@Singleton
class HeartbeatScheduler @Inject constructor(
    private val api: PresenceApi,
    @ApplicationScope private val scope: CoroutineScope,
    private val dispatchers: AppDispatchers,
) : DefaultLifecycleObserver {

    private var job: Job? = null
    @Volatile private var intervalMs: Long = DEFAULT_INTERVAL_MS // 25_000

    override fun onStart(owner: LifecycleOwner) { startLoop() }   // foreground
    override fun onStop(owner: LifecycleOwner)  { job?.cancel(); job = null } // background

    private fun startLoop() {
        if (job?.isActive == true) return
        job = scope.launch(dispatchers.io) {
            while (isActive) {
                runCatching { api.heartbeat() }
                    .onSuccess { it.ttlSeconds?.let { ttl -> intervalMs = (ttl * 1000L) * 6 / 10 } }
                    .onFailure { /* log, swallow — retry next tick */ }
                delay(intervalMs)
            }
        }
    }
    companion object { const val DEFAULT_INTERVAL_MS = 25_000L }
}
```

Registration (in `app`, after auth is established):

```kotlin
ProcessLifecycleOwner.get().lifecycle.addObserver(heartbeatScheduler)
```

The scheduler fires the heartbeat **immediately** on `onStart` (loop body runs
before the first `delay`). Cadence = 60% of server `ttl_seconds` (so two
heartbeats land inside one TTL), bounded to `[10s, 60s]`. The scheduler must not
run while unauthenticated; it is started only after `GET /ui/me` succeeds
(AND-029) and stopped on logout (AND-032).

### 4.5 UI (`core-ui`, package `...core.ui.presence`)

```kotlin
@Composable fun PresenceDot(status: PresenceStatus, modifier: Modifier = Modifier)

@Composable fun AvatarPresenceBadge(
    avatarUrl: String?,
    contentDescription: String?,
    status: PresenceStatus,
    stale: Boolean = false,
    modifier: Modifier = Modifier,
)

/** "Active now" / "Active 5m ago" / "Active yesterday" — locale-aware. */
@Composable fun lastSeenLabel(presence: Presence): String
```

Colors come from the M3 theme (AND-019): online = success/tertiary, away =
warning, offline = no dot (or muted outline). `stale` renders the dot at reduced
opacity. AND-121's conversation row and AND-123's thread header consume
`AvatarPresenceBadge` + `lastSeenLabel`, observing `repository.presenceOf(...)`
via their existing ViewModels.

### 4.6 Gradle wiring

`core-network` already has Retrofit/Moshi/Hilt (AND-010). `core-data` adds
`androidx.lifecycle:lifecycle-process` and `lifecycle-runtime-ktx` (for
`ProcessLifecycleOwner` / `DefaultLifecycleObserver`) if not already present. No
new third-party deps; SSE comes from AND-143. `core-ui` needs no new deps (Coil
already present for avatars).

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. Paths assume the `messaging/`
prefix (confirm Q-1).

### POST `messaging/presence/heartbeat`
Request (body optional; may be empty `{}`):
```json
{ "client_ts": "2026-06-05T12:31:00Z" }
```
Response `200`:
```json
{ "ok": true, "ttl_seconds": 45 }
```
`ttl_seconds` (if present) drives cadence; absent → client default 25 s.

### GET `messaging/presence?user_ids=usr_1,usr_2`
Response `200`:
```json
{
  "items": [
    { "user_id": "usr_1", "online": true,  "status": "online",
      "last_seen": "2026-06-05T12:30:55Z" },
    { "user_id": "usr_2", "online": false, "status": "offline",
      "last_seen": "2026-06-04T18:02:11Z" }
  ]
}
```
Users with no record may be omitted from `items` (treated as OFFLINE) or returned
with `online:false` (Q-2).

### SSE event `presence_update` (delivered via AND-143 channel)
```
event: presence_update
data: {"items":[{"user_id":"usr_2","online":true,"status":"online","last_seen":"2026-06-05T12:31:10Z"}]}
```
A single event may carry one or many `items` (batch). Event name/shape reconciled
against the SSE stream contract (Q-1).

**Error envelope:** FastAPI `detail` union (`string | [{msg,type,loc}] |
{code,...}`). Mapping to typed `ApiError` is AND-015; this ticket lets non-2xx
surface as `HttpException`. A `401` is handled by AND-013 (refresh-then-retry
once); a terminal `401` on heartbeat means the session is gone → stop the loop and
route to login (AND-025).

## 6. Data & State Management

- **In-memory only.** Presence is volatile and short-lived — no Room. The source
  of truth is `PresenceRepository.cache: MutableStateFlow<Map<String, Presence>>`,
  exposed as a read-only `StateFlow`. Nothing presence-related persists across
  process death (correct behavior: a relaunch re-seeds).
- **DataStore (optional, prefs only):** none required by this ticket; if a "show
  my online status" privacy toggle is added (Q-4) it lives in the existing
  preferences DataStore (AND-078), gating the heartbeat.
- **State flow contract:** ViewModels (AND-122/AND-123) call
  `repository.presenceOf(userId)` and surface `PresenceStatus` + last-seen inside
  their existing `StateFlow<UiState>`; this ticket does not introduce a new
  screen-level `UiState`.
- **Merge semantics:** seed and SSE updates merge by `user_id`; the most-recent
  `last_seen` wins on conflict. Updates use `MutableStateFlow.update { }` for
  atomic, conflated emission.
- **Reference-counted tracking:** `track(ids)` returns a `PresenceSubscription`
  (an `AutoCloseable`); ViewModels open it in `init`/`viewModelScope` and close it
  in `onCleared`. Untracked, unreferenced ids are evicted after a debounce
  (default 60 s) to bound memory.
- **Self:** `authState.currentUserId` is excluded from peer tracking and never
  seeded.

## 7. Error Handling & Resilience

- **Heartbeat failures** (`SocketTimeoutException`, `IOException`, 5xx) are caught
  per-tick, logged at `WARN` (redacted), and the loop continues — one failed beat
  never stops presence reporting. The heartbeat is **not** retried with backoff
  inside a tick (the next tick is the retry); it is a POST and not auto-retried by
  AND-016.
- **`GET presence` failures** propagate to the caller of `seed()`; the repository
  catches them, keeps prior cache values (or OFFLINE defaults), and a re-seed
  occurs on the next SSE reconnect or screen re-track. Idempotent GET → eligible
  for AND-016 bounded backoff and the ~20 s timeout policy (AND-009).
- **SSE disconnect (AND-143 reconnecting):** entries are marked `stale = true`
  (dot dimmed) rather than flipped to OFFLINE — avoids a flicker storm on flaky
  dev networks. On reconnect, re-seed tracked ids, then clear `stale`.
- **Freshness fallback:** if SSE is down for longer than the freshness window
  (2 × TTL), peers age out to OFFLINE via the `lastSeen` comparison (FR-5) even
  without an explicit event — presence cannot be indefinitely "stuck online".
- **Terminal 401 on heartbeat:** stop the scheduler, clear the cache, defer to
  AND-013/AND-025 for re-auth/route-to-login.
- **Deserialization:** lenient Moshi (nullable optionals, defaults, ignored
  unknown keys); a malformed `presence_update` payload is dropped (logged) without
  tearing down the SSE collector.

## 8. Security & Privacy

- **Authenticated surface:** heartbeat and presence reads require an active
  session (cookies); the server scopes presence to permitted peers (returns
  403/404 otherwise). No manual `Cookie`/`Authorization` headers — delegated to
  AND-011/AND-012.
- **Privacy of online state:** presence is personal data. A "share my online
  status" preference (Q-4) should gate the heartbeat — when off, the client stops
  heart-beating and the user appears offline. Default per product (assume ON
  pending grooming).
- **Cleartext on dev:** heartbeat `client_ts` and peer `last_seen` ride plaintext
  HTTP/SSE on the `dev` host (known dev-only risk, scoped cleartext config
  AND-006); `staging`/`prod` are HTTPS-only.
- **No content in logs:** the heartbeat carries no message content; presence logs
  must be redacted (no raw user ids/timestamps in release logcat — see Section
  10). `client_ts` carries no PII beyond a coarse timestamp.
- **No background tracking:** the heartbeat runs **only** while foregrounded — no
  `WorkManager`/`Service` keeps a user "online" while the app is closed,
  satisfying the "while foregrounded" acceptance and minimizing privacy/battery
  exposure.

## 9. Accessibility & i18n

- **Indicators are not color-only.** The presence dot pairs color with a
  `contentDescription` on `AvatarPresenceBadge` ("Alice, online" / "Alice, last
  active 5 minutes ago") so TalkBack announces state; color alone never conveys
  presence (WCAG 1.4.1). Offline = absent/muted dot + descriptive text.
- **Touch/size:** the dot is decorative overlay on an already-tappable avatar; it
  adds no separate target and does not reduce the avatar's ≥48 dp target.
- **i18n:** all presence strings ("Active now", "Active {n}m ago", "Active
  yesterday", "Offline") are string resources (AND-111) with plurals where
  applicable; relative-time formatting uses `DateUtils.getRelativeTimeSpanString`
  / ICU so it is locale-aware and RTL-safe (AND-114). Timestamps transported as
  ISO-8601 UTC; formatting is UI-side and locale-aware.

## 10. Telemetry & Logging

- **HTTP/SSE logging** inherited from AND-009's redacting interceptor (debug
  only). No new request/response body logging here.
- **Operational logs (redacted, debug):** heartbeat tick success/failure counts,
  current `intervalMs`, SSE presence event received (count only, no ids),
  re-seed-on-reconnect. User ids/timestamps are hashed or omitted in release.
- **Analytics:** optional, lightweight — `presence_heartbeat_failed` (with cause
  category) and `presence_indicator_shown` may be emitted from the repository/UI
  if an analytics seam exists; otherwise N/A. No per-peer presence-change event is
  emitted (too chatty). Event emission is owned by the consuming ViewModels, not
  by `PresenceApi`.
- **Build-time:** KSP must generate Moshi adapters for all presence DTOs; a
  missing adapter fails the build (no reflection fallback, AND-010 policy).

## 11. Testing Strategy

JVM unit tests in `core-network/src/test`, `core-model/src/test`,
`core-data/src/test` using `MockWebServer` (AND-046 harness + fixtures) and
`kotlinx-coroutines-test` (`runTest`, `TestDispatcher`, virtual time). Compose UI
tests for the indicators in `core-ui`/`feature-messaging` instrumented tests.

**T-1 — heartbeat contract.** `POST messaging/presence/heartbeat`; assert
verb/path and that an empty/`client_ts` body serializes; decode `HeartbeatResp`
incl. `ttl_seconds`.

**T-2 — getPresence contract.** `GET messaging/presence?user_ids=usr_1,usr_2`;
assert the comma-joined query param and decode `PresenceListDto` with mixed
online/offline + nullable `last_seen`.

**T-3 — DTO mapping/freshness.** `PresenceDto -> Presence`: explicit `status`
wins; `online:true` → ONLINE; `online:false` + recent `last_seen` (inside window)
→ ONLINE; stale `last_seen` → OFFLINE; missing `last_seen` → null. Use an injected
fixed `Clock`.

**T-4 — heartbeat foreground lifecycle (virtual time).** With a fake
`LifecycleOwner`/test scope: `onStart` fires a beat immediately and then every
`intervalMs`; `onStop` cancels the loop (no further beats); a subsequent `onStart`
restarts and fires immediately. Assert the MockWebServer received the expected
number of requests at advanced virtual times.

**T-5 — heartbeat failure resilience.** A failing heartbeat (timeout/500) is
swallowed and the loop continues to the next tick (assert beat N+1 still fires).

**T-6 — cadence from TTL.** A `ttl_seconds:45` response sets `intervalMs` to
`45*1000*0.6 = 27_000`, clamped to `[10s,60s]`.

**T-7 — SSE merge.** Feed a fake `SseClient` flow a `presence_update` event;
assert `repository.presence` reflects the merged user with correct status and that
`presenceOf(id)` emits the update. Most-recent `last_seen` wins on conflicting
merges.

**T-8 — re-seed on reconnect.** Simulate SSE disconnect → entries marked `stale`;
on reconnect, assert a `getPresence` re-seed for currently-tracked ids and `stale`
cleared.

**T-9 — reference counting / eviction.** Two trackers of the same id seed once;
closing both schedules eviction after debounce; reopening re-seeds.

**T-10 — self exclusion.** The local user id (from a fake `AuthStateStore`) is
never seeded and `presenceOf(selfId)` is never populated from peer data.

**T-11 — Compose indicators.** `PresenceDot`/`AvatarPresenceBadge` render
online/away/offline/stale states; assert `contentDescription` text per state
(TalkBack semantics) — satisfies Section 9.

**T-12 — Hilt providers.** `PresenceApi`, `PresenceRepository`,
`HeartbeatScheduler` inject as singletons on the shared graph (same instance on
repeated injection).

Coverage target: ≥90% on the new repository/scheduler/mapper/DTO surface; every
endpoint has a path/verb assertion; the freshness rule and lifecycle behavior are
each directly asserted (acceptance-aligned).

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-143** (backlog-named dependency) — the SSE client core that delivers
  `presence_update` events; AND-145's read side is built on its `Flow<SseEvent>`.

**Transitive upstream (already required):**
- AND-010 (shared Retrofit/Moshi) and AND-009 (shared `OkHttpClient`, timeouts,
  redacting logging) for `PresenceApi`.
- AND-026 (`OkResp`/DTO conventions), AND-120 (`*Api`/DTO pattern precedent),
  AND-015/AND-018 (error/`ApiResult` mapping at the repository boundary),
  AND-016 (backoff for the idempotent presence GET).
- AND-011/AND-012/AND-013 (cookies, CSRF, 401-refresh) — applied transparently.
- AND-029/AND-032 (auth state for self id + start/stop on login/logout),
  AND-025 (route-to-login on terminal 401).
- AND-019 (M3 theme colors), AND-111/AND-114 (i18n/RTL) for indicators.
- AND-046 (MockWebServer harness + fixture loader) for tests.

**Soft / integration consumers (this ticket touches, does not block):**
- AND-121 (conversation list row) and AND-123 (thread header) — add the indicator
  + last-seen; AND-145 provides the composables and the `presenceOf` flow.
- Profile screen (AND-071/AND-073) — may reuse `AvatarPresenceBadge` (optional).

`blocks: []` — no ticket lists AND-145 as a hard dependency; presence is an
additive enhancement to existing messaging surfaces.

**Sequencing within the ticket:** (1) confirm endpoint prefix, presence shape,
SSE event name, and TTL semantics against `/openapi.json` + web reference +
AND-143 contract, capture fixtures (AND-046); (2) DTOs (`core-model`) + mapper;
(3) `PresenceApi` + provider (`core-network`); (4) `PresenceRepository` +
`HeartbeatScheduler` (`core-data`); (5) indicator composables (`core-ui`);
(6) wire scheduler to `ProcessLifecycleOwner` in `app`, indicators into
AND-121/AND-123; (7) tests T-1..T-12.

## 13. Risks & Open Questions

- **R-1 Endpoint/path drift.** Heartbeat/presence routes may not sit under
  `messaging/`. Mitigation: reconcile against `/openapi.json` + web reference
  (Q-1); path assertions in T-1/T-2 catch mismatches.
- **R-2 SSE event shape.** The `presence_update` event name and whether it batches
  multiple users (vs one-per-event) must match AND-143's stream. Mitigation:
  confirm against the live stream; T-7 guards parsing.
- **R-3 Cadence vs server TTL.** Too-frequent heartbeats waste the unreliable dev
  backend; too-infrequent flips users offline. Mitigation: derive cadence from
  `ttl_seconds` at 60%, clamp `[10s,60s]`; freshness window = 2 × TTL.
- **R-4 Battery / network on flaky dev host.** A 25 s foreground heartbeat is
  modest but the ~20 s timeout means a slow beat can overlap the next tick.
  Mitigation: guard against overlapping beats (skip a tick if one is in flight);
  foreground-only (no background work).
- **R-5 Privacy expectations.** Users may not expect to broadcast online status.
  Mitigation: a privacy toggle gating the heartbeat (Q-4); default per product.
- **Q-1** Are the routes `messaging/presence[/heartbeat]` or bare
  `presence[/heartbeat]`, and what is the exact SSE event name
  (`presence_update`?)? *Proposed:* match `/openapi.json` + AND-143; spec assumes
  `messaging/presence...` and `presence_update`.
- **Q-2** Does the backend distinguish `away` from `online`/`offline`, and does
  `GET presence` omit unknown users or return `online:false`? *Proposed:* support
  AWAY only if `status` is sent; treat omitted users as OFFLINE.
- **Q-3** Does heartbeat return a `ttl_seconds` to drive cadence, or is cadence
  client-fixed? *Proposed:* honor `ttl_seconds` if present; else 25 s default.
- **Q-4** Is there a "share online status" privacy preference, and what is its
  default? *Proposed:* add a DataStore toggle gating the heartbeat; default ON
  pending grooming.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Presence reflects online/last-seen: a peer reported
  `online`/recent `last_seen` renders an online indicator with a last-seen label;
  a stale/absent peer renders offline. Verified by T-3/T-7/T-11 and the live
  conversation list/thread header showing correct indicators.
- **AC-2 (backlog).** The heartbeat runs while foregrounded: `POST
  messaging/presence/heartbeat` fires immediately on foreground and repeats on the
  configured cadence, and **stops** when backgrounded, restarting on return
  (T-4).
- **AC-3.** Exactly one heartbeat loop runs regardless of visible screens; it is
  process-lifecycle-bound, not screen-bound (T-4/T-12).
- **AC-4.** Live `presence_update` SSE events (from AND-143) merge into the
  presence cache and update observing UI without a manual refresh (T-7).
- **AC-5.** Presence is seeded via `GET messaging/presence?user_ids=` so
  indicators are correct on first paint, and re-seeded on SSE reconnect (T-2/T-8).
- **AC-6.** A failed heartbeat (timeout/5xx/terminal-handled-401) never stops the
  loop (except terminal 401 → stop + route to login) and never crashes the app
  (T-5).
- **AC-7.** Presence DTOs decode via codegen adapters (snake_case `user_id`,
  `last_seen`, `ttl_seconds`); unknown keys ignored; absent optionals default
  (T-1/T-2).
- **AC-8.** The local user is never shown as a peer indicator and never seeded
  (T-10).
- **AC-9.** Indicators are not color-only: each carries a TalkBack
  `contentDescription`; strings are localized resources (T-11; Sections 8–9).
- **AC-10.** No new `OkHttpClient`/`Retrofit`/SSE connection is constructed; no
  per-method CSRF/cookie headers declared; module builds clean under AGP 8.7.3 /
  Gradle 8.9 / JDK 17 with KSP adapters present; all tests pass in CI; no
  detekt/lint regressions (AND-005).

## 15. Definition of Done

- DTOs + mapper (`com.testlogon.android.core.model.presence`), `PresenceApi` +
  `PresenceApiModule` (`...core.network.presence[.di]`), `PresenceRepository` +
  `HeartbeatScheduler` (`...core.data.presence`), and indicator composables
  (`...core.ui.presence`) are implemented, reusing the shared Retrofit (AND-010)
  and the AND-143 SSE client; no transport/DTO redefined.
- The heartbeat is wired to `ProcessLifecycleOwner` in `app`, gated by auth
  (started after `GET /ui/me`, stopped on logout); indicators are wired into the
  AND-121 conversation row and AND-123 thread header.
- Open questions Q-1..Q-4 resolved against `/openapi.json`, the web reference, and
  the AND-143 stream contract; endpoint paths, SSE event name, presence/`status`
  shape, cadence/TTL, and any privacy toggle reflect the confirmed contract.
- JSON fixtures captured (via AND-046) for heartbeat response, presence list, and
  a `presence_update` SSE payload, matching live backend shapes.
- Tests T-1 through T-12 implemented and green in CI; ≥90% line coverage on the
  new surface; lifecycle (foreground start / background stop / restart),
  freshness rule, SSE merge, re-seed-on-reconnect, and self-exclusion each
  directly asserted.
- No second `OkHttpClient`/`Retrofit`/SSE connection; no manual cookie/CSRF/auth
  headers; presence user ids/timestamps not logged in release (verified in
  review); no background heartbeat (foreground-only).
- `./gradlew :core-model:testDebugUnitTest :core-network:testDebugUnitTest
  :core-data:testDebugUnitTest :core-ui:assemble` passes locally and in CI with no
  new lint/detekt violations (AND-005).
- Code reviewed and merged to `android-port`; a one-line note in the `core-data`
  README (AND-007) records the presence subsystem (heartbeat cadence/TTL, SSE
  `presence_update` consumption, foreground-only policy, and delegation of
  cookie/CSRF/refresh to AND-011/AND-012/AND-013).
