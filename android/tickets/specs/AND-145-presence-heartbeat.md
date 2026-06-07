---
id: AND-145
title: Presence + heartbeat
milestone: M3
epic: E20
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
to `POST /messaging/presence/heartbeat` on a **client-fixed cadence of 30 s**
(matches the web reference `HEARTBEAT_INTERVAL_MS = 30_000`,
`src/hooks/usePresence.ts`). [CORRECTED] The backend does **not** advertise a
`ttl_seconds`/TTL in the heartbeat response (verified: `PresenceOut` /
`PresenceHeartbeatIn` and the web client both omit it), so there is no
server-driven cadence — cadence is a client constant; see Q-3. When the app is
backgrounded the heartbeat coroutine is cancelled; on return to foreground it
restarts and fires immediately (no wait for the first interval).

FR-2. **Single heartbeat instance.** Exactly one heartbeat loop runs regardless
of how many screens are visible. It is owned by a `@Singleton`
`HeartbeatScheduler` bound to `ProcessLifecycleOwner`, not to any screen's
ViewModel.

FR-3. **Presence read seeds.** Given a set of peer user ids (the participants
visible in the conversation list / open thread / profile), the repository seeds
their current presence via `GET /messaging/presence?user_ids=a,b,c` so indicators
are correct on first paint, before any SSE event arrives. [CORRECTED] The
response is a **bare JSON array** of presence objects (`PresenceStatus[]` in the
web client), not an `{ "items": [...] }` envelope.

FR-4. **Live presence updates over SSE.** The repository subscribes to AND-143's
event flow, filters **`presence:update`** events [CORRECTED — colon-delimited
event name, not `presence_update`; verified in `src/hooks/useMessagingStream.ts`],
parses their payload, and merges each into the in-memory presence cache, updating
any observing UI within one event round-trip. [CORRECTED] Each `presence:update`
event carries a **single user** (`{ user_id, online, last_seen_at }`), not a
batch of `items`.

FR-5. **Presence model.** Each tracked user resolves to a `Presence` with a
`status` (`ONLINE`, `OFFLINE`) and a nullable `lastSeen: Instant`. [CORRECTED]
The backend presence record exposes only a boolean `online` and an epoch
`last_seen_at` — there is **no `away` state** on the read side (`PresenceOut` =
`{ user_id, online, last_seen_at }`). `AWAY` is therefore dropped from the
read-side model; a user is `ONLINE` iff the server reports `online == true`,
otherwise `OFFLINE`. (`last_seen_at` is rendered as a "last seen" label but is
not used to synthesize an ONLINE state, matching the web client which keys the
indicator purely off `online`.) The optional `status` write field on
`PresenceHeartbeatIn` is for the *self* heartbeat only (see Q-2) and is not
reflected back in the read schema.

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
enum class PresenceStatus { ONLINE, OFFLINE }   // [CORRECTED] no AWAY on read side

data class Presence(
    val userId: String,
    val status: PresenceStatus,
    val lastSeen: Instant?,      // null if never reported
    val stale: Boolean = false,  // true while SSE is disconnected
)

// Wire DTOs (Moshi codegen)
// [CORRECTED] Heartbeat request = PresenceHeartbeatIn { device?, status? }
@JsonClass(generateAdapter = true)
data class HeartbeatReq(
    @Json(name = "device") val device: String? = null,   // e.g. "android"; nullable
    @Json(name = "status") val status: String? = null,   // optional self-status hint
)

// [CORRECTED] Heartbeat 200 body (untyped in OpenAPI; web declares this shape).
// No `ttl_seconds` exists.
@JsonClass(generateAdapter = true)
data class HeartbeatResp(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "online") val online: Boolean = true,
    @Json(name = "last_seen_at") val lastSeenAt: Long? = null, // epoch seconds/ms
)

// [CORRECTED] PresenceOut / web PresenceStatus = { user_id, online, last_seen_at }.
// No `status` field; `last_seen_at` is an epoch integer, not an ISO string.
@JsonClass(generateAdapter = true)
data class PresenceDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "online") val online: Boolean = false,
    @Json(name = "last_seen_at") val lastSeenAt: Long? = null, // epoch (integer)
)

// [CORRECTED] GET /messaging/presence returns a BARE ARRAY (PresenceStatus[]),
// not an { items: [...] } envelope. Retrofit decodes List<PresenceDto> directly;
// no wrapper DTO is needed.

// [CORRECTED] Payload of an SSE `presence:update` event = a single user object,
// matching `useMessagingStream.ts` ({ user_id, online, last_seen_at }).
@JsonClass(generateAdapter = true)
data class PresenceUpdateEvent(
    @Json(name = "user_id") val userId: String,
    @Json(name = "online") val online: Boolean = false,
    @Json(name = "last_seen_at") val lastSeenAt: Long? = null,
)
```

`Instant` (or `Instant.ofEpochSecond/ofEpochMilli`) parsing from the epoch
`last_seen_at` happens in the `core-data` mapper, not in the DTO (the DTO stays a
faithful wire mirror — mirrors AND-120's timestamp policy). A
`PresenceDto -> Presence` mapper resolves status directly from `online`
(`online == true` → ONLINE, else OFFLINE); `last_seen_at` populates `lastSeen`
for the label only. [CORRECTED] (Confirm the epoch unit — seconds vs
milliseconds — against a live response; see Open assumptions.)

### 4.2 `PresenceApi` (`core-network`, package `...core.network.presence`)

```kotlin
package com.testlogon.android.core.network.presence

import com.testlogon.android.core.model.presence.HeartbeatReq
import com.testlogon.android.core.model.presence.HeartbeatResp
import com.testlogon.android.core.model.presence.PresenceDto
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
    // [CORRECTED] Returns a bare array (List<PresenceDto>), not an items-envelope.
    @GET("messaging/presence")
    suspend fun getPresence(
        @Query("user_ids") userIds: String, // comma-joined ids
    ): List<PresenceDto>
}
```

Path prefix (`messaging/presence...`) is **confirmed** against the OpenAPI index:
`GET /messaging/presence` and `POST /messaging/presence/heartbeat` both exist
under the `messaging` tag, and the web client calls these exact paths
(`src/api/endpoints/messaging.ts`). Q-1 (path) is resolved; the SSE event name is
`presence:update` (also confirmed). Method names/signatures stand.

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
    // [CORRECTED] Fixed cadence — backend advertises no TTL. 30 s matches web.
    private val intervalMs: Long = INTERVAL_MS // 30_000

    override fun onStart(owner: LifecycleOwner) { startLoop() }   // foreground
    override fun onStop(owner: LifecycleOwner)  { job?.cancel(); job = null } // background

    private fun startLoop() {
        if (job?.isActive == true) return
        job = scope.launch(dispatchers.io) {
            while (isActive) {
                runCatching { api.heartbeat(HeartbeatReq(device = "android")) }
                    .onFailure { /* log, swallow — retry next tick */ }
                delay(intervalMs)
            }
        }
    }
    companion object { const val INTERVAL_MS = 30_000L }
}
```

Registration (in `app`, after auth is established):

```kotlin
ProcessLifecycleOwner.get().lifecycle.addObserver(heartbeatScheduler)
```

The scheduler fires the heartbeat **immediately** on `onStart` (loop body runs
before the first `delay`). [CORRECTED] Cadence is a **client constant of 30 s** —
there is no server `ttl_seconds` to derive from (verified against `PresenceOut` /
the web client). The scheduler must not run while unauthenticated; it is started
only after `GET /ui/me` succeeds (AND-029) and stopped on logout (AND-032).

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

Colors come from the M3 theme (AND-019): online = success/tertiary (the web
client uses an emerald dot), offline = no dot (or muted outline; web uses
`bg-muted-foreground/40`). [CORRECTED] There is no `away`/warning state —
the read model is online/offline only. `stale` renders the dot at reduced
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

Base path (`dev`): `http://18.222.237.167:8000/`. Paths **confirmed** against the
OpenAPI index (`messaging` tag) and `src/api/endpoints/messaging.ts`.

### POST `messaging/presence/heartbeat`  (schema `PresenceHeartbeatIn`)
[CORRECTED] Request body — `{ device?, status? }` (both nullable). Web sends
`{ device }`:
```json
{ "device": "android" }
```
Response `200` (untyped in OpenAPI; web declares this shape — **no `ttl_seconds`**):
```json
{ "ok": true, "user_id": "usr_self", "online": true, "last_seen_at": 1749126660 }
```
Cadence is a client constant (30 s); nothing in the response drives it.

### GET `messaging/presence?user_ids=usr_1,usr_2`  (items = `PresenceOut`)
[CORRECTED] Response `200` is a **bare array** (`PresenceStatus[]` /
`List[PresenceOut]`), each `{ user_id, online, last_seen_at }` — no `status`
field, `last_seen_at` is an **epoch integer**:
```json
[
  { "user_id": "usr_1", "online": true,  "last_seen_at": 1749126655 },
  { "user_id": "usr_2", "online": false, "last_seen_at": 1749066131 }
]
```
Users with no record may be omitted from the array (treated as OFFLINE) or
returned with `online:false` (Q-2 — unverified which).

### SSE event `presence:update` (delivered via AND-143 channel)
[CORRECTED] Event name is colon-delimited (`presence:update`); payload is a
**single user** (verified in `src/hooks/useMessagingStream.ts`):
```
event: presence:update
data: {"user_id":"usr_2","online":true,"last_seen_at":1749126670}
```
One user per event (no `items` batch). Event name/shape confirmed against the web
SSE handler; reconcile the exact AND-143 transport framing at integration.

**Error envelope:** FastAPI `detail` union (`string | [{msg,type,loc}] |
{code,...}`). [Verified] Both endpoints declare `422 → HTTPValidationError`
(`{ detail: [{ loc, msg, type }] }`) in OpenAPI; the web client's
`mapAuthorizationError` also reads an optional `detail.code` string. Mapping to
typed `ApiError` is AND-015; this ticket lets non-2xx surface as `HttpException`. A `401` is handled by AND-013 (refresh-then-retry
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
  `last_seen_at` (epoch) wins on conflict [CORRECTED field name]. Updates use
  `MutableStateFlow.update { }` for atomic, conflated emission.
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
- **Freshness fallback:** [CORRECTED — no server TTL exists] presence state is
  driven purely by the server `online` flag (read seed + `presence:update`); the
  client does not synthesize OFFLINE from a freshness window. To avoid being
  "stuck online" when SSE is down, the repository re-seeds via `GET
  /messaging/presence` on each SSE reconnect and on the 60 s fallback poll
  (mirroring the web `PRESENCE_FALLBACK_POLL_MS = 60_000`), letting the server's
  authoritative `online` correct stale entries.
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
- **Cleartext on dev:** the heartbeat `device` field and peer `last_seen_at` ride
  plaintext HTTP/SSE on the `dev` host (known dev-only risk, scoped cleartext
  config AND-006); `staging`/`prod` are HTTPS-only.
- **No content in logs:** the heartbeat carries no message content; presence logs
  must be redacted (no raw user ids/timestamps in release logcat — see Section
  10). The `device` field carries no PII beyond a coarse platform tag.
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
verb/path and that a `{ device }` body serializes [CORRECTED]; decode
`HeartbeatResp` (`{ ok, user_id, online, last_seen_at }` — **no `ttl_seconds`**).

**T-2 — getPresence contract.** `GET messaging/presence?user_ids=usr_1,usr_2`;
assert the comma-joined query param and decode a **bare `List<PresenceDto>`**
[CORRECTED] with mixed online/offline + epoch `last_seen_at`.

**T-3 — DTO mapping.** `PresenceDto -> Presence`: `online:true` → ONLINE;
`online:false` → OFFLINE [CORRECTED — no `status`/freshness-window synthesis];
`last_seen_at` epoch maps to `lastSeen: Instant`; missing `last_seen_at` → null.

**T-4 — heartbeat foreground lifecycle (virtual time).** With a fake
`LifecycleOwner`/test scope: `onStart` fires a beat immediately and then every
`intervalMs`; `onStop` cancels the loop (no further beats); a subsequent `onStart`
restarts and fires immediately. Assert the MockWebServer received the expected
number of requests at advanced virtual times.

**T-5 — heartbeat failure resilience.** A failing heartbeat (timeout/500) is
swallowed and the loop continues to the next tick (assert beat N+1 still fires).

**T-6 — fixed cadence.** [CORRECTED — no TTL] Assert the loop uses the 30 s
constant (`INTERVAL_MS`) regardless of response body; advancing virtual time by
30 s triggers exactly one more beat. (No `ttl_seconds` parsing exists to test.)

**T-7 — SSE merge.** Feed a fake `SseClient` flow a `presence:update` event
[CORRECTED name]; assert `repository.presence` reflects the merged single user
with correct status and that `presenceOf(id)` emits the update. Most-recent
`last_seen_at` wins on conflicting merges.

**T-8 — re-seed on reconnect.** Simulate SSE disconnect → entries marked `stale`;
on reconnect, assert a `getPresence` re-seed for currently-tracked ids and `stale`
cleared.

**T-9 — reference counting / eviction.** Two trackers of the same id seed once;
closing both schedules eviction after debounce; reopening re-seeds.

**T-10 — self exclusion.** The local user id (from a fake `AuthStateStore`) is
never seeded and `presenceOf(selfId)` is never populated from peer data.

**T-11 — Compose indicators.** `PresenceDot`/`AvatarPresenceBadge` render
online/offline/stale states [CORRECTED — no away]; assert `contentDescription`
text per state (TalkBack semantics) — satisfies Section 9.

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
- **R-2 SSE event shape.** [RESOLVED] The event name is `presence:update` and it
  carries **one user per event** (`{ user_id, online, last_seen_at }`), confirmed
  in `src/hooks/useMessagingStream.ts`. Residual risk: AND-143's exact transport
  framing of the `data:` line. T-7 guards parsing.
- **R-3 Cadence.** [RESOLVED — no server TTL] The backend advertises no
  `ttl_seconds`; cadence is a fixed 30 s client constant (matches web). Risk
  reduces to: too-infrequent could lag the indicator, mitigated by the 60 s
  fallback re-seed. No clamp/derivation needed.
- **R-4 Battery / network on flaky dev host.** A 25 s foreground heartbeat is
  modest but the ~20 s timeout means a slow beat can overlap the next tick.
  Mitigation: guard against overlapping beats (skip a tick if one is in flight);
  foreground-only (no background work).
- **R-5 Privacy expectations.** Users may not expect to broadcast online status.
  Mitigation: a privacy toggle gating the heartbeat (Q-4); default per product.
- **Q-1** [RESOLVED] Routes are `messaging/presence` (GET) and
  `messaging/presence/heartbeat` (POST) — confirmed in OpenAPI + web. SSE event
  name is `presence:update` (colon), single-user payload.
- **Q-2** [PARTIALLY RESOLVED] The read schema (`PresenceOut`) exposes **no `away`
  state** — only boolean `online` — so the indicator is online/offline only. The
  *write* `PresenceHeartbeatIn` accepts an optional `status` string, but it is not
  reflected in reads; treat AWAY as out of scope. **Open:** whether `GET presence`
  omits unknown users vs returns `online:false` is not specified in the schema
  (response is untyped) — treat omitted users as OFFLINE; verify on a live host.
- **Q-3** [RESOLVED] Heartbeat returns **no `ttl_seconds`**; cadence is
  client-fixed at 30 s (matching the web `HEARTBEAT_INTERVAL_MS`).
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
- **AC-4.** Live `presence:update` SSE events (from AND-143) merge into the
  presence cache and update observing UI without a manual refresh (T-7).
- **AC-5.** Presence is seeded via `GET messaging/presence?user_ids=` so
  indicators are correct on first paint, and re-seeded on SSE reconnect (T-2/T-8).
- **AC-6.** A failed heartbeat (timeout/5xx/terminal-handled-401) never stops the
  loop (except terminal 401 → stop + route to login) and never crashes the app
  (T-5).
- **AC-7.** Presence DTOs decode via codegen adapters (snake_case `user_id`,
  `last_seen_at`, `online`) [CORRECTED field names; no `ttl_seconds`]; unknown
  keys ignored; absent optionals default; `GET presence` decodes a bare JSON array
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
  README (AND-007) records the presence subsystem (fixed 30 s heartbeat cadence,
  SSE `presence:update` consumption, foreground-only policy, and delegation of
  cookie/CSRF/refresh to AND-011/AND-012/AND-013).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Endpoint `POST /messaging/presence/heartbeat` exists.** VERIFIED.
   OpenAPI `POST /messaging/presence/heartbeat` (op
   `presence_heartbeat_messaging_presence_heartbeat_post`); frontend
   `src/api/endpoints/messaging.ts: sendHeartbeat`.
2. **Endpoint `GET /messaging/presence?user_ids=` exists.** VERIFIED.
   OpenAPI `GET /messaging/presence` (param `user_ids`); frontend
   `src/api/endpoints/messaging.ts: getPresence`.
3. **Heartbeat request body shape.** CORRECTED. Spec claimed
   `{ client_ts: ISO-8601 }`. Actual schema `PresenceHeartbeatIn = { device?:
   string|null, status?: string|null }` (OpenAPI `components.schemas.PresenceHeartbeatIn`);
   web sends `{ device }` (`src/api/endpoints/messaging.ts: sendHeartbeat`).
4. **Heartbeat response includes `ttl_seconds` to drive cadence.** CORRECTED.
   No such field exists. OpenAPI 200 schema for the heartbeat is empty (`{}`,
   untyped); the web client types the body as
   `{ ok, user_id, online, last_seen_at }` (`src/api/endpoints/messaging.ts`).
   Cadence is therefore client-fixed.
5. **Heartbeat cadence value.** CORRECTED. Spec said 25 s derived from TTL;
   actual web cadence is a fixed `HEARTBEAT_INTERVAL_MS = 30_000`
   (`src/hooks/usePresence.ts`). Adopted 30 s.
6. **`GET presence` response is an `{ items: [...] }` envelope.** CORRECTED.
   It is a **bare array**. Frontend types it `PresenceStatus[]` and iterates
   `for (const entry of data)` / `data?.[0]` (`src/api/endpoints/messaging.ts:
   getPresence`, `src/hooks/usePresence.ts`).
7. **Presence record fields.** CORRECTED. Spec used `{ user_id, online, status,
   last_seen (ISO string) }`. Actual `PresenceOut = { user_id, online,
   last_seen_at }` with `last_seen_at` an **integer (epoch)** and all three
   required (OpenAPI `components.schemas.PresenceOut`); identical to frontend
   `src/api/types.ts: PresenceStatus`. No `status` field on reads; `last_seen` →
   `last_seen_at`.
8. **An `AWAY`/`away` presence state exists.** CORRECTED. The read model has no
   `away` — only boolean `online` (`PresenceOut`, `src/api/types.ts:
   PresenceStatus`, web `PresenceDot.tsx` keys off `online` only). `AWAY`
   removed from `PresenceStatus` enum and indicator colors.
9. **SSE event name `presence_update`.** CORRECTED. Actual name is
   **`presence:update`** (colon), verified in
   `src/hooks/useMessagingStream.ts` (handler `if (eventType ===
   "presence:update")` and subscription list).
10. **SSE `presence_update` payload batches many `items`.** CORRECTED. Each
    event carries a **single user** `{ user_id, online, last_seen_at }`
    (`src/hooks/useMessagingStream.ts`).
11. **Auth: cookies + `ui_csrf` → `X-CSRF-Token`, `credentials: include`,
    `Authorization: Bearer`.** VERIFIED. `src/api/client.ts` (reads `ui_csrf`
    cookie → `X-CSRF-Token`, sets `Authorization` from auth store, all requests
    `credentials: "include"`).
12. **401 → refresh-then-retry once via session refresh.** VERIFIED.
    `src/api/client.ts` posts `/ui/session/refresh` on 401 then retries.
13. **Error envelope is FastAPI `detail` union; 422 → HTTPValidationError.**
    VERIFIED. OpenAPI both endpoints declare `422: HTTPValidationError`; web
    `src/api/client.ts: mapAuthorizationError` reads optional `detail.code`.
14. **`ProcessLifecycleOwner` / `DefaultLifecycleObserver` for foreground-bound
    heartbeat.** VERIFIED (framework ref).
    https://developer.android.com/reference/androidx/lifecycle/ProcessLifecycleOwner
    and androidx `lifecycle-process`. Web analog ties the heartbeat to
    `document.visibilityState === "visible"` (`src/hooks/usePresence.ts`).
15. **60 s fallback re-seed poll.** VERIFIED. Web
    `PRESENCE_FALLBACK_POLL_MS = 60_000` (`src/hooks/usePresence.ts`) — used as
    precedent for the reconnect/fallback re-seed.
16. **`last_seen_at` epoch unit (seconds vs ms).** UNVERIFIED-ASSUMPTION.
    OpenAPI types it only as `integer`; neither schema nor TS pins the unit.
    Assumed seconds; must confirm against a live response.
17. **`GET presence` behavior for unknown users (omit vs `online:false`).**
    UNVERIFIED-ASSUMPTION. Response is untyped in OpenAPI; no fixture available.
    Assumed omitted users are treated OFFLINE.
18. **AND-143 SSE transport framing (the `Flow<SseEvent>` contract).**
    UNVERIFIED-ASSUMPTION. AND-143 is an upstream dependency not present in these
    sources; only the web SSE handler (event names/payload) could be confirmed.

### Corrections made

- C-3 Heartbeat request body `client_ts` → `PresenceHeartbeatIn { device, status }`
  (FR-1 narrative, §4.1 DTO, §4.4 call, §5, §8, T-1).
- C-4/C-5 Removed server `ttl_seconds`/TTL-derived cadence; fixed 30 s constant
  (FR-1, §4.1 `HeartbeatResp`, §4.4 scheduler, §5, T-6, R-3, Q-3, §15 DoD).
- C-6 `GET presence` envelope → bare `List<PresenceDto>` (FR-3, §4.1, §4.2 API
  signature + import, §5, T-2, AC-7).
- C-7 `last_seen` (ISO string) → `last_seen_at` (epoch integer); removed `status`
  read field (§4.1 DTOs, §5, §6 merge, §8, T-2/T-3/T-7, AC-7).
- C-8 Removed `AWAY` state from `PresenceStatus` enum, mapper, indicator colors,
  and tests (FR-5, §4.1, §4.5, T-11, Q-2).
- C-9/C-10 SSE event `presence_update` (batch) → `presence:update` (single user)
  (FR-4, §4.1 `PresenceUpdateEvent`, §5, T-7, R-2, Q-1, AC-4, §15 DoD).
- C-freshness Removed the "2 × TTL freshness window → OFFLINE" synthesis (no TTL
  exists); replaced with server-`online`-driven state + reconnect/60 s re-seed
  (FR-5, §7, T-3).

### Open assumptions

- **Epoch unit of `last_seen_at`** (seconds vs milliseconds) — schema says only
  `integer`; the mapper must be confirmed against a live response (audit #16).
- **Unknown-user handling in `GET presence`** — untyped response; assumed omitted
  = OFFLINE (audit #17).
- **AND-143 SSE wrapper contract** — upstream, not in provided sources; the
  `Flow<SseEvent>` shape, reconnect signal, and exact `data:` framing are assumed
  per the spec's dependency description (audit #18).
- **`status` write field semantics on `PresenceHeartbeatIn`** — present in schema
  but never read back; assumed unused by this client pending backend grooming.
- **Privacy "share online status" toggle (Q-4)** — no backend/web evidence; a
  pure product assumption.

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device); MWS =
contract/MockWebServer (JVM); emu = headless emulator AVD `test35` (x86_64, API
35); device = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R,
API 34, arm64-v8a). Most cases here are JVM/MWS or Compose-UI and run fine on the
emulator; the physical device is only mandatory for the real-network/flaky-host
case (TC-13) where true plaintext-HTTP timeout behavior over a cellular/Wi-Fi NIC
differs from the emulator's loopback.

**TC-AND-145-01 — Heartbeat contract (happy path).** Type: contract/MWS. Target:
MWS (JVM). Preconditions: MockWebServer enqueues `200 { "ok": true, "user_id":
"usr_self", "online": true, "last_seen_at": 1749126660 }`. Steps: call
`PresenceApi.heartbeat(HeartbeatReq(device="android"))`. Expected: request is
`POST /messaging/presence/heartbeat`, body serializes `{ "device": "android" }`,
`Content-Type: application/json`; response decodes to `HeartbeatResp(ok=true,
userId="usr_self", online=true, lastSeenAt=1749126660)`; no `ttl_seconds` parsed.
Traces: AC-2, AC-7.

**TC-AND-145-02 — getPresence contract (bare array, mixed states).** Type:
contract/MWS. Target: MWS (JVM). Preconditions: enqueue `200 [ {user_id:"usr_1",
online:true,last_seen_at:1749126655}, {user_id:"usr_2",online:false,
last_seen_at:1749066131} ]`. Steps: call `getPresence("usr_1,usr_2")`. Expected:
request `GET /messaging/presence?user_ids=usr_1,usr_2`; decodes to a
`List<PresenceDto>` of size 2 with correct `online`/`lastSeenAt`. Traces: AC-5,
AC-7.

**TC-AND-145-03 — DTO → domain mapping.** Type: unit. Target: JVM.
Preconditions: none. Steps: map `PresenceDto(online=true)`,
`PresenceDto(online=false)`, and one with null `lastSeenAt`. Expected:
`online=true` → `PresenceStatus.ONLINE`; `online=false` → `OFFLINE`; `lastSeenAt`
epoch → `Instant`; null `last_seen_at` → null `lastSeen`; no `AWAY` ever produced.
Traces: AC-1, AC-7.

**TC-AND-145-04 — Heartbeat foreground lifecycle (virtual time).** Type: unit
(coroutines-test). Target: JVM. Preconditions: `TestScope`, fake `LifecycleOwner`,
MWS or fake `PresenceApi` counting calls. Steps: deliver `onStart`; advance
virtual time by 0 s, 30 s, 60 s; then `onStop`; advance 60 s; then `onStart`
again. Expected: a beat fires immediately on each `onStart`, then every 30 s;
after `onStop` no further beats; the second `onStart` fires immediately again.
Traces: AC-2, AC-3.

**TC-AND-145-05 — Single heartbeat instance.** Type: unit. Target: JVM.
Preconditions: scheduler already running (`onStart` once). Steps: invoke
`onStart`/`startLoop` again while a job is active. Expected: no second loop is
created (`job?.isActive` guard); call count stays single-cadence. Traces: AC-3.

**TC-AND-145-06 — Heartbeat failure resilience.** Type: contract/MWS. Target:
MWS (JVM). Preconditions: enqueue `500` (or `SocketTimeout`) for beat N, then
`200` for beat N+1. Steps: run scheduler across two ticks (virtual time).
Expected: the failure is swallowed (no crash, no loop cancellation), beat N+1
still fires and succeeds. Traces: AC-6.

**TC-AND-145-07 — SSE merge (single-user `presence:update`).** Type: unit/
integration. Target: JVM. Preconditions: fake `SseClient` emitting an event named
`presence:update` with `{ user_id:"usr_2", online:true, last_seen_at:1749126670 }`;
`usr_2` already tracked. Steps: start repository, emit the event, collect
`presenceOf("usr_2")`. Expected: cache entry for `usr_2` becomes ONLINE with the
new `lastSeen`; observing flow emits the update; most-recent `last_seen_at` wins
over an older seeded value. Traces: AC-4.

**TC-AND-145-08 — Re-seed on SSE reconnect (offline/flaky path).** Type:
integration. Target: JVM. Preconditions: tracked ids `{usr_1,usr_2}` seeded;
fake `SseClient` signals disconnect then reconnect; MWS/fake API records
`getPresence` calls. Steps: trigger disconnect, assert entries marked
`stale=true`; trigger reconnect. Expected: on reconnect, exactly one
`getPresence` re-seed for the currently-tracked ids fires and `stale` is cleared;
during disconnect entries are dimmed, not flipped OFFLINE. Traces: AC-5, AC-6.

**TC-AND-145-09 — Reference-counted tracking & eviction.** Type: unit. Target:
JVM. Preconditions: virtual time; fake API counts seeds. Steps: two trackers
`track({usr_1})`; close both; advance past eviction debounce; re-`track({usr_1})`.
Expected: only one seed for the first two trackers; after both close + debounce
the id is evicted; re-tracking re-seeds. Traces: AC-3, AC-5.

**TC-AND-145-10 — Self exclusion.** Type: unit. Target: JVM. Preconditions: fake
`AuthStateStore.currentUserId = "usr_self"`. Steps: attempt to track a set that
includes `usr_self` and observe `presenceOf("usr_self")`. Expected: `usr_self` is
never seeded (no `getPresence` includes it) and is never populated from peer data.
Traces: AC-8.

**TC-AND-145-11 — Compose indicators + accessibility.** Type: Compose-UI. Target:
emu (test35) — or JVM via Robolectric. Preconditions: composables under test.
Steps: render `AvatarPresenceBadge`/`PresenceDot` in ONLINE, OFFLINE, and stale
states. Expected: online shows the colored dot, offline shows no/muted dot, stale
shows reduced opacity; each exposes a non-color `contentDescription` (e.g.
"Alice, online" / "Alice, last active 5 minutes ago"); state is announced to
TalkBack and never conveyed by color alone (WCAG 1.4.1). Traces: AC-1, AC-9.

**TC-AND-145-12 — Hilt graph singletons.** Type: integration (Hilt test). Target:
emu (test35). Preconditions: Hilt test component. Steps: inject `PresenceApi`,
`PresenceRepository`, `HeartbeatScheduler` twice. Expected: same instance each
time (all `@Singleton`); no second Retrofit/OkHttp/SSE constructed. Traces: AC-3,
AC-10.

**TC-AND-145-13 — Flaky dev host: slow/timeout heartbeat over real network.**
Type: instrumented/e2e. Target: **device (mandatory)** — SM-A156U on real
Wi-Fi/cellular against the plaintext dev host `http://18.222.237.167:8000`.
Preconditions: app built with the dev cleartext config (AND-006); auth
established. Steps: foreground the app and let heartbeats run while the dev host
is slow (~20 s); background then foreground. Expected: a slow/timed-out beat is
swallowed and the loop survives (next tick fires); overlapping in-flight beats are
guarded (a tick is skipped if one is in flight); cleartext HTTP succeeds only on
the dev host; backgrounding stops the loop, foregrounding restarts it with an
immediate beat. Must run on the physical device because emulator loopback does not
reproduce real NIC timeout/cleartext behavior. Traces: AC-2, AC-6, AC-10.

**TC-AND-145-14 — Terminal 401 on heartbeat stops the loop.** Type: contract/MWS.
Target: MWS (JVM). Preconditions: enqueue `401` for the heartbeat, with refresh
also failing (terminal). Steps: run one tick. Expected: after the
refresh-then-retry-once (AND-013) still yields 401, the scheduler stops the loop
and the cache is cleared (deferring re-auth/route-to-login to AND-013/AND-025);
no further beats. Traces: AC-6.

**TC-AND-145-15 — Security: no manual auth headers / no second client.** Type:
unit/integration. Target: JVM. Preconditions: `PresenceApi` over the shared
Retrofit. Steps: inspect the `PresenceApi` interface and the recorded MWS request
headers. Expected: no `@Header("Cookie")`/`@Header("Authorization")`/CSRF
declared on any method; cookies/`X-CSRF-Token` are applied by the shared OkHttp
interceptors (AND-011/AND-012); no new `OkHttpClient`/`Retrofit`/SSE is
constructed. Traces: AC-9 (auth/privacy), AC-10.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (presence reflects online/last-seen) | TC-03, TC-07, TC-11 |
| AC-2 (heartbeat runs while foregrounded; stop/restart) | TC-01, TC-04, TC-13 |
| AC-3 (exactly one process-bound loop) | TC-04, TC-05, TC-09, TC-12 |
| AC-4 (live `presence:update` SSE merge) | TC-07 |
| AC-5 (seed + re-seed on reconnect) | TC-02, TC-08, TC-09 |
| AC-6 (failed beat never stops loop; terminal 401 → stop) | TC-06, TC-08, TC-13, TC-14 |
| AC-7 (DTO codegen decode; correct field names) | TC-01, TC-02, TC-03 |
| AC-8 (self never shown/seeded) | TC-10 |
| AC-9 (not color-only; localized; auth delegated) | TC-11, TC-15 |
| AC-10 (no new client/headers; clean build) | TC-12, TC-13, TC-15 |
