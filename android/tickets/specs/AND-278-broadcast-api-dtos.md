---
id: AND-278
title: Broadcast API + DTOs
milestone: M6
epic: E38
priority: P0
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-279, AND-286]
---

# AND-278 — Broadcast API + DTOs

## 1. Overview & Goal

This ticket defines the typed HTTP seam for the TestLogon **broadcast** (live
streaming) domain on Android: the Retrofit service interface `BroadcastApi`, the
Moshi DTOs it (de)serializes (broadcast sessions, the live/scheduled/upcoming
list shapes, and the full session-detail shape), and the DTO→domain mappers that
produce the canonical `core-model` broadcast types consumed by every downstream
broadcast feature (the browse/scheduled lists in AND-279 and the broadcast
viewer ViewModel in AND-286).

Scope, verbatim from the backlog: *`/broadcast/sessions`, scheduled/upcoming,
session detail DTOs.* This is the Kotlin port of the web reference broadcast API
layer (`frontend/src/api/endpoints/broadcast.ts`) plus the broadcast slice of
`frontend/src/api/types.ts`. The single acceptance criterion is that **broadcast
payloads map (tested)** — every endpoint is callable with verb/path/query/body
matching the backend contract, and every broadcast JSON shape (a live session
with an HLS playback URL, a scheduled/upcoming session with a start time, and a
full session-detail object) decodes losslessly into the domain model, proven by
`MockWebServer` and pure-mapper unit tests.

This is a **transport + serialization-definition** ticket. It owns: the
`BroadcastApi` interface (`@GET`/`@Headers`/`@Body`/`@Query`/`@Path`
annotations), the broadcast DTOs with Moshi codegen adapters, the
`BroadcastSessionStatus` enum, the `BroadcastMappers.kt` DTO→domain functions,
and the Hilt provider that constructs the service from the shared Retrofit.

It deliberately does **not** own: the persistent cookie jar (AND-011), the CSRF
interceptor (AND-012), the 401-refresh `Authenticator` (AND-013), `ApiResult`
wrapping (AND-018), error `detail` mapping (AND-015), Room caching, any
repository, ViewModel, navigation, UI, the HLS player itself (Media3/ExoPlayer,
AND-166/AND-167), or the live chat/real-time stream (SSE, AND-143 family). Those
attach to the shared `OkHttpClient`/`Retrofit` or live in higher layers
(`core-data`, `feature-*`) and take effect for `BroadcastApi` calls without
changes here.

The deliverable: a compiling `BroadcastApi`, its DTOs + codegen adapters, the
mapper functions, the Hilt provider, and a test suite asserting each endpoint's
HTTP method, resolved path, query shape, decoded response, and exhaustive
DTO→domain mapping (including status enums, the HLS URL on live sessions, the
scheduled start time on upcoming sessions, and missing/unknown fields).

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Production code lands in module **`core-network`** (the
  `BroadcastApi` interface, DTOs, mappers, Hilt provider) under package
  `com.testlogon.android.core.network.broadcast`, with the canonical domain
  types in **`core-model`** under
  `com.testlogon.android.core.model.broadcast`.
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP, no reflection fallback), Hilt
  (KSP), Coroutines, JDK 17, minSdk 24 / compile/target 35, AGP 8.7.3, Gradle
  8.9. `java.time` (`Instant`) is available via
  `coreLibraryDesugaringEnabled = true` (AND-001/AND-002).
- **Module layering:** `app -> feature-* -> core-*`. `BroadcastApi`/DTOs/mappers
  live in `core-network` + `core-model`, are consumed by `core-data`
  repositories, and ultimately by the broadcast features. No `feature-*`/`app`
  symbols leak into `core-network`/`core-model`.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** establishes
  the cookie-based session that authenticates every broadcast call.
  `BroadcastApi` cannot return real data until a session exists; it reuses the
  same shared `Retrofit`/`OkHttpClient`, cookie jar (AND-011), CSRF interceptor
  (AND-012), and 401-refresh authenticator (AND-013) that AND-027 wired up. The
  dependency is on the *session machinery being in place*, not on AuthApi types.
  (Backlog lists `Deps: AND-027`.)
- **Transitive upstream:** AND-026 (Moshi/DTO patterns + the shared
  `InstantJsonAdapter`), AND-010 (shared Retrofit/Moshi), AND-009 (shared
  `OkHttpClient` + ~20s timeouts + redacting logger), AND-016 (bounded backoff
  for idempotent GETs), AND-006 (`BuildConfig.API_BASE_URL`). Dev base URL
  resolves to `http://18.222.237.167:8000/` (plaintext HTTP, unreliable dev
  host).
- **Web reference (authoritative for shapes):**
  `frontend/src/api/endpoints/broadcast.ts` (endpoints) and
  `frontend/src/api/types.ts` (`BroadcastSession`, `BroadcastStatus`,
  `BroadcastHost`/`Broadcaster`). OpenAPI at `/openapi.json` is the final
  authority; any deviation in this spec is reconciled against it before merge.
- **Downstream siblings (this epic, E38 / M6):**
  - **AND-279 (Browse / scheduled broadcasts)** — renders live/scheduled/
    upcoming lists and a remind-me toggle; consumes this ticket's list calls and
    domain model.
  - **AND-286 (Broadcast viewer ViewModel)** — owns the session state machine
    and chat merge; consumes the session-detail call and the HLS playback URL
    surfaced here.
  - **AND-287 (Broadcast viewer tests)** — depends on AND-286.

## 3. Functional Requirements

FR-1. Declare a single Retrofit interface `BroadcastApi` covering the broadcast
read operations exposed by `broadcast.ts`: list sessions filtered by status
(live / scheduled / upcoming), list a single status convenience set if the
backend exposes one, and get a single session's full detail. (Exact set
reconciled against `/openapi.json`; Section 5 is the working contract.)

FR-2. Each method's HTTP verb and relative path match the backend contract.
Paths are declared **without** a leading slash (AND-010 convention) so they
append to the normalized base URL `http://18.222.237.167:8000/`.

FR-3. All methods are `suspend` and return typed DTO bodies (Retrofit native
coroutine support). All broadcast read operations are **idempotent GETs**.

FR-4. The list endpoint uses a typed `@Query` `status` param accepting the
on-wire values `live`, `scheduled`, `upcoming` (and an optional `page` cursor).
Single-resource ops use `@Path`. No raw `Map`/`JsonObject`.

FR-5. Define Moshi `@JsonClass(generateAdapter = true)` DTOs for every broadcast
shape: `BroadcastSessionDto` (list element + detail superset),
`BroadcastSessionListRespDto` (paged envelope), `BroadcastHostDto`, and a
`BroadcastPlaybackDto` for the HLS/playback sub-object. Wire fields are
snake_case; Kotlin properties are camelCase via `@Json(name=...)` only where
codegen cannot infer.

FR-6. **Session status MUST be modeled losslessly.** Define
`BroadcastSessionStatus { LIVE, SCHEDULED, UPCOMING, ENDED, CANCELLED, UNKNOWN }`.
The mapper maps unknown status strings to `UNKNOWN` (never throws). `scheduled`
and `upcoming` are distinct on the wire (scheduled = confirmed start time set;
upcoming = soon/announced); both are preserved as distinct enum values so
AND-279 can list them separately.

FR-7. **The HLS playback URL MUST be carried through for live sessions.** A live
session exposes a `playback` sub-object with an `hls_url` (and optional
`thumbnail_url`/`dvr` flag). The DTO preserves it verbatim; the domain
`BroadcastSession.playbackUrl` is non-null for `LIVE` sessions and null
otherwise. No HLS playback logic is implemented here (that is AND-166/AND-167);
this ticket only transports the URL for AND-286 to feed to ExoPlayer.

FR-8. Timestamps are parsed to `java.time.Instant` via the shared
`InstantJsonAdapter`: `scheduled_start_at` (when the broadcast is due to begin),
`started_at` (actual go-live), and `ended_at`. `scheduledStartAt` is non-null
for `SCHEDULED`/`UPCOMING` sessions so AND-279 can render countdowns and
remind-me.

FR-9. Provide pure DTO→domain mappers in `BroadcastMappers.kt`:
`BroadcastSessionDto.toDomain(): BroadcastSession`,
`BroadcastHostDto.toDomain(): BroadcastHost`, and
`BroadcastSessionListRespDto.toDomain(): BroadcastSessionPage`. Mappers MUST map
unknown enum strings to `UNKNOWN`, tolerate absent optional fields via Kotlin
defaults, and never throw on recoverable shape variance.

FR-10. A Hilt `@Provides @Singleton fun provideBroadcastApi(retrofit: Retrofit):
BroadcastApi` constructs the service from the shared Retrofit (AND-010). No new
Retrofit/OkHttp instance is created. Broadcast Moshi adapters are codegen (KSP);
only the shared `InstantJsonAdapter` (and any enum-fallback adapter) is
registered on the shared Moshi if not already present.

FR-11. CSRF (`X-CSRF-Token`) and cookies are **not** declared per-method; they
are injected globally (AND-012/AND-011). `BroadcastApi` stays header-agnostic.
(All operations here are GETs, so CSRF is irrelevant at runtime, but the rule
holds for any future mutation.)

## 4. Technical Design

Production code lands in
`core-network/src/main/kotlin/com/testlogon/android/core/network/broadcast/`
(interface, DTOs, mappers, `di/`) and
`core-model/src/main/kotlin/com/testlogon/android/core/model/broadcast/`
(domain types).

### 4.1 Domain types (core-model)

```kotlin
package com.testlogon.android.core.model.broadcast

import java.time.Instant

data class BroadcastSession(
    val id: String,
    val title: String,
    val description: String?,
    val status: BroadcastSessionStatus,
    val host: BroadcastHost,
    val scheduledStartAt: Instant?,   // non-null for SCHEDULED / UPCOMING
    val startedAt: Instant?,          // non-null once LIVE / ENDED
    val endedAt: Instant?,            // non-null for ENDED
    val playbackUrl: String?,         // HLS .m3u8; non-null for LIVE (and DVR'd ENDED)
    val thumbnailUrl: String?,
    val viewerCount: Int?,            // current viewers; null when not live
    val isDvr: Boolean,               // playback supports DVR/seek
    val remindMeSet: Boolean,         // viewer has a reminder for this session
)

enum class BroadcastSessionStatus { LIVE, SCHEDULED, UPCOMING, ENDED, CANCELLED, UNKNOWN }

data class BroadcastHost(
    val id: String,
    val username: String,            // u-identifier / handle
    val displayName: String,
    val avatarUrl: String?,
)

data class BroadcastSessionPage(
    val items: List<BroadcastSession>,
    val nextPage: String?,           // opaque cursor; null when no more
)
```

These are the canonical types AND-279 and AND-286 consume. `BroadcastHost`
mirrors the public-profile identity semantics from AND-073 (the `u-identifier`
handle).

### 4.2 DTOs (core-network)

```kotlin
package com.testlogon.android.core.network.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import java.time.Instant

@JsonClass(generateAdapter = true)
data class BroadcastSessionDto(
    val id: String,
    val title: String,
    val description: String? = null,
    val status: String? = null,
    val host: BroadcastHostDto? = null,
    @Json(name = "scheduled_start_at") val scheduledStartAt: Instant? = null,
    @Json(name = "started_at") val startedAt: Instant? = null,
    @Json(name = "ended_at") val endedAt: Instant? = null,
    val playback: BroadcastPlaybackDto? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "viewer_count") val viewerCount: Int? = null,
    @Json(name = "remind_me") val remindMe: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class BroadcastPlaybackDto(
    @Json(name = "hls_url") val hlsUrl: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    val dvr: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class BroadcastHostDto(
    val id: String,
    val username: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
)

@JsonClass(generateAdapter = true)
data class BroadcastSessionListRespDto(
    val items: List<BroadcastSessionDto> = emptyList(),
    @Json(name = "next_page") val nextPage: String? = null,
)
```

`BroadcastSessionDto` is the superset used by both the list element and the
detail response; absent fields (e.g. `playback` on a scheduled session) fall
back to Kotlin defaults. `Instant` (de)serialization uses the shared
`InstantJsonAdapter`. If `/openapi.json` shows the top-level `thumbnail_url`
lives only inside `playback`, the mapper prefers `playback.thumbnailUrl` then
the top-level field (Q-3).

### 4.3 The `BroadcastApi` interface

```kotlin
package com.testlogon.android.core.network.broadcast

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

interface BroadcastApi {

    /**
     * List broadcast sessions filtered by status. Idempotent GET; paged via an
     * opaque next_page cursor. `status` accepts "live" | "scheduled" |
     * "upcoming" (and, if exposed, "ended").
     */
    @GET("broadcast/sessions")
    suspend fun listSessions(
        @Query("status") status: String,
        @Query("page") page: String? = null,
    ): BroadcastSessionListRespDto

    /** Full detail for a single broadcast session. Idempotent GET. */
    @GET("broadcast/sessions/{sessionId}")
    suspend fun getSession(@Path("sessionId") sessionId: String): BroadcastSessionDto
}
```

Notes: the exact path (`broadcast/sessions` vs `broadcast/sessions/live` style
dedicated routes) and whether `status` is a query param or a path segment are
confirmed against `/openapi.json` and `broadcast.ts` before coding (Q-1). If the
backend exposes dedicated `scheduled`/`upcoming` routes instead of a `status`
query, the interface adds the matching methods; the DTOs/mappers are unaffected.
The remind-me toggle itself (a mutation) is **owned by AND-279**, not declared
here; this ticket only surfaces the read-side `remind_me` boolean.

### 4.4 Mappers

```kotlin
package com.testlogon.android.core.network.broadcast

import com.testlogon.android.core.model.broadcast.*

fun BroadcastSessionDto.toDomain(): BroadcastSession = BroadcastSession(
    id = id,
    title = title,
    description = description,
    status = status.toBroadcastStatus(),
    host = (host ?: BroadcastHostDto(id = "", username = null,
        displayName = null, avatarUrl = null)).toDomain(),
    scheduledStartAt = scheduledStartAt,
    startedAt = startedAt,
    endedAt = endedAt,
    playbackUrl = playback?.hlsUrl,
    thumbnailUrl = playback?.thumbnailUrl ?: thumbnailUrl,
    viewerCount = viewerCount,
    isDvr = playback?.dvr ?: false,
    remindMeSet = remindMe,
)

fun BroadcastHostDto.toDomain(): BroadcastHost = BroadcastHost(
    id = id,
    username = username.orEmpty(),
    displayName = displayName ?: username.orEmpty(),
    avatarUrl = avatarUrl,
)

fun BroadcastSessionListRespDto.toDomain(): BroadcastSessionPage =
    BroadcastSessionPage(items = items.map { it.toDomain() }, nextPage = nextPage)

private fun String?.toBroadcastStatus(): BroadcastSessionStatus =
    when (this?.lowercase()) {
        "live" -> BroadcastSessionStatus.LIVE
        "scheduled" -> BroadcastSessionStatus.SCHEDULED
        "upcoming" -> BroadcastSessionStatus.UPCOMING
        "ended", "finished" -> BroadcastSessionStatus.ENDED
        "cancelled", "canceled" -> BroadcastSessionStatus.CANCELLED
        else -> BroadcastSessionStatus.UNKNOWN
    }
```

Mappers are pure, side-effect-free, and individually unit-tested. The
status-extension helper centralizes unknown-value tolerance and absorbs both
US/UK spellings of "cancelled" and `ended`/`finished` synonyms.

### 4.5 Hilt provider

```kotlin
package com.testlogon.android.core.network.broadcast.di

import com.testlogon.android.core.network.broadcast.BroadcastApi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object BroadcastApiModule {

    @Provides
    @Singleton
    fun provideBroadcastApi(retrofit: Retrofit): BroadcastApi =
        retrofit.create(BroadcastApi::class.java)
}
```

The injected `Retrofit` is the singleton from AND-010's `NetworkModule` (built
on AND-009's `OkHttpClient`). No client/Retrofit is constructed here.

### 4.6 Gradle wiring

No new dependencies. `core-network/build.gradle.kts` already has Retrofit, Moshi
(+ KSP codegen), Hilt, and (test) MockWebServer from AND-010. `core-network`
already depends on `:core-model`. This ticket adds source files (interface,
DTOs, mappers, provider) and domain types in `:core-model` only.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All reads ride the cookie
session. Shapes below are the working contract, reconciled against
`/openapi.json` + `broadcast.ts` before merge.

### GET `broadcast/sessions?status=live`
Response `200` — a live session carries an HLS `playback.hls_url`:
```json
{
  "items": [
    {
      "id": "bcs_01HX1",
      "title": "Friday Night Live",
      "description": "Weekly Q&A",
      "status": "live",
      "host": {
        "id": "usr_42", "username": "dana", "display_name": "Dana Ruiz",
        "avatar_url": "https://cdn.testlogon.dev/a/usr_42.jpg"
      },
      "started_at": "2026-06-05T23:00:00Z",
      "viewer_count": 1284,
      "playback": {
        "hls_url": "https://stream.testlogon.dev/bcs_01HX1/index.m3u8",
        "thumbnail_url": "https://cdn.testlogon.dev/t/bcs_01HX1.jpg",
        "dvr": true
      }
    }
  ],
  "next_page": null
}
```

### GET `broadcast/sessions?status=scheduled`
Response `200` — scheduled/upcoming sessions carry `scheduled_start_at` and no
`playback`:
```json
{
  "items": [
    {
      "id": "bcs_01HX2",
      "title": "Album listening party",
      "status": "scheduled",
      "host": { "id": "usr_42", "username": "dana", "display_name": "Dana Ruiz" },
      "scheduled_start_at": "2026-06-07T18:00:00Z",
      "thumbnail_url": "https://cdn.testlogon.dev/t/bcs_01HX2.jpg",
      "remind_me": true
    }
  ],
  "next_page": "eyJvZmZzZXQiOjUwfQ=="
}
```

### GET `broadcast/sessions?status=upcoming`
Response `200` — identical element shape with `status:"upcoming"`. Used by
AND-279 as a separate tab/section from `scheduled`.

### GET `broadcast/sessions/{sessionId}`
Response `200` — a single `BroadcastSessionDto` (the detail superset; same
element shape, with `playback` present when live/DVR). `404` if unknown. This is
the call AND-286's viewer ViewModel uses to obtain the `playbackUrl` it feeds to
ExoPlayer (AND-167).

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg,type,loc}] | {code,...}`). Mapping to a typed `ApiError` is
owned by **AND-015**; this ticket lets non-2xx surface as
`retrofit2.HttpException`.

## 6. Data & State Management

`BroadcastApi` is **stateless** — a singleton interface proxy with no fields.
This ticket holds no `StateFlow`/`UiState`, no Room, no DataStore.

- **Session state** (auth) lives in cookies, persisted by the cookie jar
  (AND-011); `BroadcastApi` never reads/writes cookies. CSRF
  (`ui_csrf` → `X-CSRF-Token`) would be attached by AND-012 for any future
  mutation; all current operations are GETs.
- **Serialization:** request/response (de)serialization uses Moshi codegen
  adapters (KSP) + the shared `InstantJsonAdapter` via the shared converter.
  Unknown JSON keys are ignored; absent optional fields fall back to Kotlin
  defaults (lenient). Unknown enum strings map to `UNKNOWN` in mappers, not at
  the adapter level.
- **Domain mapping** is the one transformation this ticket performs:
  DTO→`core-model` via pure `toDomain()` functions. Callers (`core-data`
  broadcast repository) decide whether to wrap in `ApiResult<T>` (AND-018),
  cache in Room (AND-115/AND-116), or expose via `StateFlow`. None of that is
  here.
- **Paging:** `listSessions` returns a `BroadcastSessionListRespDto` /
  `BroadcastSessionPage` with a `next_page` cursor; the actual Paging 3
  `PagingSource`/`RemoteMediator` for the lists is owned by AND-279. This ticket
  only exposes the cursor-bearing call.
- **"broadcast session state machine"** (idle → connecting → live → reconnecting
  → ended) referenced by AND-286 is a **ViewModel** concern, not a transport
  concern. This ticket only supplies the typed `BroadcastSessionStatus` and the
  `playbackUrl` the state machine keys off; it holds no machine of its own.
- **Threading:** suspend methods are invoked from a coroutine on an IO
  dispatcher injected at the repository layer. This ticket imposes no
  dispatcher.

## 7. Error Handling & Resilience

- **Non-2xx** surfaces as `retrofit2.HttpException` carrying the raw error body
  for AND-015 to decode the FastAPI `detail`. A `401` on any call is intercepted
  by the AND-013 `Authenticator`, which calls `sessionRefresh()` once and
  retries; only a second `401` propagates (→ route to login, AND-025).
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged. The ~20s timeouts and bounded backoff for
  the **idempotent GETs** (`listSessions`, `getSession`) are owned by
  AND-009/AND-016 on the shared client. These reads are safe to auto-retry.
- **Stale/offline lists:** because the dev host is unreliable, the broadcast
  lists are expected to render from a stale cache while a refresh fails. That
  SWR/offline behavior is owned by AND-116/AND-117 in `core-data`; this ticket
  only guarantees that a failed call surfaces a clean throwable rather than
  partial/garbage data.
- **Deserialization failures** surface as `JsonDataException` from the
  converter. Mappers are written defensively so recoverable shape variance
  (missing `playback` on a scheduled session, unknown `status`, absent
  `viewer_count`, missing `host`) never throws. A genuinely malformed payload
  (e.g. an item with no `id`/`title`, which Moshi treats as non-null) fails the
  converter deterministically, surfaced to callers for AND-015/AND-018 handling.
- **Live-but-no-URL:** a session reported `status:"live"` with no
  `playback.hls_url` maps to `status = LIVE, playbackUrl = null`; AND-286 must
  treat a null `playbackUrl` on a LIVE session as a "stream unavailable" state
  rather than crashing (R-2). This ticket guarantees the mapper does not
  fabricate a URL.
- This ticket maps **no** errors to user-facing types itself — that is AND-015
  (`ApiError`) / AND-018 (`ApiResult`).

## 8. Security & Privacy

- **Authenticated surface:** broadcast endpoints require the cookie session
  established by the auth flow (AND-027 family). `BroadcastApi` adds no manual
  `Cookie`/`Authorization` headers; identity is carried implicitly by the jar.
  Whether some live listings are public/unauthenticated is reconciled against
  `/openapi.json` (Q-4); the transport is identical either way.
- **HLS URL sensitivity:** `playback.hls_url` may embed a short-lived signed
  token or be entitlement-gated server-side. This ticket transports it verbatim
  and **must not log it** (it can grant stream access). Any expiry/refresh of a
  signed playback URL is a playback-feature concern (AND-167/AND-286), not here.
- **CSRF:** no mutating verbs in this ticket; the global AND-012 interceptor
  remains the owner for any future broadcast mutation.
- **Cleartext on dev:** broadcast payloads (titles, host handles, playback URLs)
  ride plaintext HTTP on the dev host — a known, dev-only risk permitted by the
  scoped cleartext config (AND-006); `staging`/`prod` are HTTPS-only. Note the
  `hls_url` in the sample points at an HTTPS CDN even on dev.
- **No payload/URL logging:** this ticket adds no logging; the shared logging
  interceptor (AND-009) is debug-only and redacted. A code-review check confirms
  no `hls_url` or broadcast payload body reaches logcat in any build.
- **No new permissions / no token storage:** purely network transport.

## 9. Accessibility & i18n

Not directly applicable — this is a headless transport + serialization layer
with no UI surface and no user-facing strings. Two hand-offs to downstream UI
tickets:

- **i18n of times/counts:** this ticket transports `Instant`
  (`scheduledStartAt`/`startedAt`) and the raw `viewerCount` without formatting
  them. Localized, timezone-aware countdown rendering ("starts in 2h"), relative
  "live now" labels, and number-formatted viewer counts are owned by the
  broadcast list/viewer UI (AND-279 / the AND-286 screen).
- **Error text localization** derived from these endpoints is owned by AND-015
  (error mapping) and the consuming feature ViewModels.

## 10. Telemetry & Logging

- **HTTP logging** is inherited from AND-009's redacting
  `HttpLoggingInterceptor` (debug builds only). No new logging here; broadcast
  payload bodies — and especially `hls_url` — must be redacted (Section 8). No
  `Timber` payload dumps.
- **No analytics events** emitted by this layer. Broadcast-list-viewed,
  session-opened, remind-me-toggled, and stream-start/heartbeat analytics are
  emitted by the consuming feature ViewModels (AND-279/AND-286) and the playback
  analytics heartbeat (AND-171), derived from `ApiResult` outcomes — and must
  follow the AND-052 redaction policy (no raw `hls_url`/credential material).
- **Build-time signal:** KSP must generate Moshi adapters for every broadcast
  DTO; a missing adapter fails the build (no reflection fallback, per AND-010
  policy).

## 11. Testing Strategy

All tests are JVM unit tests in `core-network/src/test/...` using `MockWebServer`
and the production Moshi/Retrofit configuration (including the shared
`InstantJsonAdapter`). Endpoint tests assert **verb, resolved path, query, and
decoded response**; mapper tests assert **exhaustive DTO→domain correctness**.
This satisfies the backlog acceptance "broadcast payloads map (tested)".

Test harness:
```kotlin
private fun api(server: MockWebServer): BroadcastApi {
    val moshi = Moshi.Builder()
        .add(InstantJsonAdapter()) // mirrors provideMoshi()
        .build()
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(BroadcastApi::class.java)
}
```

**T-1 — `listSessions(live)` query + decode (KEY).**
```kotlin
@Test fun listSessions_live_sendsStatusQueryAndDecodes() = runTest {
    val server = MockWebServer().apply {
        enqueue(MockResponse().setBody(LIVE_JSON)); start()
    }
    val resp = api(server).listSessions(status = "live")
    val req = server.takeRequest()
    assertEquals("GET", req.method)
    val url = req.requestUrl!!
    assertEquals("/broadcast/sessions", url.encodedPath)
    assertEquals("live", url.queryParameter("status"))
    val s = resp.items.single().toDomain()
    assertEquals(BroadcastSessionStatus.LIVE, s.status)
    assertEquals("https://stream.testlogon.dev/bcs_01HX1/index.m3u8", s.playbackUrl)
    assertTrue(s.isDvr)
    assertEquals(1284, s.viewerCount)
    server.shutdown()
}
```

**T-2 — scheduled mapping.** `SCHEDULED_JSON` → `status == SCHEDULED`,
`scheduledStartAt` parsed to the right `Instant`, `playbackUrl == null`,
`remindMeSet == true`, `nextPage == "eyJvZmZzZXQiOjUwfQ=="`.

**T-3 — upcoming mapping.** `status:"upcoming"` maps to
`BroadcastSessionStatus.UPCOMING` (distinct from `SCHEDULED`), confirming the
two tabs in AND-279 can be separated.

**T-4 — `getSession`** issues `GET /broadcast/sessions/bcs_01HX1` (path param
interpolated) and decodes the single-session detail superset including
`playback`.

**T-5 — status enum tolerance.** `status:"ended"` → `ENDED`,
`status:"canceled"` → `CANCELLED`, `status:"weird"` → `UNKNOWN`, missing
`status` → `UNKNOWN`. No throw.

**T-6 — missing-optionals tolerance.** A scheduled item with no `playback`, no
`viewer_count`, no `description`, and no top-level `thumbnail_url` maps without
throwing: `playbackUrl == null`, `viewerCount == null`, `isDvr == false`.

**T-7 — host fallback.** An item with `host` present but missing `display_name`
maps `displayName` to the `username`; a `host` with only an `id` still maps
(no throw). An item with **no** `host` maps to an empty-identity `BroadcastHost`
(R-3) rather than crashing.

**T-8 — playback thumbnail precedence.** When both `playback.thumbnail_url` and
top-level `thumbnail_url` are present, `thumbnailUrl` prefers
`playback.thumbnail_url`; when only the top-level is present, it is used (Q-3).

**T-9 — paging passthrough.** `listSessions(status, page = "cursor1")` sends
`?status=…&page=cursor1`; `toDomain()` on the envelope yields a
`BroadcastSessionPage` whose `nextPage` matches the response.

**T-10 — live-without-url safety.** A `status:"live"` item with no
`playback.hls_url` maps to `LIVE` + `playbackUrl == null` (R-2) — no fabricated
URL, no throw.

**T-11 — error propagation.** A `401` from `listSessions` throws
`retrofit2.HttpException` with `code() == 401` (non-2xx not swallowed, leaving
room for AND-013/AND-015).

**T-12 — Hilt provider.** `@HiltAndroidTest` (or `core-testing` harness) injects
`BroadcastApi` and asserts a non-null singleton built on the shared Retrofit
(same instance on repeated injection).

Coverage target: ≥90% on the new surface (interface binding + all mappers).
Every endpoint has ≥1 path/verb assertion; every DTO field with non-trivial
mapping (status enum, playback URL, scheduled start time, host fallback,
thumbnail precedence) has a dedicated assertion.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-027** — AuthApi / session endpoints. Establishes the cookie session
  machinery every broadcast call rides on; blocking per the backlog
  `Deps: AND-027`.

**Transitive upstream (already required by AND-027/AND-010):** AND-026
(Moshi/DTO patterns + `InstantJsonAdapter`), AND-010 (shared Retrofit/Moshi),
AND-009 (shared `OkHttpClient`, timeouts, redacting logger), AND-016
(idempotent-GET backoff), AND-006 (`BuildConfig`), AND-003/AND-004 (module
structure, Hilt baseline). Integration-depends on AND-011/AND-012/AND-013 for
cookies/CSRF/refresh at runtime (unit tests use MockWebServer and are
unaffected).

**Downstream (this ticket blocks):**
- **AND-279 (Browse / scheduled broadcasts)** — renders live/scheduled/upcoming
  lists (Paging 3 over `listSessions`) and owns the remind-me **mutation**;
  consumes this ticket's `BroadcastApi` + `BroadcastSession`/`BroadcastSessionPage`
  domain types. Hence `blocks: [AND-279]`.
- **AND-286 (Broadcast viewer ViewModel)** — owns the session state machine and
  chat merge; consumes `getSession` and the `playbackUrl` surfaced here to feed
  ExoPlayer (AND-167). Hence `blocks: [AND-286]`.
- AND-287 (Broadcast viewer tests) depends on AND-286 transitively.
- The **broadcast repository** (`core-data`) consumes `BroadcastApi` and the
  mappers and adds SWR caching (AND-116).

**Sequencing within the ticket:** (1) confirm endpoint set, the `status`
query-vs-path decision, paths, and field names against `/openapi.json` +
`frontend/src/api/endpoints/broadcast.ts` + `types.ts`; (2) define `core-model`
domain types; (3) define DTOs + codegen adapters; (4) write
`BroadcastMappers.kt`; (5) declare `BroadcastApi`; (6) add `BroadcastApiModule`;
(7) write tests T-1..T-12.

## 13. Risks & Open Questions

- **R-1 List routing shape.** The backend may filter by a `status` query on a
  single `broadcast/sessions` route, or expose dedicated routes
  (`broadcast/sessions/live`, `/scheduled`, `/upcoming`). Mitigation: match
  `broadcast.ts`/OpenAPI; default to the `?status=` query. Guarded by T-1.
- **R-2 Live session without a playable URL.** A `live` session may transiently
  lack `playback.hls_url` (just-going-live, region-gated, entitlement-gated).
  Mitigation: mapper preserves `status = LIVE` with `playbackUrl = null`; AND-286
  treats null as "stream unavailable". Guarded by T-10.
- **R-3 Missing/partial host.** Some sessions may omit `host` or send a partial
  host. Mitigation: mapper provides an empty-identity fallback and prefers
  `display_name`→`username`. Guarded by T-7. Open: should a session with no host
  be filtered out by the repository? (Defer to AND-279.)
- **R-4 Scheduled vs upcoming semantics.** The distinction between `scheduled`
  and `upcoming` is backend-defined; if they collapse to one value, AND-279's
  two tabs merge. Mitigation: preserve both as distinct enum values here so the
  decision lives in the UI ticket, not transport. Guarded by T-3.
- **R-5 HLS URL expiry.** A signed `hls_url` may expire between `getSession` and
  player start. Mitigation: out of scope here (AND-167/AND-286 handle re-fetch);
  this ticket only transports the URL and must not cache it beyond the DTO.
- **Q-1** Is the list a `?status=` query on `broadcast/sessions` or dedicated
  status routes? *Proposed:* match OpenAPI/`broadcast.ts`; spec assumes the
  `status` query.
- **Q-2** Paging shape: `{items, next_page}` cursor envelope vs bare array vs
  offset/limit? *Proposed:* default to the `{items, next_page}` cursor envelope;
  reconcile with `broadcast.ts`. Guarded by T-9.
- **Q-3** Is `thumbnail_url` top-level, inside `playback`, or both? *Proposed:*
  DTO captures both; mapper prefers `playback.thumbnail_url`. Guarded by T-8.
- **Q-4** Are any broadcast listings public (unauthenticated)? *Proposed:*
  confirm via OpenAPI; transport is identical, but it affects whether AND-279 can
  show a pre-login preview.
- **Q-5** Does `getSession` return the same superset as a list element, or a
  richer detail object (e.g. with chat-channel id / ingest metadata)? *Proposed:*
  confirm via OpenAPI; if richer, extend `BroadcastSessionDto` with optional
  fields rather than introducing a second DTO. Guarded by T-4.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Broadcast payloads map (tested): every broadcast JSON
  shape in Section 5 — the live session (with `playback.hls_url`), the scheduled
  session (with `scheduled_start_at`), the upcoming session, and the
  single-session detail — decodes via the production Moshi config and maps
  losslessly into the `core-model` domain types, proven by mapper unit tests
  (T-1..T-3, T-5..T-8, T-10).
- **AC-2.** `BroadcastApi` declares the broadcast read operations
  (`listSessions(status, page)`, `getSession(sessionId)`) and the module
  compiles against the new DTOs and `core-model` types.
- **AC-3.** Each endpoint is callable and its **verb + resolved path + query**
  match Section 5, asserted with MockWebServer (T-1, T-4, T-9).
- **AC-4.** The `status` query is serialized for `live`/`scheduled`/`upcoming`
  and the paged `{items, next_page}` envelope decodes, with the cursor preserved
  through `toDomain()` (T-1, T-2, T-9).
- **AC-5.** The HLS `playback.hls_url` is carried through to
  `BroadcastSession.playbackUrl` for live sessions and is `null` for
  scheduled/upcoming; `isDvr` reflects `playback.dvr` (T-1, T-2, T-10).
- **AC-6.** `scheduled_start_at`/`started_at`/`ended_at` parse to `Instant` via
  the shared adapter; `scheduledStartAt` is non-null for scheduled/upcoming
  (T-2, T-3).
- **AC-7.** Unknown/synonym status strings and missing optional fields map to
  `UNKNOWN`/defaults (including the host fallback) without throwing (T-5, T-6,
  T-7).
- **AC-8.** Non-2xx (e.g. `401` from `listSessions`) surfaces as `HttpException`
  and is not swallowed (T-11).
- **AC-9.** `BroadcastApi` is Hilt-provided as a `@Singleton` on the shared
  Retrofit; repeated injection yields the same instance; no new
  `OkHttpClient`/`Retrofit` and no per-method CSRF/cookie headers (T-12).
- **AC-10.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle
  8.9 / JDK 17 with KSP-generated adapters present and no detekt/lint
  regressions.

## 15. Definition of Done

- Domain types (`BroadcastSession`, `BroadcastHost`, `BroadcastSessionPage`,
  `BroadcastSessionStatus`) live in `core-model`
  (`com.testlogon.android.core.model.broadcast`); DTOs, `BroadcastApi`,
  `BroadcastMappers.kt`, and `BroadcastApiModule` live in `core-network`
  (`com.testlogon.android.core.network.broadcast` + `.di`).
- Open questions Q-1..Q-5 are resolved against `/openapi.json` and
  `frontend/src/api/endpoints/broadcast.ts` + `types.ts`; the interface's
  paths/verbs/query params and the DTO field names reflect the confirmed
  contract.
- MockWebServer + mapper tests T-1 through T-12 are implemented and green in CI;
  ≥90% line coverage on the new surface; every endpoint has a path/verb
  assertion and status/playback-URL/scheduled-time/host mapping each has a
  dedicated assertion.
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/auth headers in the
  interface; no broadcast payload bodies and **no `hls_url`** in logs (verified
  in review).
- `./gradlew :core-model:assemble :core-network:assemble :core-network:testDebugUnitTest`
  passes locally and in CI with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; the broadcast repository
  (`core-data`) and the M6 broadcast features are unblocked — **AND-279 has the
  list calls + paging envelope** and **AND-286 has `getSession` + the
  `playbackUrl`** to drive the viewer.
- A one-line note in the `core-network` README (owned by AND-007) records the
  `BroadcastApi` path/verb map and the delegation of cookie/CSRF/refresh to
  AND-011/AND-012/AND-013.
</content>
</invoke>
