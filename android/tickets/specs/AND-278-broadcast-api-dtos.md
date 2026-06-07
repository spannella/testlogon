---
id: AND-278
title: Broadcast API + DTOs
milestone: M6
epic: E38
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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

FR-4. **[CORRECTED]** The list endpoint uses an optional typed `@Query` `status`
param (a free lifecycle string, e.g. `live`/`scheduled`/`stopped`) and an
optional `@Query` `limit: Int`. **There is no `page` cursor** — the envelope is
`{items, has_more}`. Scheduled and upcoming are **dedicated routes**
(`broadcast/sessions/scheduled`, `broadcast/sessions/upcoming`), each taking only
`limit` and returning `{items, count}`. Single-resource ops use `@Path`. No raw
`Map`/`JsonObject`.

FR-5. **[CORRECTED]** Define Moshi `@JsonClass(generateAdapter = true)` DTOs for
every broadcast shape: `BroadcastSessionDto` (the `BroadcastSessionOut` shape,
used for both list element and `getSession`), `BroadcastSessionListRespDto`
(`{items, has_more}`), `BroadcastScheduledListRespDto` (`{items, count}`), and
`BroadcastPlaybackUrlDto` (`{session_id, playback_url, expires_at}`). **There is
no `BroadcastHostDto` and no `BroadcastPlaybackDto`** — the wire has no nested
host or playback object. Wire fields are snake_case; Kotlin properties are
camelCase via `@Json(name=...)`.

FR-6. **[CORRECTED]** **Session status MUST be modeled losslessly.** Define
`BroadcastSessionStatus { DRAFT, SCHEDULED, PROVISIONING, READY, LIVE, STOPPING,
STOPPED, CANCELLED, ERROR, UNKNOWN }` — the verified lifecycle union from
`broadcast.ts`. The mapper maps unknown status strings to `UNKNOWN` (never
throws). There is **no `UPCOMING` or `ENDED` status value**: "upcoming" is a
route, and the terminal state is `STOPPED`/`CANCELLED`.

FR-7. **[CORRECTED]** **The HLS playback URL MUST be carried through.** The URL
is the **top-level `cloudfront_playback_url`** field (not a `playback.hls_url`
sub-object). The DTO preserves it verbatim; the domain
`BroadcastSession.playbackUrl` is populated from it (typically non-null once
`READY`/`LIVE`, null while `DRAFT`/`SCHEDULED`). A fresh short-lived URL may be
minted via `POST .../playback-url`. No HLS playback logic is implemented here
(AND-166/AND-167); this ticket only transports the URL for AND-286.

FR-8. **[CORRECTED]** Timestamps: `created_at`/`updated_at`/`started_at`/
`stopped_at`/`cancelled_at` are **ISO-8601 strings**, parsed to
`java.time.Instant` in the mapper. `scheduled_at` (and `expires_at` on the mint
response) is an **epoch-second integer**, parsed via `Instant.ofEpochSecond`.
There is **no `scheduled_start_at` or `ended_at`** field; `stopped_at` is the
go-offline timestamp. `scheduledAt` is non-null for scheduled sessions so AND-279
can render countdowns.

FR-9. **[CORRECTED]** Provide pure DTO→domain mappers in `BroadcastMappers.kt`:
`BroadcastSessionDto.toDomain(): BroadcastSession`,
`BroadcastSessionListRespDto.toDomain(): BroadcastSessionPage`, and
`BroadcastScheduledListRespDto.toDomain(): BroadcastScheduledPage`. (No host
mapper — there is no host DTO.) Mappers MUST map unknown enum strings to
`UNKNOWN`, tolerate absent optional fields via Kotlin defaults, and never throw
on recoverable shape variance.

FR-10. A Hilt `@Provides @Singleton fun provideBroadcastApi(retrofit: Retrofit):
BroadcastApi` constructs the service from the shared Retrofit (AND-010). No new
Retrofit/OkHttp instance is created. Broadcast Moshi adapters are codegen (KSP);
only the shared `InstantJsonAdapter` (and any enum-fallback adapter) is
registered on the shared Moshi if not already present.

FR-11. **[CORRECTED]** Auth headers are **not** declared per-method; they are
injected globally. Note the web client (`client.ts`) attaches, on **every**
request including GETs: cookies (`credentials:"include"`), an
`Authorization: Bearer <accessToken>`, the `X-CSRF-Token` (from the `ui_csrf`
cookie — sent on GETs too, not only mutations), and `X-IMPERSONATION-TOKEN`
when impersonating. The OpenAPI also documents `X-SESSION-ID`/
`X-IMPERSONATION-TOKEN` header params. `BroadcastApi` stays header-agnostic; the
shared interceptors (AND-011/AND-012/AND-013) own all of these. The `mintPlaybackUrl`
POST is the one mutation here and relies on the global CSRF/auth injection.

## 4. Technical Design

Production code lands in
`core-network/src/main/kotlin/com/testlogon/android/core/network/broadcast/`
(interface, DTOs, mappers, `di/`) and
`core-model/src/main/kotlin/com/testlogon/android/core/model/broadcast/`
(domain types).

### 4.1 Domain types (core-model)

> **CORRECTED.** The domain model below was realigned to the verified
> `BroadcastSessionOut` contract: `title`→`name`, no `host` object (only a
> `createdBy` string), `playbackUrl` from `cloudfront_playback_url`,
> `scheduledAt` is epoch-second, `stoppedAt` replaces the non-existent
> `endedAt`, and the status enum uses the **real** lifecycle values. `viewerCount`
> and `remindMeSet` are **not** on the session payload — they come from the
> `/viewers/count` and `/remind-me` endpoints (out of scope here; AND-279/286).

```kotlin
package com.testlogon.android.core.model.broadcast

import java.time.Instant

data class BroadcastSession(
    val id: String,
    val profileId: String,
    val name: String?,                // human title (wire field "name"; nullable)
    val description: String?,
    val status: BroadcastSessionStatus,
    val createdBy: String,            // operator sub; there is no nested host object on the wire
    val scheduledAt: Instant?,        // from epoch-second "scheduled_at"; non-null for SCHEDULED
    val startedAt: Instant?,          // from ISO "started_at"; non-null once LIVE/STOPPED
    val stoppedAt: Instant?,          // from ISO "stopped_at"; non-null once STOPPED
    val cancelledAt: Instant?,        // from ISO "cancelled_at"
    val playbackUrl: String?,         // from cloudfront_playback_url (HLS .m3u8); null until live/ready
    val thumbnailUrl: String?,        // top-level thumbnail_url
    val createdAt: Instant,
    val updatedAt: Instant,
)

// Verified lifecycle values from frontend BroadcastSessionStatus union + backend status strings.
enum class BroadcastSessionStatus {
    DRAFT, SCHEDULED, PROVISIONING, READY, LIVE, STOPPING, STOPPED, CANCELLED, ERROR, UNKNOWN
}

data class BroadcastSessionPage(
    val items: List<BroadcastSession>,
    val hasMore: Boolean,             // from BroadcastSessionListOut.has_more (not a cursor)
)

data class BroadcastScheduledPage(
    val items: List<BroadcastSession>,
    val count: Int,                   // from BroadcastScheduledListOut.count
)
```

These are the canonical types AND-279 and AND-286 consume. There is **no**
`BroadcastHost` type — the backend exposes only `created_by` (a subject string);
display-identity hydration, if needed, is a downstream concern.

### 4.2 DTOs (core-network)

> **CORRECTED against `BroadcastSessionOut` in OpenAPI + `frontend/src/api/endpoints/broadcast.ts`.**
> The earlier draft of this DTO was largely fictional. The real wire shape has
> **no nested `host` object**, **no nested `playback` object**, and **no
> `hls_url`/`scheduled_start_at`/`ended_at`/`viewer_count`/`remind_me`/`next_page`
> fields**. The verified shape is below; see §16 for the full audit.

```kotlin
package com.testlogon.android.core.network.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import java.time.Instant

@JsonClass(generateAdapter = true)
data class BroadcastSessionDto(
    val id: String,                                       // required
    @Json(name = "profile_id") val profileId: String,     // required
    val status: String,                                   // required (lifecycle, see enum below)
    @Json(name = "created_by") val createdBy: String,      // required; operator sub (no host object)
    @Json(name = "created_at") val createdAt: String,      // required; ISO-8601 string
    @Json(name = "updated_at") val updatedAt: String,      // required; ISO-8601 string
    val name: String? = null,                             // human title (NOT "title")
    val description: String? = null,
    @Json(name = "cloudfront_playback_url") val cloudfrontPlaybackUrl: String? = null, // the HLS .m3u8 URL
    @Json(name = "mediapackage_endpoint") val mediapackageEndpoint: String? = null,
    @Json(name = "ingest_url") val ingestUrl: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null, // top-level only; no playback sub-object
    @Json(name = "scheduled_at") val scheduledAt: Long? = null,     // epoch seconds (integer), NOT an ISO string
    @Json(name = "schedule_status") val scheduleStatus: String? = null,
    @Json(name = "started_at") val startedAt: String? = null,       // ISO-8601 string (parsed to Instant in mapper)
    @Json(name = "stopped_at") val stoppedAt: String? = null,       // ISO-8601 string (replaces the non-existent "ended_at")
    @Json(name = "cancelled_at") val cancelledAt: String? = null,
    @Json(name = "tip_total_cents") val tipTotalCents: Int? = null,
    @Json(name = "tip_count") val tipCount: Int? = null,
)

@JsonClass(generateAdapter = true)
data class BroadcastSessionListRespDto(           // BroadcastSessionListOut
    val items: List<BroadcastSessionDto> = emptyList(),
    @Json(name = "has_more") val hasMore: Boolean = false,   // NOT a "next_page" cursor
)

@JsonClass(generateAdapter = true)
data class BroadcastScheduledListRespDto(         // BroadcastScheduledListOut (scheduled & upcoming routes)
    val items: List<BroadcastSessionDto> = emptyList(),
    val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class BroadcastPlaybackUrlDto(               // BroadcastPlaybackUrlOut (mint endpoint)
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "playback_url") val playbackUrl: String,
    @Json(name = "expires_at") val expiresAt: Long,         // epoch seconds
)
```

`BroadcastSessionOut` is the **same shape** for the list element and the
`getSession` detail response (verified — there is no richer detail DTO; Q-5
resolved). Absent optional fields fall back to Kotlin defaults. The only ISO
timestamps are `created_at`/`updated_at`/`started_at`/`stopped_at`/`cancelled_at`
(strings → `Instant` via the shared adapter); `scheduled_at` and `expires_at`
are **epoch-second integers** and are parsed with `Instant.ofEpochSecond(...)`
in the mapper, **not** by the `InstantJsonAdapter`. There is no `host`,
`playback`, `viewer_count`, or `remind_me` on the wire — those are separate
endpoints (`/viewers/count`, `/remind-me`) owned by AND-279/AND-286.

### 4.3 The `BroadcastApi` interface

```kotlin
package com.testlogon.android.core.network.broadcast

import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

interface BroadcastApi {

    /**
     * List broadcast sessions, optionally filtered by lifecycle status.
     * Idempotent GET. The wire envelope is {items, has_more} — there is NO
     * cursor; the only paging lever is `limit`. `status` is a free string
     * matching a lifecycle value ("live", "scheduled", "stopped", ...); it is
     * optional (omit for all).
     */
    @GET("broadcast/sessions")
    suspend fun listSessions(
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
    ): BroadcastSessionListRespDto

    /** Dedicated scheduled-sessions route. Returns {items, count}. */
    @GET("broadcast/sessions/scheduled")
    suspend fun listScheduledSessions(
        @Query("limit") limit: Int? = null,
    ): BroadcastScheduledListRespDto

    /** Dedicated upcoming-sessions route. Returns {items, count}. */
    @GET("broadcast/sessions/upcoming")
    suspend fun listUpcomingSessions(
        @Query("limit") limit: Int? = null,
    ): BroadcastScheduledListRespDto

    /** Full session. Same BroadcastSessionOut shape as a list element. Idempotent GET. */
    @GET("broadcast/sessions/{sessionId}")
    suspend fun getSession(@Path("sessionId") sessionId: String): BroadcastSessionDto

    /**
     * Mint a short-lived signed playback URL for a session. POST (mutation:
     * mints/rotates a token), returns {session_id, playback_url, expires_at}.
     * Optional in this ticket — the session's own `cloudfront_playback_url`
     * suffices for most reads; AND-286 calls this when an entitlement-gated /
     * expiring URL is required.
     */
    @POST("broadcast/sessions/{sessionId}/playback-url")
    suspend fun mintPlaybackUrl(@Path("sessionId") sessionId: String): BroadcastPlaybackUrlDto
}
```

Notes (VERIFIED): the list IS a `?status=`/`?limit=` query on
`broadcast/sessions` (Q-1 resolved — `status` query confirmed), **and** the
backend additionally exposes dedicated `broadcast/sessions/scheduled` and
`broadcast/sessions/upcoming` routes (used by the web `broadcastSchedule.ts`),
so this interface declares both. There is no `?status=upcoming`/`ended` query
value — "upcoming" is a route, and the lifecycle enum has no `UPCOMING`/`ENDED`.
The remind-me toggle (`POST`/`DELETE broadcast/sessions/{id}/remind-me`,
returning `{ok, remind_at}`) is **owned by AND-279**; there is no `remind_me`
boolean on the session payload to surface. The `@POST` import must be added to
the interface.

### 4.4 Mappers

> **CORRECTED.** Mappers realigned to the real fields. ISO timestamps go through
> the shared `InstantJsonAdapter`-typed DTO fields would be possible, but since
> the verified DTO carries `started_at`/`stopped_at` as **strings**, they are
> parsed with `Instant.parse(...)` in the mapper; `scheduled_at` is an
> **epoch-second integer** parsed with `Instant.ofEpochSecond(...)`.

```kotlin
package com.testlogon.android.core.network.broadcast

import com.testlogon.android.core.model.broadcast.*
import java.time.Instant

private fun String?.parseInstantOrNull(): Instant? =
    this?.let { runCatching { Instant.parse(it) }.getOrNull() }

private fun Long?.epochSecondsToInstant(): Instant? =
    this?.let { Instant.ofEpochSecond(it) }

fun BroadcastSessionDto.toDomain(): BroadcastSession = BroadcastSession(
    id = id,
    profileId = profileId,
    name = name,
    description = description,
    status = status.toBroadcastStatus(),
    createdBy = createdBy,
    scheduledAt = scheduledAt.epochSecondsToInstant(),
    startedAt = startedAt.parseInstantOrNull(),
    stoppedAt = stoppedAt.parseInstantOrNull(),
    cancelledAt = cancelledAt.parseInstantOrNull(),
    playbackUrl = cloudfrontPlaybackUrl,
    thumbnailUrl = thumbnailUrl,
    createdAt = createdAt.parseInstantOrNull() ?: Instant.EPOCH,
    updatedAt = updatedAt.parseInstantOrNull() ?: Instant.EPOCH,
)

fun BroadcastSessionListRespDto.toDomain(): BroadcastSessionPage =
    BroadcastSessionPage(items = items.map { it.toDomain() }, hasMore = hasMore)

fun BroadcastScheduledListRespDto.toDomain(): BroadcastScheduledPage =
    BroadcastScheduledPage(items = items.map { it.toDomain() }, count = count)

private fun String?.toBroadcastStatus(): BroadcastSessionStatus =
    when (this?.lowercase()) {
        "draft" -> BroadcastSessionStatus.DRAFT
        "scheduled" -> BroadcastSessionStatus.SCHEDULED
        "provisioning" -> BroadcastSessionStatus.PROVISIONING
        "ready" -> BroadcastSessionStatus.READY
        "live" -> BroadcastSessionStatus.LIVE
        "stopping" -> BroadcastSessionStatus.STOPPING
        "stopped" -> BroadcastSessionStatus.STOPPED
        "cancelled", "canceled" -> BroadcastSessionStatus.CANCELLED
        "error" -> BroadcastSessionStatus.ERROR
        else -> BroadcastSessionStatus.UNKNOWN
    }
```

Mappers are pure, side-effect-free, and individually unit-tested. The
status-extension helper centralizes unknown-value tolerance and absorbs the
US/UK spellings of "cancelled". The status values are the verified union from
`frontend/src/api/endpoints/broadcast.ts` (`BroadcastSessionStatus`).

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

> **CORRECTED** against `BroadcastSessionListOut`/`BroadcastSessionOut`/
> `BroadcastScheduledListOut`/`BroadcastPlaybackUrlOut` in `openapi.pretty.json`
> and `frontend/src/api/endpoints/broadcast.ts` + `broadcastSchedule.ts`. The
> envelope is `{items, has_more}`; the session has `name`/`created_by`/
> `cloudfront_playback_url`/`scheduled_at` (epoch int), not the previously
> invented `title`/`host`/`playback.hls_url`/`scheduled_start_at`.

### GET `broadcast/sessions?status=live&limit=50` → `BroadcastSessionListOut`
Response `200` — a live session carries its HLS URL at top-level
`cloudfront_playback_url`:
```json
{
  "items": [
    {
      "id": "bcs_01HX1",
      "profile_id": "prof_9",
      "status": "live",
      "name": "Friday Night Live",
      "description": "Weekly Q&A",
      "created_by": "usr_42",
      "created_at": "2026-06-05T22:00:00Z",
      "updated_at": "2026-06-05T23:00:05Z",
      "started_at": "2026-06-05T23:00:00Z",
      "cloudfront_playback_url": "https://stream.testlogon.dev/bcs_01HX1/index.m3u8",
      "mediapackage_endpoint": "https://mp.testlogon.dev/bcs_01HX1",
      "thumbnail_url": "https://cdn.testlogon.dev/t/bcs_01HX1.jpg",
      "tip_total_cents": 12500,
      "tip_count": 37
    }
  ],
  "has_more": false
}
```

### GET `broadcast/sessions/scheduled?limit=50` → `BroadcastScheduledListOut`
Response `200` — `{items, count}`; a scheduled session carries `scheduled_at`
(epoch seconds) and `schedule_status`, and no playback URL yet:
```json
{
  "items": [
    {
      "id": "bcs_01HX2",
      "profile_id": "prof_9",
      "status": "scheduled",
      "name": "Album listening party",
      "created_by": "usr_42",
      "created_at": "2026-06-01T10:00:00Z",
      "updated_at": "2026-06-01T10:00:00Z",
      "scheduled_at": 1749319200,
      "schedule_status": "scheduled",
      "thumbnail_url": "https://cdn.testlogon.dev/t/bcs_01HX2.jpg"
    }
  ],
  "count": 1
}
```

### GET `broadcast/sessions/upcoming?limit=50` → `BroadcastScheduledListOut`
Response `200` — identical `{items, count}` shape; the backend, not a
`status` value, decides what is "upcoming". Used by AND-279 as a separate
section from `scheduled`.

### GET `broadcast/sessions/{sessionId}` → `BroadcastSessionOut`
Response `200` — a single `BroadcastSessionOut`, the **same shape** as a list
element (verified: no richer detail object). `422` on a malformed path param;
non-existence returns the backend's error envelope. AND-286 reads
`cloudfront_playback_url` from here (or mints a fresh one — below) to feed
ExoPlayer (AND-167).

### POST `broadcast/sessions/{sessionId}/playback-url` → `BroadcastPlaybackUrlOut`
Response `200` — mints a short-lived signed playback URL:
```json
{ "session_id": "bcs_01HX1", "playback_url": "https://stream.testlogon.dev/bcs_01HX1/index.m3u8?token=…", "expires_at": 1749322800 }
```

**Error envelope (all endpoints):** FastAPI `{ "detail": … }` where `detail` is
`string | [{msg,type,loc}] | {code,...}` (e.g. the geo-block case uses
`{code:"geo_blocked", message, ...}`; authorization failures use
`{code:"role_required…"}` — see `frontend/src/api/client.ts:normalizeErrorDetail`/
`mapAuthorizationError`). Every broadcast endpoint documents `422:HTTPValidationError`
for bad params/body. Mapping `detail` to a typed `ApiError` is owned by
**AND-015**; this ticket lets non-2xx surface as `retrofit2.HttpException`.

## 6. Data & State Management

`BroadcastApi` is **stateless** — a singleton interface proxy with no fields.
This ticket holds no `StateFlow`/`UiState`, no Room, no DataStore.

- **Session state** (auth) lives in cookies (plus the Bearer token / session
  headers — see FR-11), persisted/attached by AND-011/AND-012; `BroadcastApi`
  never reads/writes them. **[CORRECTED]** The web client attaches
  `X-CSRF-Token` (from `ui_csrf`) on **every** request including GETs, so the
  Android interceptor (AND-012) should do the same; CSRF is not GET-exempt here.
  The one mutation in this ticket is the `mintPlaybackUrl` POST.
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
- **Paging:** **[CORRECTED]** `listSessions` returns a
  `BroadcastSessionListRespDto` / `BroadcastSessionPage` with a **`has_more`
  boolean** (not an opaque cursor); the only paging lever is the `limit` query.
  The scheduled/upcoming routes return `{items, count}`. The actual Paging 3
  `PagingSource`/`RemoteMediator` (if any) is owned by AND-279. This ticket only
  exposes the `has_more`/`count`-bearing calls.
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
  converter. **[CORRECTED]** Mappers are written defensively so recoverable
  shape variance (absent `cloudfront_playback_url`, unknown `status`, absent
  optional `name`/`description`/timestamps) never throws. A genuinely malformed
  payload — an item missing a **required** field (`id`, `profile_id`, `status`,
  `created_by`, `created_at`, `updated_at`, all non-null per `BroadcastSessionOut`)
  — fails the converter deterministically, surfaced to callers for
  AND-015/AND-018 handling.
- **Live-but-no-URL:** **[CORRECTED]** a session reported `status:"live"` with no
  `cloudfront_playback_url` maps to `status = LIVE, playbackUrl = null`; AND-286
  must treat a null `playbackUrl` on a LIVE session as a "stream unavailable"
  state (or mint via `playback-url`) rather than crashing (R-2). This ticket
  guarantees the mapper does not fabricate a URL.
- This ticket maps **no** errors to user-facing types itself — that is AND-015
  (`ApiError`) / AND-018 (`ApiResult`).

## 8. Security & Privacy

- **Authenticated surface:** broadcast endpoints require the cookie session
  established by the auth flow (AND-027 family). `BroadcastApi` adds no manual
  `Cookie`/`Authorization` headers; identity is carried implicitly by the jar.
  Whether some live listings are public/unauthenticated is reconciled against
  `/openapi.json` (Q-4); the transport is identical either way.
- **HLS URL sensitivity:** **[CORRECTED field name]** `cloudfront_playback_url`
  (and the minted `playback_url` with its `expires_at`) may embed a short-lived
  signed token or be entitlement-gated server-side. This ticket transports it
  verbatim and **must not log it** (it can grant stream access). Any
  expiry/refresh of a signed playback URL is a playback-feature concern
  (AND-167/AND-286), not here.
- **CSRF:** **[CORRECTED]** the web client sends `X-CSRF-Token` on all requests
  (GET and POST). This ticket's `mintPlaybackUrl` is a POST and depends on it;
  the global AND-012 interceptor remains the owner for CSRF on every verb.
- **Cleartext on dev:** broadcast payloads (titles, host handles, playback URLs)
  ride plaintext HTTP on the dev host — a known, dev-only risk permitted by the
  scoped cleartext config (AND-006); `staging`/`prod` are HTTPS-only. Note the
  `hls_url` in the sample points at an HTTPS CDN even on dev.
- **No payload/URL logging:** this ticket adds no logging; the shared logging
  interceptor (AND-009) is debug-only and redacted. A code-review check confirms
  no `cloudfront_playback_url`/minted `playback_url` or broadcast payload body
  reaches logcat in any build.
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
  payload bodies — and especially `cloudfront_playback_url`/`playback_url` — must be redacted (Section 8). No
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

> **CORRECTED.** The T-cases below were written against the fictional shape;
> they are realigned here to the verified contract: assert `name`/`created_by`/
> `cloudfront_playback_url`/`scheduled_at`(epoch)/`has_more`, the dedicated
> `scheduled`/`upcoming` routes, and the real status enum. The host-fallback
> (T-7) and DVR/`playback.thumbnail` precedence (T-8) cases are **dropped** (no
> host or playback sub-object exists); a host/playback-precedence test would be
> testing a shape the backend never sends. The authoritative, renumbered test
> matrix is **§17**; the T-list here is retained for continuity.

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
    assertEquals("https://stream.testlogon.dev/bcs_01HX1/index.m3u8", s.playbackUrl) // from cloudfront_playback_url
    assertEquals("Friday Night Live", s.name)
    assertFalse(resp.hasMore)
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

- **AC-1 (backlog).** **[CORRECTED]** Broadcast payloads map (tested): every
  broadcast JSON shape in Section 5 — the live session (with
  `cloudfront_playback_url`), the scheduled session (with epoch `scheduled_at`),
  the upcoming-route response, the single-session `getSession`, and the
  `mintPlaybackUrl` response — decodes via the production Moshi config and maps
  losslessly into the `core-model` domain types, proven by mapper unit tests
  (T-1..T-3, T-5..T-6, T-10).
- **AC-2.** `BroadcastApi` declares the broadcast read operations
  (`listSessions(status, page)`, `getSession(sessionId)`) and the module
  compiles against the new DTOs and `core-model` types.
- **AC-3.** Each endpoint is callable and its **verb + resolved path + query**
  match Section 5, asserted with MockWebServer (T-1, T-4, T-9).
- **AC-4.** **[CORRECTED]** The `status` and `limit` queries are serialized on
  `broadcast/sessions`, the dedicated `scheduled`/`upcoming` routes are callable,
  and the `{items, has_more}` / `{items, count}` envelopes decode and map through
  `toDomain()` (T-1, T-2, T-9).
- **AC-5.** **[CORRECTED]** The top-level `cloudfront_playback_url` is carried
  through to `BroadcastSession.playbackUrl` and is `null` when absent
  (scheduled/draft); the `mintPlaybackUrl` POST decodes `{session_id,
  playback_url, expires_at}` (T-1, T-2, T-10).
- **AC-6.** **[CORRECTED]** ISO `created_at`/`updated_at`/`started_at`/
  `stopped_at`/`cancelled_at` and epoch-second `scheduled_at` parse to `Instant`;
  `scheduledAt` is non-null for scheduled sessions (T-2, T-3).
- **AC-7.** **[CORRECTED]** Unknown/synonym status strings and missing optional
  fields map to `UNKNOWN`/defaults (no host fallback — there is no host on the
  wire) without throwing (T-5, T-6).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. "OpenAPI"
= `reference/openapi.index.txt` / `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend pointers are under `reference/src/`.

1. **`GET /broadcast/sessions` exists, idempotent list.** VERIFIED. OpenAPI
   `GET /broadcast/sessions` (op `list_sessions_route...`, resp
   `200:BroadcastSessionListOut`); `src/api/endpoints/broadcast.ts: listSessions`.
2. **List params are `status` + `limit` (NOT a `page` cursor).** CORRECTED
   (spec said `page` cursor). OpenAPI `GET /broadcast/sessions | params=status,limit`;
   `src/api/endpoints/broadcast.ts: listSessions` passes only `{status}`;
   `src/pages/broadcast/BroadcastPage.tsx:137` calls `listSessions({status})`.
3. **List envelope is `{items, has_more}` (NOT `{items, next_page}`).** CORRECTED.
   OpenAPI schema `BroadcastSessionListOut` = `items[] + has_more:boolean`;
   `src/api/endpoints/broadcast.ts: SessionListResponse`.
4. **`status` query value is a free lifecycle string, with no `upcoming`/`ended`
   value.** CORRECTED (spec listed on-wire values `live|scheduled|upcoming`).
   `src/api/endpoints/broadcast.ts: BroadcastSessionStatus` =
   `draft|scheduled|provisioning|ready|live|stopping|stopped|cancelled|error`.
5. **Scheduled & upcoming are DEDICATED routes returning `{items, count}`.**
   CORRECTED (spec defaulted to a `?status=` query and only conditionally added
   routes). OpenAPI `GET /broadcast/sessions/scheduled` and
   `GET /broadcast/sessions/upcoming`, both `200:BroadcastScheduledListOut`
   (`items[] + count:int`), `params=limit`; `src/api/endpoints/broadcastSchedule.ts:
   listScheduledSessions / listUpcomingSessions`.
6. **`GET /broadcast/sessions/{session_id}` returns the SAME `BroadcastSessionOut`
   shape (no richer detail object).** VERIFIED (resolves Q-5). OpenAPI
   `GET /broadcast/sessions/{session_id} | resp=200:BroadcastSessionOut`;
   `src/api/endpoints/broadcast.ts: getSession` returns `BroadcastSession`.
7. **Session human title field is `name`, NOT `title`.** CORRECTED. OpenAPI
   `BroadcastSessionOut.name` (nullable); `src/api/endpoints/broadcast.ts:
   BroadcastSession.name`.
8. **There is NO nested `host` object / `BroadcastHost`; only `created_by`
   (string).** CORRECTED (spec invented `host`/`BroadcastHostDto`/`BroadcastHost`
   with username/display_name/avatar_url). OpenAPI `BroadcastSessionOut` has
   `created_by` (required string) and no host; `src/api/endpoints/broadcast.ts:
   BroadcastSession` has no host field.
9. **HLS playback URL is top-level `cloudfront_playback_url`, NOT a `playback`
   sub-object with `hls_url`/`dvr`.** CORRECTED. OpenAPI
   `BroadcastSessionOut.cloudfront_playback_url`; `src/api/endpoints/broadcast.ts:
   BroadcastSession.cloudfront_playback_url`. No `playback`/`hls_url`/`dvr` field
   exists anywhere in the schema.
10. **A separate mint endpoint exists: `POST /broadcast/sessions/{id}/playback-url`
    → `{session_id, playback_url, expires_at}`.** VERIFIED. OpenAPI
    `POST /broadcast/sessions/{session_id}/playback-url |
    resp=200:BroadcastPlaybackUrlOut`; schema `BroadcastPlaybackUrlOut`;
    `src/api/endpoints/broadcast.ts: mintPlaybackUrl`.
11. **`scheduled_at` is an epoch-second INTEGER, NOT an ISO `scheduled_start_at`.**
    CORRECTED. OpenAPI `BroadcastSessionOut.scheduled_at: integer|null`;
    `src/api/endpoints/broadcast.ts: scheduled_at?: number|null`;
    `src/api/endpoints/broadcastSchedule.ts: ScheduleSessionReq.scheduled_at: number`.
12. **Timestamps `started_at`/`stopped_at`/`cancelled_at`/`created_at`/`updated_at`
    are ISO strings; there is NO `ended_at`.** CORRECTED (spec used `ended_at`).
    OpenAPI `BroadcastSessionOut` — these are `type:string`; `stopped_at` is the
    go-offline field; `src/api/endpoints/broadcast.ts` mirrors the names.
13. **No `viewer_count` on the session payload; viewer count is a separate GET.**
    CORRECTED (spec had `viewer_count` on the session). OpenAPI
    `GET /broadcast/sessions/{session_id}/viewers/count | resp=200:ViewerCountOut`;
    `src/api/endpoints/broadcast.ts: getViewerCount / ViewerCountResponse`.
14. **No `remind_me` boolean on the session; reminders are separate POST/DELETE.**
    CORRECTED. OpenAPI `POST` & `DELETE /broadcast/sessions/{session_id}/remind-me`;
    `src/api/endpoints/broadcastSchedule.ts: registerReminder / cancelReminder`
    (`ReminderResponse = {ok, remind_at}`). No `remind_me` field in
    `BroadcastSessionOut`.
15. **Status enum.** CORRECTED to `DRAFT, SCHEDULED, PROVISIONING, READY, LIVE,
    STOPPING, STOPPED, CANCELLED, ERROR (+UNKNOWN)`. Source:
    `src/api/endpoints/broadcast.ts: BroadcastSessionStatus`; backend
    `BroadcastSessionOut.status: string` (free string).
16. **Required (non-null) session fields:** `id, profile_id, status, created_by,
    created_at, updated_at`. VERIFIED. OpenAPI `BroadcastSessionOut.required`.
17. **Auth: cookie session + `Authorization: Bearer` + `X-CSRF-Token` on EVERY
    request (incl. GETs) + `X-IMPERSONATION-TOKEN` when impersonating.** CORRECTED
    (spec said cookie-only and CSRF irrelevant for GETs). `src/api/client.ts`
    (`fetch(..., {credentials:"include"})`, sets `Authorization` from auth store,
    sets `X-CSRF-Token` from `ui_csrf` cookie unconditionally, sets
    `X-IMPERSONATION-TOKEN`). OpenAPI documents `X-SESSION-ID`/`X-IMPERSONATION-TOKEN`
    header params on every broadcast op.
18. **401 handling: refresh once via `POST /ui/session/refresh`, then retry; a
    second 401 logs out.** VERIFIED (consistent with AND-013 delegation).
    `src/api/client.ts: refreshSession` + the 401 branch.
19. **Error envelope is FastAPI `{detail}` (string | array of `{msg,type,loc}` |
    `{code,...}`); all ops document `422:HTTPValidationError`; 403 may be
    `{code:"geo_blocked"}` or `{code:"role_required..."}`.** VERIFIED. OpenAPI per-op
    `422:HTTPValidationError`; `src/api/client.ts: normalizeErrorDetail` /
    `mapAuthorizationError` (geo_blocked + role_required codes).
20. **`BroadcastApi` reuses the shared Retrofit/OkHttp; Hilt `@Provides @Singleton`.**
    UNVERIFIED-ASSUMPTION (Android-side design; no external contract). Consistent
    with AND-010 module conventions cited in §2; framework ref: Retrofit
    `create()` + Dagger Hilt `@Provides`/`@Singleton`
    (developer.android.com/training/dependency-injection/hilt-android — framework ref).
21. **Moshi codegen via KSP, `coreLibraryDesugaring` for `java.time.Instant` at
    minSdk 24.** UNVERIFIED-ASSUMPTION (build config; not in the API sources).
    framework ref: developer.android.com/studio/write/java8-support (desugaring);
    github.com/square/moshi (codegen). Pins per §2.
22. **Dev base URL `http://18.222.237.167:8000/` (cleartext).** UNVERIFIED from
    the provided sources (the web client reads `VITE_API_BASE_URL` from env,
    `src/api/client.ts:7`; the IP is not in-repo). Carried from upstream AND-006.

### Corrections made

- **DTO shape (§4.2)** rewritten to the verified `BroadcastSessionOut`: removed
  invented `host`/`playback`/`hls_url`/`dvr`/`viewer_count`/`remind_me`/`next_page`;
  added `name`, `profile_id`, `created_by`, `cloudfront_playback_url`,
  `mediapackage_endpoint`, `scheduled_at`(epoch), `schedule_status`,
  `stopped_at`, `cancelled_at`; envelopes `{items, has_more}` and `{items, count}`;
  added `BroadcastPlaybackUrlDto`. (Audit #3,7–14.)
- **Domain model (§4.1)** realigned: `title`→`name`, removed `BroadcastHost`,
  `endedAt`→`stoppedAt`, `next_page`→`hasMore`, added `BroadcastScheduledPage`,
  corrected status enum. (Audit #4,7,8,12,15.)
- **Interface (§4.3)** corrected: `page`→`limit`, `status` made optional, added
  dedicated `listScheduledSessions`/`listUpcomingSessions` and the
  `mintPlaybackUrl` POST (+ `@POST` import). (Audit #2,5,10.)
- **Mappers (§4.4)** rewritten for the real fields; epoch-vs-ISO timestamp
  parsing split; status `when` uses the real enum. (Audit #11,12,15.)
- **FR-4..FR-9, FR-11; §5 samples; §6 paging; §7 deser/live-no-URL; §8 CSRF/HLS;
  §10 logging; AC-1,AC-4..AC-7** all corrected inline (marked `[CORRECTED]`).
  (Audit #2,3,4,5,9,11,12,13,14,17,19.)
- **§5 error envelope** expanded to the real `detail` union + 422 + geo/role
  codes. (Audit #19.)

### Open assumptions

- **Android transport/DI/build details (Audit #20, #21):** unverifiable from the
  API/OpenAPI/frontend sources — they are client-side framework choices. Backed
  by Android framework docs (Hilt, desugaring, Moshi) and the §2 stack pins, not
  by a backend contract.
- **Dev base URL / cleartext (Audit #22):** the concrete IP is not present in the
  provided reference (the web app uses an env var). Treated as inherited from
  AND-006; flag for confirmation before coding the `BuildConfig`.
- **`status` filter accepted values at runtime:** the backend types `status` as a
  free string; which lifecycle values it actually filters on is not constrained
  by the schema. The web app passes through whatever the UI selects
  (`BroadcastPage.tsx:137`). Assumed to accept any lifecycle value; verify the
  empty/`all` case server-side.
- **Whether any broadcast list is public/unauthenticated (Q-4):** every
  `/broadcast/sessions*` op carries auth header params in OpenAPI, so all are
  assumed authenticated; the public surface is limited to
  `/broadcast/public/clips/*`. Not a blocker for transport.

## 17. Test Plan

Test targets: **JVM** = local JVM unit/Robolectric (no device); **emulator** =
headless AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15
5G (SM-A156U, API 34, arm64-v8a). This ticket is a headless transport +
serialization layer, so the bulk runs on **JVM** (MockWebServer). Two cases note
where a real device adds value (ABI/desugaring + real-network playback URL),
though they are not strictly required for this ticket's acceptance.

All `Traces` link to §14 Acceptance Criteria.

- **TC-AND-278-01 — listSessions happy path (live).** Type: contract/MockWebServer.
  Target: JVM. Preconditions: MockWebServer enqueues the §5 live
  `BroadcastSessionListOut` body (200). Steps: call
  `listSessions(status="live", limit=50)`; capture the request. Expected:
  method `GET`, path `/broadcast/sessions`, query `status=live` & `limit=50`;
  decoded `items[0]` maps to `status=LIVE`, `name="Friday Night Live"`,
  `playbackUrl="https://stream.testlogon.dev/bcs_01HX1/index.m3u8"`,
  `hasMore=false`. Traces: AC-1, AC-3, AC-4, AC-5.

- **TC-AND-278-02 — scheduled route maps epoch `scheduled_at`.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue the §5
  `BroadcastScheduledListOut` (`{items, count}`) with `scheduled_at:1749319200`.
  Steps: call `listScheduledSessions(limit=50)`. Expected: `GET
  /broadcast/sessions/scheduled?limit=50`; `status=SCHEDULED`,
  `scheduledAt == Instant.ofEpochSecond(1749319200)`, `playbackUrl == null`,
  `count == 1`. Traces: AC-1, AC-4, AC-6.

- **TC-AND-278-03 — upcoming route.** Type: contract/MockWebServer. Target: JVM.
  Preconditions: enqueue a `BroadcastScheduledListOut`. Steps: call
  `listUpcomingSessions(limit=50)`. Expected: `GET
  /broadcast/sessions/upcoming?limit=50`; envelope decodes to
  `BroadcastScheduledPage` with the right `count`; the route is distinct from
  `scheduled` (separate path assertion). Traces: AC-3, AC-4.

- **TC-AND-278-04 — getSession path interpolation + full decode.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue a single
  `BroadcastSessionOut` (live, with `cloudfront_playback_url`, ISO `started_at`).
  Steps: call `getSession("bcs_01HX1")`. Expected: `GET
  /broadcast/sessions/bcs_01HX1`; decoded domain has `playbackUrl` set,
  `startedAt == Instant.parse("2026-06-05T23:00:00Z")`, `createdAt`/`updatedAt`
  parsed. Traces: AC-1, AC-3, AC-5, AC-6.

- **TC-AND-278-05 — mintPlaybackUrl POST.** Type: contract/MockWebServer. Target:
  JVM. Preconditions: enqueue `BroadcastPlaybackUrlOut` (200). Steps: call
  `mintPlaybackUrl("bcs_01HX1")`. Expected: method `POST`, path
  `/broadcast/sessions/bcs_01HX1/playback-url`; decoded `sessionId`,
  `playbackUrl`, `expiresAt == Instant.ofEpochSecond(...)` (epoch int). Traces:
  AC-1, AC-3, AC-5.

- **TC-AND-278-06 — status enum tolerance & unknown.** Type: unit (pure mapper).
  Target: JVM. Preconditions: none. Steps: map DTOs with
  `status` ∈ {`draft`,`provisioning`,`ready`,`stopping`,`stopped`,`error`,
  `Live` (mixed case),`canceled`,`weird`, null}. Expected: each maps to its enum
  value (case-insensitive; `canceled`→`CANCELLED`), `weird`/null→`UNKNOWN`; no
  throw. Traces: AC-7.

- **TC-AND-278-07 — missing-optionals tolerance.** Type: unit (pure mapper).
  Target: JVM. Preconditions: a DTO with only the 6 required fields (`id`,
  `profile_id`, `status`, `created_by`, `created_at`, `updated_at`). Steps: call
  `toDomain()`. Expected: `name==null`, `description==null`, `playbackUrl==null`,
  `scheduledAt==null`, `startedAt==null`, `stoppedAt==null`; no throw. Traces:
  AC-1, AC-7.

- **TC-AND-278-08 — required-field-missing fails deterministically.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue an item missing
  `profile_id` (a required, non-null field). Steps: call `getSession(...)`.
  Expected: the Moshi converter throws `JsonDataException` (not a silent
  null/garbage object); the throwable propagates to the caller. Traces: AC-1.

- **TC-AND-278-09 — paging signal passthrough.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: enqueue a list with `has_more:true`. Steps: call
  `listSessions(status="live", limit=2)`; assert request has
  `?status=live&limit=2`; map envelope. Expected: `BroadcastSessionPage.hasMore
  == true`; no cursor field anywhere. Traces: AC-3, AC-4.

- **TC-AND-278-10 — live-without-URL safety.** Type: unit (pure mapper). Target:
  JVM. Preconditions: a `status:"live"` DTO with `cloudfront_playback_url`
  absent. Steps: `toDomain()`. Expected: `status==LIVE`, `playbackUrl==null` (no
  fabricated URL), no throw. Traces: AC-5, AC-7.

- **TC-AND-278-11 — 401 surfaces as HttpException (not swallowed).** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue `401` with a
  FastAPI `{"detail":"Authentication required"}` body. Steps: call
  `listSessions(status="live")`. Expected: throws `retrofit2.HttpException` with
  `code()==401`; raw error body available for AND-013/AND-015. Traces: AC-8.

- **TC-AND-278-12 — 422 validation error body preserved.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue `422` with an
  `HTTPValidationError` body (`{"detail":[{"loc":["query","limit"],"msg":"…",
  "type":"…"}]}`). Steps: call `listSessions(limit=...)`. Expected:
  `HttpException` with `code()==422`; the array-form `detail` is intact in
  `errorBody()` for AND-015 to normalize. Traces: AC-8.

- **TC-AND-278-13 — Hilt provides a singleton on the shared Retrofit.** Type:
  instrumented (`@HiltAndroidTest`). Target: emulator (`test35`).
  Preconditions: Hilt test graph with the shared `Retrofit` bound. Steps: inject
  `BroadcastApi` twice. Expected: non-null; the same instance both times; no new
  `OkHttpClient`/`Retrofit` constructed; no per-method cookie/CSRF/auth headers
  declared on the interface. Traces: AC-9.

- **TC-AND-278-14 — clean build incl. KSP adapters + ABI/desugaring sanity.**
  Type: instrumented/e2e. Target: **device** (SM-A156U, arm64-v8a, API 34) —
  must run on the physical device to exercise the arm64 ABI and API-34
  `Instant`/`java.time` desugaring path (the emulator is x86_64/API 35). Steps:
  assemble `:core-network`, install the instrumented test APK, run a smoke test
  that decodes the §5 live payload and asserts `scheduledAt`/`startedAt` parse to
  the correct `Instant`. Expected: KSP-generated Moshi adapters present (build
  fails if missing); decode + epoch/ISO parsing correct on arm64/API 34. Traces:
  AC-1, AC-6, AC-10.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (payloads map) | TC-01, TC-02, TC-04, TC-05, TC-07, TC-08, TC-14 |
| AC-2 (interface compiles vs DTOs) | Compile-time; exercised transitively by TC-01..TC-05, TC-13 |
| AC-3 (verb+path+query) | TC-01, TC-03, TC-04, TC-05, TC-09 |
| AC-4 (status/limit + `{items,has_more}`/`{items,count}`) | TC-01, TC-02, TC-03, TC-09 |
| AC-5 (`cloudfront_playback_url`→`playbackUrl` + mint) | TC-01, TC-04, TC-05, TC-10 |
| AC-6 (ISO + epoch timestamps → `Instant`) | TC-02, TC-04, TC-14 |
| AC-7 (unknown status / missing optionals tolerated) | TC-06, TC-07, TC-10 |
| AC-8 (non-2xx → HttpException, not swallowed) | TC-11, TC-12 |
| AC-9 (Hilt singleton on shared Retrofit) | TC-13 |
| AC-10 (clean CI build, KSP adapters) | TC-14 (+ all JVM cases in CI) |
</content>
</invoke>
