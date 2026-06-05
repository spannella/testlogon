---
id: AND-270
title: Calendar API + DTOs
milestone: M6
epic: E37
priority: P0
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-138]
---

# AND-270 — Calendar API + DTOs

## 1. Overview & Goal

This ticket defines the typed HTTP seam for the TestLogon **calendar** domain on
Android: the Retrofit service interface `CalendarApi`, the Moshi DTOs it
(de)serializes (events, recurrence, calendars, RSVP), and the DTO→domain mappers
that produce the canonical `core-model` calendar types consumed by every
downstream calendar feature (calendar list/agenda screens, event detail, and the
calendar-message renderer AND-138).

Scope, verbatim from the backlog: *`calendar.ts` endpoints/DTOs (events,
recurrence).* This is the Kotlin port of the web reference API layer file
`frontend/src/api/endpoints/calendar.ts` plus the calendar slice of
`frontend/src/api/types.ts`. The single acceptance criterion is that **calendar
payloads map (tested)** — i.e. every endpoint is callable with verb/path/body
matching the backend contract, and every calendar JSON shape (including recurring
events and RSVP) decodes losslessly into the domain model, proven by
`MockWebServer` and pure-mapper unit tests.

This is a **transport + serialization-definition** ticket. It owns:
the `CalendarApi` interface (`@HTTP`/`@Headers`/`@Body`/`@Query`/`@Path`
annotations), the calendar DTOs with Moshi codegen adapters, the recurrence
(RRULE) representation, the `CalendarMappers.kt` DTO→domain functions, and the
Hilt provider that constructs the service from the shared Retrofit.

It deliberately does **not** own: the persistent cookie jar (AND-011), the CSRF
interceptor (AND-012), the 401-refresh `Authenticator` (AND-013), `ApiResult`
wrapping (AND-018), error `detail` mapping (AND-015), Room caching of calendar
data, any repository, ViewModel, navigation, or UI. Those attach to the shared
`OkHttpClient`/`Retrofit` or live in higher layers (`core-data`, `feature-*`) and
take effect for `CalendarApi` calls without changes here.

The deliverable: a compiling `CalendarApi`, its DTOs + codegen adapters, the
mapper functions, the Hilt provider, and a test suite asserting each endpoint's
HTTP method, resolved path, query/body shape, decoded response, and exhaustive
DTO→domain mapping (including recurrence and missing/unknown fields).

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Production code lands in modules **`core-network`** (the
  `CalendarApi` interface, DTOs, mappers, Hilt provider) under package
  `com.testlogon.android.core.network.calendar`, with the canonical domain types
  in **`core-model`** under `com.testlogon.android.core.model.calendar`.
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP, no reflection fallback), Hilt
  (KSP), Coroutines, JDK 17, minSdk 24 / compile/target 35, AGP 8.7.3, Gradle 8.9.
  `java.time` (`Instant`, `LocalDate`, `ZoneId`) is available via
  `coreLibraryDesugaringEnabled = true` (AND-001/AND-002).
- **Module layering:** `app -> feature-* -> core-*`. `CalendarApi`/DTOs/mappers
  live in `core-network` + `core-model`, are consumed by `core-data` repositories,
  and ultimately by the calendar features. No `feature-*`/`app` symbols leak into
  `core-network`/`core-model`.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** establishes the
  cookie-based session that authenticates every calendar call. `CalendarApi`
  cannot return real data until a session exists; it reuses the same shared
  `Retrofit`/`OkHttpClient`, cookie jar (AND-011), CSRF interceptor (AND-012), and
  401-refresh authenticator (AND-013) that AND-027 wired up. The dependency is on
  the *session machinery being in place*, not on AuthApi types.
- **Transitive upstream:** AND-026 (Moshi/DTO patterns + shared `InstantJsonAdapter`
  if already defined), AND-010 (shared Retrofit/Moshi), AND-009 (shared
  `OkHttpClient` + ~20s timeouts + redacting logger), AND-016 (bounded backoff for
  idempotent GETs), AND-006 (`BuildConfig.API_BASE_URL`). Dev base URL resolves to
  `http://18.222.237.167:8000/` (plaintext HTTP, unreliable dev host).
- **Web reference (authoritative for shapes):**
  `frontend/src/api/endpoints/calendar.ts` (endpoints) and
  `frontend/src/api/types.ts` (`CalendarEvent`, `Calendar`, `Recurrence`/RRULE,
  `RsvpStatus`, `EventVisibility`). OpenAPI at `/openapi.json` is the final
  authority; any deviation in this spec is reconciled against it before merge.
- **Sibling consumer — AND-138 (calendar message cells):** already defines
  provisional `CalendarEventPayload`/`CalendarSharePayload` locally and flags that
  the **M6 calendar domain (this epic, AND-037 family / AND-270) owns the canonical
  types**. This ticket supplies those canonical `core-model` types; AND-138 migrates
  to them. Field names here MUST stay compatible with AND-138's payloads.

## 3. Functional Requirements

FR-1. Declare a single Retrofit interface `CalendarApi` covering the calendar
operations exposed by `calendar.ts`: list calendars, list events in a range, get
a single event, create an event, update an event, delete an event, and set the
viewer's RSVP. (Exact set reconciled against `/openapi.json`; Section 5 is the
working contract.)

FR-2. Each method's HTTP verb and relative path match the backend contract.
Paths are declared **without** a leading slash (AND-010 convention) so they append
to the normalized base URL `http://18.222.237.167:8000/`.

FR-3. All methods are `suspend` and return typed DTO bodies (Retrofit native
coroutine support). A method with no meaningful body returns `Unit`.

FR-4. The range-list endpoint uses typed `@Query` params (`from`, `to`,
`calendar_id?`, `page?`) — RFC-3339 / ISO-8601 strings on the wire. Mutations use
`@Body` request DTOs; single-resource ops use `@Path`. No raw `Map`/`JsonObject`.

FR-5. Define Moshi `@JsonClass(generateAdapter = true)` DTOs for every calendar
shape: `CalendarDto`, `CalendarEventDto`, `RecurrenceDto`, `EventRangeRespDto`
(paged), `RsvpReqDto`, plus request DTOs `EventCreateReqDto`/`EventUpdateReqDto`.
Wire fields are snake_case; Kotlin properties are camelCase via `@Json(name=...)`
only where codegen cannot infer.

FR-6. **Recurrence MUST be modeled losslessly.** A recurring event carries an
RRULE-style recurrence. The DTO preserves the raw `rrule` string verbatim and any
structured fields the backend sends (`freq`, `interval`, `until`, `count`,
`byday`, `exdates[]`). The mapper produces a domain `Recurrence` that retains the
raw RRULE (so the client never silently drops recurrence) plus parsed convenience
fields where present. No client-side RRULE *expansion* is implemented here (that
is a downstream feature concern); this ticket only transports/maps it.

FR-7. Provide pure DTO→domain mappers in `CalendarMappers.kt`:
`CalendarEventDto.toDomain(): CalendarEvent`, `CalendarDto.toDomain(): Calendar`,
`RecurrenceDto.toDomain(): Recurrence`, and the inverse request mappers for
create/update. Mappers MUST map unknown enum strings to `UNKNOWN`/`PENDING`
(never throw), and tolerate absent optional fields via Kotlin defaults.

FR-8. Timestamps are parsed to `java.time.Instant` via the shared
`InstantJsonAdapter`; all-day events expose `allDay = true` and a `LocalDate`
start/end so callers avoid off-by-one across DST. The event's IANA `timezone` (if
present) is preserved on the domain model.

FR-9. A Hilt `@Provides @Singleton fun provideCalendarApi(retrofit: Retrofit):
CalendarApi` constructs the service from the shared Retrofit (AND-010). No new
Retrofit/OkHttp instance is created. The calendar Moshi adapters are codegen
(KSP); only the shared `InstantJsonAdapter` (and any enum fallback adapter) is
registered explicitly on the shared Moshi if not already present.

FR-10. CSRF (`X-CSRF-Token`) and cookies are **not** declared per-method; they are
injected globally (AND-012/AND-011). `CalendarApi` stays header-agnostic.

## 4. Technical Design

Production code lands in
`core-network/src/main/kotlin/com/testlogon/android/core/network/calendar/`
(interface, DTOs, mappers, `di/`) and
`core-model/src/main/kotlin/com/testlogon/android/core/model/calendar/`
(domain types).

### 4.1 Domain types (core-model)

```kotlin
package com.testlogon.android.core.model.calendar

import java.time.Instant
import java.time.LocalDate

data class Calendar(
    val id: String,
    val name: String,
    val ownerDisplayName: String,
    val permission: SharePermission, // VIEWER | EDITOR | OWNER | UNKNOWN
    val color: String?,              // hex, optional
)

enum class SharePermission { VIEWER, EDITOR, OWNER, UNKNOWN }

data class CalendarEvent(
    val id: String,
    val calendarId: String,
    val title: String,
    val description: String?,
    val location: String?,
    val startAt: Instant,
    val endAt: Instant?,
    val allDay: Boolean,
    val startDate: LocalDate?,        // populated when allDay
    val endDate: LocalDate?,          // populated when allDay
    val timezone: String?,           // IANA tz, e.g. "America/New_York"
    val visibility: EventVisibility, // PUBLIC | PRIVATE | UNKNOWN
    val rsvp: RsvpStatus,            // viewer's RSVP
    val recurrence: Recurrence?,     // null for one-off events
    val recurringEventId: String?,   // parent id for an expanded instance
    val updatedAt: Instant?,
)

enum class EventVisibility { PUBLIC, PRIVATE, UNKNOWN }
enum class RsvpStatus { YES, NO, MAYBE, PENDING, UNKNOWN }

data class Recurrence(
    val rrule: String,               // raw RRULE, preserved verbatim
    val freq: RecurrenceFreq,        // DAILY | WEEKLY | MONTHLY | YEARLY | UNKNOWN
    val interval: Int?,              // every N units
    val until: Instant?,             // explicit end, mutually exclusive with count
    val count: Int?,                 // number of occurrences
    val byDay: List<String>,         // e.g. ["MO","WE","FR"]
    val exDates: List<Instant>,      // exception dates
)

enum class RecurrenceFreq { DAILY, WEEKLY, MONTHLY, YEARLY, UNKNOWN }
```

These are the canonical types AND-138 migrates onto. `SharePermission` extends
AND-138's provisional enum with `OWNER`; `RsvpStatus`/visibility match its semantics.

### 4.2 DTOs (core-network)

```kotlin
package com.testlogon.android.core.network.calendar

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import java.time.Instant

@JsonClass(generateAdapter = true)
data class CalendarDto(
    val id: String,
    val name: String,
    @Json(name = "owner_display_name") val ownerDisplayName: String? = null,
    val permission: String? = null,
    val color: String? = null,
)

@JsonClass(generateAdapter = true)
data class CalendarEventDto(
    val id: String,
    @Json(name = "calendar_id") val calendarId: String,
    val title: String,
    val description: String? = null,
    val location: String? = null,
    @Json(name = "start_at") val startAt: Instant? = null,
    @Json(name = "end_at") val endAt: Instant? = null,
    @Json(name = "start_date") val startDate: String? = null, // ISO date, all-day
    @Json(name = "end_date") val endDate: String? = null,
    @Json(name = "all_day") val allDay: Boolean = false,
    val timezone: String? = null,
    val visibility: String? = null,
    val rsvp: String? = null,
    val recurrence: RecurrenceDto? = null,
    @Json(name = "recurring_event_id") val recurringEventId: String? = null,
    @Json(name = "updated_at") val updatedAt: Instant? = null,
)

@JsonClass(generateAdapter = true)
data class RecurrenceDto(
    val rrule: String? = null,
    val freq: String? = null,
    val interval: Int? = null,
    val until: Instant? = null,
    val count: Int? = null,
    val byday: List<String>? = null,
    val exdates: List<Instant>? = null,
)

@JsonClass(generateAdapter = true)
data class EventRangeRespDto(
    val items: List<CalendarEventDto>,
    @Json(name = "next_page") val nextPage: String? = null,
)

@JsonClass(generateAdapter = true)
data class EventCreateReqDto(
    @Json(name = "calendar_id") val calendarId: String,
    val title: String,
    @Json(name = "start_at") val startAt: Instant,
    @Json(name = "end_at") val endAt: Instant?,
    @Json(name = "all_day") val allDay: Boolean,
    val location: String? = null,
    val description: String? = null,
    val timezone: String? = null,
    val recurrence: RecurrenceDto? = null,
)

@JsonClass(generateAdapter = true)
data class EventUpdateReqDto(
    val title: String? = null,
    @Json(name = "start_at") val startAt: Instant? = null,
    @Json(name = "end_at") val endAt: Instant? = null,
    @Json(name = "all_day") val allDay: Boolean? = null,
    val location: String? = null,
    val description: String? = null,
    val timezone: String? = null,
    val recurrence: RecurrenceDto? = null,
)

@JsonClass(generateAdapter = true)
data class RsvpReqDto(val status: String) // "yes" | "no" | "maybe"
```

`CalendarEventDto` accepts **either** `start_at`/`end_at` (`Instant`) **or**
`start_date`/`end_date` (ISO date string, all-day); the mapper reconciles them
(R-3). `Instant` (de)serialization uses the shared `InstantJsonAdapter`.

### 4.3 The `CalendarApi` interface

```kotlin
package com.testlogon.android.core.network.calendar

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

interface CalendarApi {

    /** Calendars visible to the principal (owned + shared). Idempotent GET. */
    @GET("calendars")
    suspend fun listCalendars(): List<CalendarDto>

    /** Events overlapping [from, to). Idempotent GET; paged via next_page cursor. */
    @GET("calendar/events")
    suspend fun listEvents(
        @Query("from") from: String,            // RFC-3339, inclusive
        @Query("to") to: String,                // RFC-3339, exclusive
        @Query("calendar_id") calendarId: String? = null,
        @Query("page") page: String? = null,    // opaque cursor
    ): EventRangeRespDto

    /** Single event (may be a recurrence master or an instance). Idempotent GET. */
    @GET("calendar/events/{eventId}")
    suspend fun getEvent(@Path("eventId") eventId: String): CalendarEventDto

    @Headers("Content-Type: application/json")
    @POST("calendar/events")
    suspend fun createEvent(@Body body: EventCreateReqDto): CalendarEventDto

    @Headers("Content-Type: application/json")
    @PATCH("calendar/events/{eventId}")
    suspend fun updateEvent(
        @Path("eventId") eventId: String,
        @Body body: EventUpdateReqDto,
    ): CalendarEventDto

    @DELETE("calendar/events/{eventId}")
    suspend fun deleteEvent(@Path("eventId") eventId: String): Unit

    /** Set the viewer's RSVP for an event. */
    @Headers("Content-Type: application/json")
    @POST("calendar/events/{eventId}/rsvp")
    suspend fun setRsvp(
        @Path("eventId") eventId: String,
        @Body body: RsvpReqDto,
    ): CalendarEventDto
}
```

Notes: exact paths (`calendar/events` vs `calendars/{id}/events`) and the RSVP
verb/path are confirmed against `/openapi.json` and `calendar.ts` before coding
(Q-1/Q-2). `deleteEvent` returns `Unit` (tolerates empty 2xx); if the backend
returns a body, switch to a thin `OkResp`-style DTO.

### 4.4 Mappers

```kotlin
package com.testlogon.android.core.network.calendar

import com.testlogon.android.core.model.calendar.*
import java.time.LocalDate

fun CalendarEventDto.toDomain(): CalendarEvent {
    val startInstant = startAt ?: startDate?.let { LocalDate.parse(it).atStartOfDay(...).toInstant() }
        ?: error("event $id has neither start_at nor start_date")
    return CalendarEvent(
        id = id,
        calendarId = calendarId,
        title = title,
        description = description,
        location = location,
        startAt = startInstant,
        endAt = endAt,
        allDay = allDay,
        startDate = startDate?.let(LocalDate::parse),
        endDate = endDate?.let(LocalDate::parse),
        timezone = timezone,
        visibility = visibility.toEventVisibility(),
        rsvp = rsvp.toRsvpStatus(),
        recurrence = recurrence?.toDomain(),
        recurringEventId = recurringEventId,
        updatedAt = updatedAt,
    )
}

fun RecurrenceDto.toDomain(): Recurrence = Recurrence(
    rrule = rrule ?: synthesizeRrule(this), // never drop recurrence
    freq = freq.toRecurrenceFreq(),
    interval = interval,
    until = until,
    count = count,
    byDay = byday.orEmpty(),
    exDates = exdates.orEmpty(),
)

private fun String?.toRsvpStatus(): RsvpStatus = when (this?.lowercase()) {
    "yes" -> RsvpStatus.YES; "no" -> RsvpStatus.NO; "maybe" -> RsvpStatus.MAYBE
    "pending", null -> RsvpStatus.PENDING; else -> RsvpStatus.UNKNOWN
}
// analogous String?.toEventVisibility(), .toRecurrenceFreq(), CalendarDto.toDomain()
```

Mappers are pure, side-effect-free, and individually unit-tested. Enum extension
helpers centralize unknown-value tolerance.

### 4.5 Hilt provider

```kotlin
package com.testlogon.android.core.network.calendar.di

import com.testlogon.android.core.network.calendar.CalendarApi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object CalendarApiModule {

    @Provides
    @Singleton
    fun provideCalendarApi(retrofit: Retrofit): CalendarApi =
        retrofit.create(CalendarApi::class.java)
}
```

The injected `Retrofit` is the singleton from AND-010's `NetworkModule` (built on
AND-009's `OkHttpClient`). No client/Retrofit is constructed here.

### 4.6 Gradle wiring

No new dependencies. `core-network/build.gradle.kts` already has Retrofit, Moshi
(+ KSP codegen), Hilt, and (test) MockWebServer from AND-010. `core-network`
already depends on `:core-model`. This ticket adds source files (interface, DTOs,
mappers, provider) and domain types in `:core-model` only.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All bodies JSON; all reads ride
the cookie session + `X-CSRF-Token` (mutations). Shapes below are the working
contract, reconciled against `/openapi.json` + `calendar.ts` before merge.

### GET `calendars`
Response `200`:
```json
[
  { "id": "cal_55", "name": "Team On-call", "owner_display_name": "Dana Ruiz",
    "permission": "editor", "color": "#2E7D32" }
]
```

### GET `calendar/events?from=…&to=…&calendar_id=…&page=…`
`from`/`to` RFC-3339; `page` opaque cursor. Response `200`:
```json
{
  "items": [
    {
      "id": "evt_91", "calendar_id": "cal_55", "title": "Sprint review",
      "start_at": "2026-06-10T17:00:00Z", "end_at": "2026-06-10T18:00:00Z",
      "all_day": false, "timezone": "America/New_York",
      "visibility": "public", "rsvp": "pending", "updated_at": "2026-06-05T12:00:00Z"
    },
    {
      "id": "evt_92", "calendar_id": "cal_55", "title": "Standup",
      "start_at": "2026-06-08T13:00:00Z", "end_at": "2026-06-08T13:15:00Z",
      "all_day": false, "rsvp": "yes",
      "recurrence": {
        "rrule": "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR;UNTIL=20260731T130000Z",
        "freq": "WEEKLY", "interval": 1, "byday": ["MO","TU","WE","TH","FR"],
        "until": "2026-07-31T13:00:00Z",
        "exdates": ["2026-06-19T13:00:00Z"]
      }
    },
    {
      "id": "evt_93", "calendar_id": "cal_55", "title": "Company holiday",
      "all_day": true, "start_date": "2026-07-03", "end_date": "2026-07-04",
      "rsvp": "pending"
    }
  ],
  "next_page": "eyJvZmZzZXQiOjUwfQ=="
}
```

### GET `calendar/events/{eventId}`
Response `200`: a single `CalendarEventDto` (same shape as an `items[]` element).
`404` if unknown.

### POST `calendar/events`
Request:
```json
{ "calendar_id": "cal_55", "title": "1:1", "start_at": "2026-06-12T15:00:00Z",
  "end_at": "2026-06-12T15:30:00Z", "all_day": false }
```
Response `201`/`200`: the created `CalendarEventDto` (with server `id`).

### PATCH `calendar/events/{eventId}`
Request: sparse `EventUpdateReqDto` (only changed fields). Response `200`: updated event.

### DELETE `calendar/events/{eventId}`
Response `200`/`204` (empty body). `404` if already deleted.

### POST `calendar/events/{eventId}/rsvp`
Request: `{ "status": "yes" }`. Response `200`: updated `CalendarEventDto` with new `rsvp`.

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg,type,loc}] | {code,...}`). Mapping to typed `ApiError` is owned by
**AND-015**; this ticket lets non-2xx surface as `retrofit2.HttpException`.

## 6. Data & State Management

`CalendarApi` is **stateless** — a singleton interface proxy with no fields. This
ticket holds no `StateFlow`/`UiState`, no Room, no DataStore.

- **Session state** lives in cookies, persisted by the cookie jar (AND-011);
  `CalendarApi` never reads/writes cookies. CSRF (`ui_csrf` → `X-CSRF-Token`) is
  attached by AND-012 for mutating verbs (`POST`/`PATCH`/`DELETE`).
- **Serialization:** request/response (de)serialization uses Moshi codegen
  adapters (KSP) + the shared `InstantJsonAdapter` via the shared converter.
  Unknown JSON keys are ignored; absent optional fields fall back to Kotlin
  defaults (lenient). Unknown enum strings map to `UNKNOWN`/`PENDING` in mappers,
  not at the adapter level.
- **Domain mapping** is the one transformation this ticket performs:
  DTO→`core-model` via pure `toDomain()` functions. Callers (`core-data`
  repositories) decide whether to wrap in `ApiResult<T>` (AND-018), cache in Room,
  or expose via `StateFlow`. None of that is here.
- **Paging:** `listEvents` returns an `EventRangeRespDto` with a `next_page`
  cursor; the actual Paging 3 `PagingSource`/`RemoteMediator` is a downstream
  `core-data`/feature concern. This ticket only exposes the cursor-bearing call.
- **Threading:** suspend methods are invoked from a coroutine on an IO dispatcher
  injected at the repository layer. This ticket imposes no dispatcher.

## 7. Error Handling & Resilience

- **Non-2xx** surfaces as `retrofit2.HttpException` carrying the raw error body for
  AND-015 to decode the FastAPI `detail`. A `401` on any call is intercepted by the
  AND-013 `Authenticator`, which calls `sessionRefresh()` once and retries; only a
  second `401` propagates (→ route to login, AND-025).
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged. The ~20s timeouts and bounded backoff for
  the **idempotent GETs** (`listCalendars`, `listEvents`, `getEvent`) are owned by
  AND-009/AND-016 on the shared client. Mutating verbs are **not** auto-retried.
- **Deserialization failures** surface as `JsonDataException` from the converter.
  Mappers are written defensively so that *recoverable* shape variance (missing
  optionals, unknown enums, `start_date` vs `start_at`) never throws; only a
  genuinely malformed/contract-violating payload (e.g. event with no start at all)
  produces an error, and it does so deterministically (`error(...)` in the mapper),
  surfaced to callers for AND-015/AND-018 handling.
- **Recurrence safety:** an event with a `recurrence` object but no `rrule` string
  is still mapped (R-1) by synthesizing an RRULE from structured fields; recurrence
  is never silently dropped.
- This ticket maps **no** errors to user-facing types itself — that is AND-015
  (`ApiError`) / AND-018 (`ApiResult`).

## 8. Security & Privacy

- **Authenticated surface:** all calendar endpoints require the cookie session
  established by the auth flow (AND-027 family). `CalendarApi` adds no manual
  `Cookie`/`Authorization` headers; identity is carried implicitly by the jar.
- **CSRF:** mutating verbs (`POST`/`PATCH`/`DELETE`, including `createEvent`,
  `updateEvent`, `deleteEvent`, `setRsvp`) rely on AND-012 to attach
  `X-CSRF-Token`; without it they will `403` against a real backend (R-4).
- **Cleartext on dev:** calendar payloads (titles, locations, descriptions,
  attendee-adjacent data) ride plaintext HTTP on the dev host — a known,
  dev-only risk permitted by the scoped cleartext config (AND-006);
  `staging`/`prod` are HTTPS-only.
- **No payload logging:** event titles/locations/descriptions are potentially
  sensitive. This ticket adds no logging; the shared logging interceptor (AND-009)
  is debug-only and redacted. A code-review check confirms no calendar payload body
  reaches logcat in any build.
- **No new permissions / no token storage:** purely network transport. The
  `ACTION_INSERT` calendar hand-off (and its permission-free design) is AND-138's
  concern, not this ticket.
- **Scope:** event/RSVP operations act only within calendars the principal can see
  (server-enforced by the cookie-scoped identity).

## 9. Accessibility & i18n

Not directly applicable — this is a headless transport + serialization layer with
no UI surface and no user-facing strings. Two hand-offs to downstream UI tickets:

- **i18n of dates:** this ticket transports `Instant`/`LocalDate` + the event's
  IANA `timezone` without formatting them. Localized, timezone-aware, 12/24h-aware
  rendering (and all-day rendering without a clock) is owned by the calendar feature
  screens and by AND-138's cells.
- **Error text localization** derived from these endpoints is owned by AND-015
  (error mapping) and the consuming feature ViewModels.

## 10. Telemetry & Logging

- **HTTP logging** is inherited from AND-009's redacting `HttpLoggingInterceptor`
  (debug builds only). No new logging here; calendar payload bodies must be redacted
  (Section 8). No `Timber` payload dumps.
- **No analytics events** emitted by this layer. Calendar-view, event-open, and
  RSVP-changed analytics are emitted by the consuming feature ViewModels (their own
  tickets), derived from `ApiResult` outcomes — and must follow the AND-052
  redaction policy (no titles/locations/ids beyond anonymized form), mirroring
  AND-138's telemetry rules.
- **Build-time signal:** KSP must generate Moshi adapters for every calendar DTO; a
  missing adapter fails the build (no reflection fallback, per AND-010 policy).

## 11. Testing Strategy

All tests are JVM unit tests in `core-network/src/test/...` using `MockWebServer`
and the production Moshi/Retrofit configuration (including the shared
`InstantJsonAdapter`). Endpoint tests assert **verb, resolved path, query/body, and
decoded response**; mapper tests assert **exhaustive DTO→domain correctness**.

Test harness:
```kotlin
private fun api(server: MockWebServer): CalendarApi {
    val moshi = Moshi.Builder()
        .add(InstantJsonAdapter()) // mirrors provideMoshi()
        .build()
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(CalendarApi::class.java)
}
```

**T-1 — `listCalendars`** issues `GET /calendars`, decodes `List<CalendarDto>`.

**T-2 — `listEvents` query.**
```kotlin
@Test fun listEvents_sendsRangeQueryAndDecodes() = runTest {
    val server = MockWebServer().apply {
        enqueue(MockResponse().setBody(RANGE_JSON)); start()
    }
    val resp = api(server).listEvents(
        from = "2026-06-08T00:00:00Z", to = "2026-06-15T00:00:00Z", calendarId = "cal_55")
    val req = server.takeRequest()
    assertEquals("GET", req.method)
    val url = req.requestUrl!!
    assertEquals("/calendar/events", url.encodedPath)
    assertEquals("2026-06-08T00:00:00Z", url.queryParameter("from"))
    assertEquals("cal_55", url.queryParameter("calendar_id"))
    assertEquals("eyJvZmZzZXQiOjUwfQ==", resp.nextPage)
    assertEquals(3, resp.items.size)
    server.shutdown()
}
```

**T-3 — recurrence mapping (KEY).** `RANGE_JSON.items[1]` (weekly RRULE) maps to a
`CalendarEvent` whose `recurrence` retains `rrule` verbatim, `freq == WEEKLY`,
`byDay == ["MO","TU","WE","TH","FR"]`, `until` parsed to the right `Instant`, and
`exDates.size == 1`. Recurrence is never null/dropped.

**T-4 — all-day mapping.** `items[2]` (`all_day:true`, `start_date`/`end_date`, no
`start_at`) maps to `allDay == true`, non-null `startDate`/`endDate`
(`LocalDate`), and a derived `startAt` `Instant`; no off-by-one.

**T-5 — enum tolerance.** `rsvp:"pending"` → `PENDING`; an unknown
`visibility:"secret"` → `UNKNOWN`; missing `permission` → `UNKNOWN`. No throw.

**T-6 — `getEvent`** issues `GET /calendar/events/evt_91` (path param) and decodes
a single event.

**T-7 — `createEvent`** issues `POST /calendar/events` with a JSON body containing
`calendar_id`, `title`, `start_at`; decodes the returned event with server `id`.

**T-8 — `updateEvent`** issues `PATCH /calendar/events/evt_91` with a **sparse**
body (only the changed field serialized; nulls omitted) and decodes the response.

**T-9 — `deleteEvent`** issues `DELETE /calendar/events/evt_91` and tolerates an
empty `204`/`200` (returns `Unit`).

**T-10 — `setRsvp`** issues `POST /calendar/events/evt_91/rsvp` with
`{"status":"yes"}` and decodes the updated event (`rsvp == YES`).

**T-11 — error propagation.** A `401` from `listEvents` throws
`retrofit2.HttpException` with `code() == 401` (non-2xx not swallowed, leaving room
for AND-013/AND-015).

**T-12 — Hilt provider.** `@HiltAndroidTest` (or `core-testing` harness) injects
`CalendarApi` and asserts a non-null singleton built on the shared Retrofit (same
instance on repeated injection).

Coverage target: ≥90% on the new surface (interface binding + all mappers). Every
endpoint has ≥1 path/verb assertion; every DTO field with non-trivial mapping
(recurrence, all-day, enums) has a dedicated assertion. This satisfies the backlog
acceptance "calendar payloads map (tested)".

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-027** — AuthApi / session endpoints. Establishes the cookie session
  machinery every calendar call rides on; blocking per the backlog `Deps: AND-027`.

**Transitive upstream (already required by AND-027/AND-010):** AND-026 (Moshi/DTO
patterns + `InstantJsonAdapter`), AND-010 (shared Retrofit/Moshi), AND-009 (shared
`OkHttpClient`, timeouts, redacting logger), AND-016 (idempotent-GET backoff),
AND-006 (`BuildConfig`), AND-003/AND-004 (module structure, Hilt baseline).
Integration-depends on AND-011/AND-012/AND-013 for cookies/CSRF/refresh at runtime
(unit tests use MockWebServer and are unaffected).

**Downstream (this ticket blocks):**
- **AND-138** — calendar message cells. It currently defines provisional
  `CalendarEventPayload`/`CalendarSharePayload`/`SharePermission` and flags the M6
  calendar domain as the canonical owner. This ticket supplies the canonical
  `core-model` types (`CalendarEvent`, `Calendar`, `Recurrence`, `RsvpStatus`,
  `SharePermission`); AND-138 migrates onto them — hence `blocks: [AND-138]`.
- The **calendar repository** (`core-data`) and the **M6 calendar feature**
  (agenda/list/detail screens, Paging 3 over `listEvents`) consume `CalendarApi`
  and the mappers.

**Sequencing within the ticket:** (1) confirm endpoint set, paths, RSVP verb, and
field names against `/openapi.json` + `calendar.ts`; (2) define `core-model` domain
types; (3) define DTOs + codegen adapters; (4) write `CalendarMappers.kt`;
(5) declare `CalendarApi`; (6) add `CalendarApiModule`; (7) write tests T-1..T-12.

## 13. Risks & Open Questions

- **R-1 Recurrence representation.** Backend may send a raw `rrule` string, a
  structured object, or both. Mitigation: DTO captures both; mapper preserves
  `rrule` verbatim and synthesizes one from structured fields if absent, so
  recurrence is never dropped. Guarded by T-3. No RRULE expansion in this ticket.
- **R-2 Paging shape.** `listEvents` may return a bare array, a `{items,next_page}`
  envelope, or offset/limit params. Mitigation: match `calendar.ts`/OpenAPI;
  default to the `EventRangeRespDto` cursor envelope. Guarded by T-2.
- **R-3 All-day timestamps.** Server may send `all_day` with `start_date`/`end_date`
  (ISO date) and omit `start_at`, or send naive timestamps + separate `timezone`.
  Mitigation: DTO accepts both; mapper derives `Instant` + `LocalDate` using the
  event tz when present, device tz otherwise. Open: is `start_at` always UTC?
  Guarded by T-4.
- **R-4 CSRF on mutations.** If AND-012's interceptor is absent, `create`/`update`/
  `delete`/`rsvp` may `403` end-to-end. Unit tests (MockWebServer) are unaffected.
- **R-5 Type duplication with AND-138.** Until AND-138 migrates to these canonical
  types, the provisional copies coexist. Mitigation: land canonical types in
  `core-model` here; track AND-138 migration as the follow-up.
- **Q-1** Endpoint paths: `calendar/events` vs `calendars/{id}/events`? *Proposed:*
  match `calendar.ts`/OpenAPI; spec assumes flat `calendar/events` with optional
  `calendar_id` query.
- **Q-2** RSVP contract: `POST /calendar/events/{id}/rsvp` vs `PATCH` on the event?
  *Proposed:* confirm via OpenAPI; spec assumes the dedicated RSVP POST.
- **Q-3** Does `deleteEvent` return an empty body or `{"ok":true}`? *Proposed:*
  default `Unit`; switch to `OkResp` if a body is returned. Guarded by T-9.
- **Q-4** Recurring-instance semantics: does `getEvent` on a recurrence master
  return the series or a single instance, and is `recurring_event_id` populated on
  instances? *Proposed:* confirm via OpenAPI; mapper carries `recurringEventId`
  through regardless.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Calendar payloads map (tested): every calendar JSON shape in
  Section 5 — including the recurring event and the all-day event — decodes via the
  production Moshi config and maps losslessly into the `core-model` domain types,
  proven by mapper unit tests (T-3, T-4, T-5).
- **AC-2.** `CalendarApi` declares the calendar operations (`listCalendars`,
  `listEvents`, `getEvent`, `createEvent`, `updateEvent`, `deleteEvent`, `setRsvp`)
  and the module compiles against the new DTOs and `core-model` types.
- **AC-3.** Each endpoint is callable and its **verb + resolved path + query/body**
  match Section 5, asserted with MockWebServer (T-1, T-2, T-6..T-10).
- **AC-4.** `listEvents` serializes `from`/`to`/`calendar_id`/`page` query params
  and decodes the paged `{items, next_page}` envelope (T-2).
- **AC-5.** Recurrence is preserved end-to-end: raw `rrule` retained, `freq`/`byDay`/
  `until`/`exDates` mapped, recurrence never dropped (T-3).
- **AC-6.** All-day events map to `allDay=true` with `LocalDate` start/end and a
  derived `Instant`, with no off-by-one (T-4).
- **AC-7.** Unknown enum strings and missing optional fields map to
  `UNKNOWN`/`PENDING`/defaults without throwing (T-5).
- **AC-8.** Non-2xx (e.g. `401` from `listEvents`) surfaces as `HttpException` and
  is not swallowed (T-11).
- **AC-9.** `CalendarApi` is Hilt-provided as a `@Singleton` on the shared Retrofit;
  repeated injection yields the same instance; no new `OkHttpClient`/`Retrofit` and
  no per-method CSRF/cookie headers (T-12).
- **AC-10.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP-generated adapters present and no detekt/lint regressions.

## 15. Definition of Done

- Domain types (`CalendarEvent`, `Calendar`, `Recurrence`, enums) live in
  `core-model` (`com.testlogon.android.core.model.calendar`); DTOs, `CalendarApi`,
  `CalendarMappers.kt`, and `CalendarApiModule` live in `core-network`
  (`com.testlogon.android.core.network.calendar` + `.di`).
- Open questions Q-1..Q-4 are resolved against `/openapi.json` and
  `frontend/src/api/endpoints/calendar.ts` + `types.ts`; the interface's
  paths/verbs/query params and the DTO field names reflect the confirmed contract.
- MockWebServer + mapper tests T-1 through T-12 are implemented and green in CI;
  ≥90% line coverage on the new surface; every endpoint has a path/verb assertion
  and recurrence/all-day/enum mapping each has a dedicated assertion.
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/auth headers in the
  interface; no calendar payload bodies in logs (verified in review).
- `./gradlew :core-model:assemble :core-network:assemble :core-network:testDebugUnitTest`
  passes locally and in CI with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; the calendar repository / M6 calendar
  feature is unblocked and **AND-138 is given the canonical `core-model` calendar
  types to migrate onto** (migration tracked as the follow-up).
- A one-line note in the `core-network` README (owned by AND-007) records the
  `CalendarApi` path/verb map and the delegation of cookie/CSRF/refresh to
  AND-011/AND-012/AND-013.
