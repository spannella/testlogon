---
id: AND-270
title: Calendar API + DTOs
milestone: M6
epic: E37
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: [AND-138]
---

# AND-270 — Calendar API + DTOs

## 1. Overview & Goal

This ticket defines the typed HTTP seam for the TestLogon **calendar** domain on
Android: the Retrofit service interface `CalendarApi`, the Moshi DTOs it
(de)serializes (calendars, events, recurrence), and the DTO→domain mappers
<!-- CORRECTED: the backend calendar contract has NO RSVP concept. There is no
RSVP field on the event and no RSVP endpoint in frontend/src/api/endpoints/calendar.ts
nor in the OpenAPI index. RSVP/`setRsvp` has been removed throughout. Attendees are
modeled as a plain `attendees: string[]` on the event (EventOut.attendees). -->
that produce the canonical `core-model` calendar types consumed by every
downstream calendar feature (calendar list/agenda screens, event detail, and the
calendar-message renderer AND-138).

Scope, verbatim from the backlog: *`calendar.ts` endpoints/DTOs (events,
recurrence).* This is the Kotlin port of the web reference API layer file
`frontend/src/api/endpoints/calendar.ts` plus the calendar slice of
`frontend/src/api/types.ts`. The single acceptance criterion is that **calendar
payloads map (tested)** — i.e. every endpoint is callable with verb/path/body
matching the backend contract, and every calendar JSON shape (including recurring
events and all-day events) decodes losslessly into the domain model, proven by
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
operations exposed by `calendar.ts`: list calendars, get a single calendar,
create/update/delete a calendar, list events for a calendar (paged), get a single
event, create/update/delete an event. <!-- CORRECTED: there is NO "set RSVP"
operation. Events are nested under a calendar (`/ui/calendars/{calendar_id}/events`),
so there is no flat "list events in a range" call; the per-calendar list is the
primitive. Verified against frontend/src/api/endpoints/calendar.ts and OpenAPI
GET/POST /ui/calendars and /ui/calendars/{calendar_id}/events. --> (Exact set
reconciled against the OpenAPI index; Section 5 is the working contract.)

FR-2. Each method's HTTP verb and relative path match the backend contract.
Paths are declared **without** a leading slash (AND-010 convention) so they append
to the normalized base URL `http://18.222.237.167:8000/`. <!-- CORRECTED: the
backend paths are under the `ui/` prefix — `ui/calendars`,
`ui/calendars/{calendar_id}/events`, `ui/calendars/{calendar_id}/events/{event_id}`
— NOT the flat `calendars` / `calendar/events`. See Section 5. -->

FR-3. All methods are `suspend` and return typed DTO bodies (Retrofit native
coroutine support). A method with no meaningful body returns `Unit`.

FR-4. The event-list endpoint uses typed `@Query` params. <!-- CORRECTED: the
real query params are `start_utc`, `end_utc`, `limit`, `cursor` (see OpenAPI
GET /ui/calendars/{calendar_id}/events params=start_utc,end_utc,limit,cursor). The
web client (`getEvents`) only ever sends `cursor`, treating `start_utc`/`end_utc`/
`limit` as optional. There is NO `from`/`to`/`page`/`calendar_id` query param —
`calendar_id` is a `@Path`, not a query. --> Param names are `start_utc`, `end_utc`
(RFC-3339, both optional), `limit` (optional Int), and `cursor` (opaque, optional).
Mutations use `@Body` request DTOs; single-resource ops use `@Path` (both
`calendarId` and `eventId`). No raw `Map`/`JsonObject`.

FR-5. Define Moshi `@JsonClass(generateAdapter = true)` DTOs for every calendar
shape: `CalendarDto` (CalendarOut), `CalendarEventDto` (EventOut), `RecurrenceRuleDto`
(RecurrenceRule), `EventsPageDto` (EventsPageOut, paged), plus request DTOs
`CalendarCreateReqDto` (CalendarCreateIn), `EventCreateReqDto` (EventCreateIn), and
`EventUpdateReqDto` (the PATCH uses a partial of EventCreateIn — see
`updateEvent(..., body: Partial<EventCreateIn>)`). <!-- CORRECTED: there is no
`RsvpReqDto`; the recurrence DTO mirrors the backend `RecurrenceRule` schema. -->
Wire fields are snake_case; Kotlin properties are camelCase via `@Json(name=...)`
only where codegen cannot infer.

FR-6. **Recurrence MUST be modeled losslessly.** <!-- CORRECTED: the backend does
NOT use a raw RRULE string. The `RecurrenceRule` schema is fully structured:
`freq` (enum DAILY|WEEKLY|MONTHLY only — NO YEARLY), `interval` (default 1),
`until_utc`, `count`, `byday` (enum MO..SU), `bymonthday` (int[]), `bysetpos`
(int[]). There is NO `rrule` field and NO `exdates` inside the recurrence object.
Exception dates live at the EVENT level as `exdates_utc: string[]`, and
per-occurrence edits live in `recurrence_overrides: Record<string,
OccurrenceOverrideIn>`. --> A recurring event carries a structured
`recurrence_rule` plus event-level `exdates_utc` and `recurrence_overrides`. The
DTO preserves every structured field the backend sends; the mapper produces a
domain `Recurrence` that retains them all (so the client never silently drops
recurrence). No client-side recurrence *expansion* is implemented here (that is a
downstream feature concern); this ticket only transports/maps it.

FR-7. Provide pure DTO→domain mappers in `CalendarMappers.kt`:
`CalendarEventDto.toDomain(): CalendarEvent`, `CalendarDto.toDomain(): Calendar`,
`RecurrenceRuleDto.toDomain(): Recurrence`, and the inverse request mappers for
create/update. Mappers MUST map unknown enum strings to `UNKNOWN` (never throw),
and tolerate absent optional fields via Kotlin defaults.

FR-8. Timestamps are parsed to `java.time.Instant` via the shared
`InstantJsonAdapter`; all-day events expose `allDay = true` and a single
`LocalDate` (`all_day_date`) so callers avoid off-by-one across DST. <!-- CORRECTED:
the backend uses a single `all_day_date` string for all-day events, not separate
`start_date`/`end_date`. Timed events use `start_utc`/`end_utc`. --> The event's
IANA `timezone` (required, non-null on EventOut) is preserved on the domain model.

FR-9. A Hilt `@Provides @Singleton fun provideCalendarApi(retrofit: Retrofit):
CalendarApi` constructs the service from the shared Retrofit (AND-010). No new
Retrofit/OkHttp instance is created. The calendar Moshi adapters are codegen
(KSP); only the shared `InstantJsonAdapter` (and any enum fallback adapter) is
registered explicitly on the shared Moshi if not already present.

FR-10. CSRF (`X-CSRF-Token`) and cookies are **not** declared per-method; they are
injected globally (AND-012/AND-011). `CalendarApi` stays header-agnostic.
<!-- VERIFIED: web client (src/api/client.ts) reads the `ui_csrf` cookie and sets
`X-CSRF-Token` on every request. NOTE: the web client ALSO sends
`Authorization: Bearer <accessToken>` from the auth store, and the OpenAPI calendar
endpoints additionally declare `authorization` / `X-SESSION-ID` params. Whether the
Android port uses bearer-token or pure-cookie auth is an AND-027 decision delegated
out of this ticket; see §16 Open assumptions. -->

## 4. Technical Design

Production code lands in
`core-network/src/main/kotlin/com/testlogon/android/core/network/calendar/`
(interface, DTOs, mappers, `di/`) and
`core-model/src/main/kotlin/com/testlogon/android/core/model/calendar/`
(domain types).

### 4.1 Domain types (core-model)

> **CORRECTED 2026-06-06.** The original domain model was invented and did not
> match the backend. The shapes below mirror `CalendarOut`, `EventOut`,
> `RecurrenceRule`, and `EventsPageOut` (OpenAPI) / `Calendar`, `CalendarEvent`,
> `RecurrenceRule`, `EventsPage` (frontend `src/api/types.ts`). Removed:
> `ownerDisplayName`, `permission`/`color` on `Calendar`; `title`, `location`,
> `visibility`, `rsvp`, `recurringEventId`, `startDate`/`endDate`, `updatedAt`,
> the raw `rrule`, `RecurrenceFreq.YEARLY`, and in-recurrence `exDates`. Added:
> `name`, `ownerUserId`, `conflictDetection`, `bufferBefore/AfterMinutes` on
> `Calendar`; `name`, `attendees`, `status`, `category`, `bookingEnabled`,
> `approvalRequired`, `allDayDate`, event-level `exDatesUtc`, `recurrenceOverrides`,
> `createdAtUtc`, and recurrence `byMonthDay`/`bySetPos` on the event.

```kotlin
package com.testlogon.android.core.model.calendar

import java.time.Instant
import java.time.LocalDate

data class Calendar(
    val calendarId: String,
    val name: String,
    val timezone: String,                 // IANA, required
    val ownerUserId: String,
    val conflictDetection: Boolean,
    val bufferBeforeMinutes: Int,
    val bufferAfterMinutes: Int,
    val createdAtUtc: Instant,
    val workingHours: Map<String, List<WorkingHoursWindow>>? = null,
)

data class CalendarEvent(
    val eventId: String,
    val calendarId: String,
    val name: String,
    val description: String,              // required (defaults to "" on EventOut)
    val timezone: String,                 // IANA, required
    val startAt: Instant?,                // start_utc (null for all-day)
    val endAt: Instant?,                  // end_utc
    val allDay: Boolean,
    val allDayDate: LocalDate?,           // populated when allDay
    val attendees: List<String>,
    val bookingEnabled: Boolean,
    val approvalRequired: Boolean,
    val status: String,                   // free-form on the wire
    val category: String?,
    val recurrence: Recurrence?,          // null for one-off events
    val exDatesUtc: List<Instant>,        // event-level exception dates
    val recurrenceOverrides: Map<String, OccurrenceOverride>, // keyed by occurrence start
    val createdAtUtc: Instant,
    val syncState: String? = null,
    val syncConflictReason: String? = null,
)

data class Recurrence(
    val freq: RecurrenceFreq,             // DAILY | WEEKLY | MONTHLY | UNKNOWN
    val interval: Int,                    // default 1
    val untilUtc: Instant?,               // explicit end, mutually exclusive with count
    val count: Int?,                      // number of occurrences
    val byDay: List<String>,              // e.g. ["MO","WE","FR"]
    val byMonthDay: List<Int>,
    val bySetPos: List<Int>,
)

enum class RecurrenceFreq { DAILY, WEEKLY, MONTHLY, UNKNOWN } // NO YEARLY on the backend

// `SharePermission` is owned by the calendar-sharing surface (CalendarShare:
// permission is "read" | "write"), NOT the event model. Modeled here only if the
// share endpoints are in scope; otherwise deferred. AND-138's provisional
// SharePermission maps onto "read"/"write" semantics.
enum class SharePermission { READ, WRITE, UNKNOWN }

data class OccurrenceOverride(
    val name: String? = null,
    val description: String? = null,
    val timezone: String? = null,
    val startAt: Instant? = null,
    val endAt: Instant? = null,
    val allDay: Boolean? = null,
    val allDayDate: LocalDate? = null,
    val status: String? = null,
    val category: String? = null,
)
```

These are the canonical types AND-138 migrates onto. There is no RSVP and no event
`visibility` concept in the backend; AND-138's payloads must reconcile to these.

### 4.2 DTOs (core-network)

```kotlin
package com.testlogon.android.core.network.calendar

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import java.time.Instant

// CORRECTED 2026-06-06 to mirror CalendarOut / EventOut / RecurrenceRule /
// EventsPageOut (OpenAPI) and src/api/types.ts.

@JsonClass(generateAdapter = true)
data class CalendarDto(
    @Json(name = "calendar_id") val calendarId: String,
    val name: String,
    val timezone: String,
    @Json(name = "owner_user_id") val ownerUserId: String,
    @Json(name = "conflict_detection") val conflictDetection: Boolean = false,
    @Json(name = "buffer_before_minutes") val bufferBeforeMinutes: Int = 0,
    @Json(name = "buffer_after_minutes") val bufferAfterMinutes: Int = 0,
    @Json(name = "created_at_utc") val createdAtUtc: Instant,
    @Json(name = "working_hours") val workingHours: Map<String, List<WorkingHoursWindowDto>>? = null,
)

@JsonClass(generateAdapter = true)
data class CalendarEventDto(
    @Json(name = "event_id") val eventId: String,
    @Json(name = "calendar_id") val calendarId: String,
    val name: String,
    val description: String = "",
    val timezone: String,
    @Json(name = "start_utc") val startUtc: Instant? = null,
    @Json(name = "end_utc") val endUtc: Instant? = null,
    @Json(name = "all_day") val allDay: Boolean = false,
    @Json(name = "all_day_date") val allDayDate: String? = null, // ISO date string
    val attendees: List<String> = emptyList(),
    @Json(name = "booking_enabled") val bookingEnabled: Boolean = false,
    @Json(name = "approval_required") val approvalRequired: Boolean = false,
    val status: String = "",
    val category: String? = null,
    @Json(name = "recurrence_rule") val recurrenceRule: RecurrenceRuleDto? = null,
    @Json(name = "exdates_utc") val exdatesUtc: List<Instant>? = null,
    @Json(name = "recurrence_overrides")
    val recurrenceOverrides: Map<String, OccurrenceOverrideDto>? = null,
    @Json(name = "created_at_utc") val createdAtUtc: Instant,
    @Json(name = "sync_state") val syncState: String? = null,
    @Json(name = "sync_conflict_reason") val syncConflictReason: String? = null,
)

@JsonClass(generateAdapter = true)
data class RecurrenceRuleDto(
    val freq: String? = null,                  // "DAILY" | "WEEKLY" | "MONTHLY"
    val interval: Int = 1,
    @Json(name = "until_utc") val untilUtc: Instant? = null,
    val count: Int? = null,
    val byday: List<String>? = null,           // "MO".."SU"
    val bymonthday: List<Int>? = null,
    val bysetpos: List<Int>? = null,
)

@JsonClass(generateAdapter = true)
data class EventsPageDto(
    val events: List<CalendarEventDto>,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class EventCreateReqDto(
    val name: String,
    val description: String? = null,
    val timezone: String? = null,
    @Json(name = "start_utc") val startUtc: Instant? = null,
    @Json(name = "end_utc") val endUtc: Instant? = null,
    @Json(name = "all_day") val allDay: Boolean? = null,
    @Json(name = "all_day_date") val allDayDate: String? = null,
    val attendees: List<String>? = null,
    @Json(name = "booking_enabled") val bookingEnabled: Boolean? = null,
    @Json(name = "approval_required") val approvalRequired: Boolean? = null,
    val status: String? = null,
    val category: String? = null,
    @Json(name = "recurrence_rule") val recurrenceRule: RecurrenceRuleDto? = null,
    @Json(name = "exdates_utc") val exdatesUtc: List<Instant>? = null,
)

// PATCH uses the same shape as create (the web client passes Partial<EventCreateIn>);
// every field is nullable/omittable so unset fields are not serialized.
typealias EventUpdateReqDto = EventCreateReqDto

@JsonClass(generateAdapter = true)
data class CalendarCreateReqDto(
    val name: String,
    val timezone: String? = null,
    @Json(name = "conflict_detection") val conflictDetection: Boolean? = null,
    @Json(name = "buffer_before_minutes") val bufferBeforeMinutes: Int? = null,
    @Json(name = "buffer_after_minutes") val bufferAfterMinutes: Int? = null,
)
```

Supporting DTOs (also `@JsonClass(generateAdapter = true)`): `OkRespDto(val ok:
Boolean)` (mirrors `OkResp`, returned by deletes), `OccurrenceOverrideDto` (mirrors
`EventOccurrenceOverrideIn`/`OccurrenceOverrideIn`: optional `name`/`description`/
`timezone`/`start_utc`/`end_utc`/`all_day`/`all_day_date`/`status`/`category`), and
`WorkingHoursWindowDto` (mirrors `WorkingHoursWindow`; carried opaquely on
`CalendarDto.workingHours`).

`CalendarEventDto` carries **either** `start_utc`/`end_utc` (`Instant`, timed) **or**
`all_day:true` with `all_day_date` (a single ISO date string); the mapper reconciles
them (R-3). `Instant` (de)serialization uses the shared `InstantJsonAdapter`.
**Note:** there is no `RsvpReqDto` and no `start_date`/`end_date` pair on the wire.

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

// CORRECTED 2026-06-06: paths are `ui/calendars...`; events are nested under a
// calendar; there is no RSVP endpoint; delete returns an `OkResp` body, not empty.
interface CalendarApi {

    /** Calendars visible to the principal. Idempotent GET. `limit` optional. */
    @GET("ui/calendars")
    suspend fun listCalendars(@Query("limit") limit: Int? = null): List<CalendarDto>

    @GET("ui/calendars/{calendarId}")
    suspend fun getCalendar(@Path("calendarId") calendarId: String): CalendarDto

    @Headers("Content-Type: application/json")
    @POST("ui/calendars")
    suspend fun createCalendar(@Body body: CalendarCreateReqDto): CalendarDto

    @Headers("Content-Type: application/json")
    @PATCH("ui/calendars/{calendarId}")
    suspend fun updateCalendar(
        @Path("calendarId") calendarId: String,
        @Body body: CalendarCreateReqDto, // backend takes Partial<CalendarCreateIn>
    ): CalendarDto

    @DELETE("ui/calendars/{calendarId}")
    suspend fun deleteCalendar(@Path("calendarId") calendarId: String): OkRespDto

    /** Events for a calendar. Idempotent GET; paged via next_cursor. */
    @GET("ui/calendars/{calendarId}/events")
    suspend fun listEvents(
        @Path("calendarId") calendarId: String,
        @Query("start_utc") startUtc: String? = null, // RFC-3339, optional
        @Query("end_utc") endUtc: String? = null,     // RFC-3339, optional
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,      // opaque cursor
    ): EventsPageDto

    /** Single event (may be a recurrence master). Idempotent GET. */
    @GET("ui/calendars/{calendarId}/events/{eventId}")
    suspend fun getEvent(
        @Path("calendarId") calendarId: String,
        @Path("eventId") eventId: String,
    ): CalendarEventDto

    @Headers("Content-Type: application/json")
    @POST("ui/calendars/{calendarId}/events")
    suspend fun createEvent(
        @Path("calendarId") calendarId: String,
        @Body body: EventCreateReqDto,
        @Query("force") force: Boolean? = null, // backend supports a `force` flag
    ): CalendarEventDto

    @Headers("Content-Type: application/json")
    @PATCH("ui/calendars/{calendarId}/events/{eventId}")
    suspend fun updateEvent(
        @Path("calendarId") calendarId: String,
        @Path("eventId") eventId: String,
        @Body body: EventUpdateReqDto,
    ): CalendarEventDto

    @DELETE("ui/calendars/{calendarId}/events/{eventId}")
    suspend fun deleteEvent(
        @Path("calendarId") calendarId: String,
        @Path("eventId") eventId: String,
    ): OkRespDto
}
```

Notes: paths and the absence of an RSVP endpoint are confirmed against the OpenAPI
index and `calendar.ts`. `deleteEvent`/`deleteCalendar` return an `OkRespDto`
(`{ ok: true }`-style) per `api.del<OkResp>(...)` in `calendar.ts`. The
per-occurrence operations (`exclude`/`override`/`clear`) and sharing/conflicts/
booking endpoints exist in `calendar.ts` but are scoped OUT of this ticket (see
§13/Q-2); only the core calendar+event CRUD is in scope.

### 4.4 Mappers

```kotlin
package com.testlogon.android.core.network.calendar

import com.testlogon.android.core.model.calendar.*
import java.time.LocalDate

fun CalendarEventDto.toDomain(): CalendarEvent = CalendarEvent(
    eventId = eventId,
    calendarId = calendarId,
    name = name,
    description = description,
    timezone = timezone,
    startAt = startUtc,                                  // null for all-day
    endAt = endUtc,
    allDay = allDay,
    allDayDate = allDayDate?.let(LocalDate::parse),
    attendees = attendees,
    bookingEnabled = bookingEnabled,
    approvalRequired = approvalRequired,
    status = status,
    category = category,
    recurrence = recurrenceRule?.toDomain(),
    exDatesUtc = exdatesUtc.orEmpty(),
    recurrenceOverrides = recurrenceOverrides.orEmpty().mapValues { it.value.toDomain() },
    createdAtUtc = createdAtUtc,
    syncState = syncState,
    syncConflictReason = syncConflictReason,
)

fun RecurrenceRuleDto.toDomain(): Recurrence = Recurrence(
    freq = freq.toRecurrenceFreq(),                     // unknown -> UNKNOWN, never throws
    interval = interval,
    untilUtc = untilUtc,
    count = count,
    byDay = byday.orEmpty(),
    byMonthDay = bymonthday.orEmpty(),
    bySetPos = bysetpos.orEmpty(),
)

private fun String?.toRecurrenceFreq(): RecurrenceFreq = when (this?.uppercase()) {
    "DAILY" -> RecurrenceFreq.DAILY
    "WEEKLY" -> RecurrenceFreq.WEEKLY
    "MONTHLY" -> RecurrenceFreq.MONTHLY
    else -> RecurrenceFreq.UNKNOWN
}
// analogous CalendarDto.toDomain(), OccurrenceOverrideDto.toDomain().
// NOTE: no start/end reconciliation is needed for timed events — `start_utc` is
// nullable on EventOut and simply maps to a nullable `startAt`. There is no RSVP
// or visibility mapping (those concepts do not exist in the backend).
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
the cookie session + `X-CSRF-Token` (mutations). Shapes below are **verified**
against the OpenAPI index/spec (`CalendarOut`, `EventOut`, `RecurrenceRule`,
`EventsPageOut`) and `frontend/src/api/endpoints/calendar.ts` + `types.ts`.

> **CORRECTED 2026-06-06.** The prior Section 5 used invented flat paths
> (`calendars`, `calendar/events`), invented fields (`title`, `start_at`,
> `visibility`, `rsvp`, `start_date`/`end_date`, `next_page`, raw `rrule`), and a
> nonexistent RSVP endpoint. All replaced with the real contract below.

### GET `ui/calendars?limit=50`
Response `200` — array of `CalendarOut`:
```json
[
  { "calendar_id": "cal_55", "name": "Team On-call", "timezone": "America/New_York",
    "owner_user_id": "usr_7", "conflict_detection": true,
    "buffer_before_minutes": 0, "buffer_after_minutes": 0,
    "created_at_utc": "2026-05-01T12:00:00Z" }
]
```

### GET `ui/calendars/{calendar_id}/events?start_utc=…&end_utc=…&limit=…&cursor=…`
All four query params optional (web client typically sends only `cursor`).
Response `200` — `EventsPageOut`:
```json
{
  "events": [
    {
      "event_id": "evt_91", "calendar_id": "cal_55", "name": "Sprint review",
      "description": "", "timezone": "America/New_York",
      "start_utc": "2026-06-10T17:00:00Z", "end_utc": "2026-06-10T18:00:00Z",
      "all_day": false, "attendees": ["usr_7","usr_8"],
      "booking_enabled": false, "approval_required": false, "status": "confirmed",
      "created_at_utc": "2026-06-05T12:00:00Z"
    },
    {
      "event_id": "evt_92", "calendar_id": "cal_55", "name": "Standup",
      "description": "", "timezone": "America/New_York",
      "start_utc": "2026-06-08T13:00:00Z", "end_utc": "2026-06-08T13:15:00Z",
      "all_day": false, "attendees": [], "booking_enabled": false,
      "approval_required": false, "status": "confirmed",
      "recurrence_rule": {
        "freq": "WEEKLY", "interval": 1, "byday": ["MO","TU","WE","TH","FR"],
        "until_utc": "2026-07-31T13:00:00Z"
      },
      "exdates_utc": ["2026-06-19T13:00:00Z"],
      "created_at_utc": "2026-06-01T09:00:00Z"
    },
    {
      "event_id": "evt_93", "calendar_id": "cal_55", "name": "Company holiday",
      "description": "", "timezone": "America/New_York",
      "all_day": true, "all_day_date": "2026-07-03",
      "attendees": [], "booking_enabled": false, "approval_required": false,
      "status": "confirmed", "created_at_utc": "2026-06-01T09:00:00Z"
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjUwfQ=="
}
```

### GET `ui/calendars/{calendar_id}/events/{event_id}`
Response `200`: a single `EventOut` (same shape as an `events[]` element).
`422` on validation; `404` if unknown.

### POST `ui/calendars/{calendar_id}/events?force=…`
Request — `EventCreateIn` (note: `name`, not `title`; `start_utc`, not `start_at`):
```json
{ "name": "1:1", "start_utc": "2026-06-12T15:00:00Z",
  "end_utc": "2026-06-12T15:30:00Z", "all_day": false }
```
Response `200` (NOT 201): the created `EventOut` (with server `event_id`).

### PATCH `ui/calendars/{calendar_id}/events/{event_id}`
Request: sparse `EventCreateIn` (only changed fields; web client passes
`Partial<EventCreateIn>`). Response `200`: updated `EventOut`.

### DELETE `ui/calendars/{calendar_id}/events/{event_id}`
Response `200` with an `OkResp` body (`api.del<OkResp>` in `calendar.ts`).
`422` on validation.

> **There is no RSVP endpoint.** The web app has no per-viewer RSVP concept for
> calendar events. Attendees are a flat `attendees: string[]`. (Removed the prior
> `POST .../rsvp` section entirely.)

**Error envelope (all endpoints):** FastAPI `HTTPValidationError` for `422`
(`{ "detail": [{ "loc": [...], "msg": "...", "type": "..." }] }`) and the
`detail` union (`string | [{msg,type,loc}] | {code,...}`) for other errors — see
`normalizeErrorDetail` in `src/api/client.ts`. Mapping to typed `ApiError` is
owned by **AND-015**; this ticket lets non-2xx surface as `retrofit2.HttpException`.

## 6. Data & State Management

`CalendarApi` is **stateless** — a singleton interface proxy with no fields. This
ticket holds no `StateFlow`/`UiState`, no Room, no DataStore.

- **Session state** lives in cookies, persisted by the cookie jar (AND-011);
  `CalendarApi` never reads/writes cookies. CSRF (`ui_csrf` cookie → `X-CSRF-Token`
  header, verified in `src/api/client.ts`) is attached by AND-012 for mutating
  verbs (`POST`/`PATCH`/`DELETE`).
- **Serialization:** request/response (de)serialization uses Moshi codegen
  adapters (KSP) + the shared `InstantJsonAdapter` via the shared converter.
  Unknown JSON keys are ignored; absent optional fields fall back to Kotlin
  defaults (lenient). Unknown enum strings map to `UNKNOWN`/`PENDING` in mappers,
  not at the adapter level.
- **Domain mapping** is the one transformation this ticket performs:
  DTO→`core-model` via pure `toDomain()` functions. Callers (`core-data`
  repositories) decide whether to wrap in `ApiResult<T>` (AND-018), cache in Room,
  or expose via `StateFlow`. None of that is here.
- **Paging:** `listEvents` returns an `EventsPageDto` with a `next_cursor`
  cursor (verified: `EventsPageOut.next_cursor`); the actual Paging 3
  `PagingSource`/`RemoteMediator` is a downstream `core-data`/feature concern.
  This ticket only exposes the cursor-bearing call.
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
  optionals, unknown `freq` enums, timed-vs-all-day events where `start_utc` is
  absent and `all_day_date` is present) never throws. <!-- CORRECTED: `start_utc`
  is legitimately nullable on EventOut (all-day events), so a missing start is NOT
  a malformed payload and the mapper must NOT `error(...)` on it. The original
  "event with no start at all → error()" rule is wrong. --> A genuinely
  contract-violating payload (e.g. an EventOut missing the required `event_id`,
  `calendar_id`, `name`, `timezone`, or `created_at_utc`) fails at the Moshi
  adapter as a `JsonDataException`, surfaced to callers for AND-015/AND-018.
- **Recurrence safety:** an event with a `recurrence_rule` object whose `freq` is
  unknown is still mapped (R-1) with `freq = UNKNOWN` and all structured fields
  preserved; recurrence is never silently dropped. (There is no raw `rrule` string
  to synthesize — recurrence is fully structured.)
- This ticket maps **no** errors to user-facing types itself — that is AND-015
  (`ApiError`) / AND-018 (`ApiResult`).

## 8. Security & Privacy

- **Authenticated surface:** all calendar endpoints require the cookie session
  established by the auth flow (AND-027 family). `CalendarApi` adds no manual
  `Cookie`/`Authorization` headers; identity is carried implicitly by the jar.
- **CSRF:** mutating verbs (`POST`/`PATCH`/`DELETE`, i.e. `createCalendar`,
  `updateCalendar`, `deleteCalendar`, `createEvent`, `updateEvent`, `deleteEvent`)
  rely on AND-012 to attach `X-CSRF-Token` (read from the `ui_csrf` cookie, as the
  web client does in `src/api/client.ts`); without it they may fail against a real
  backend (R-4). <!-- CORRECTED: removed `setRsvp` (no such endpoint). -->
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
- **Scope:** event operations act only within calendars the principal can see /
  has been shared (server-enforced by the cookie-scoped identity; sharing is
  `read`/`write` per `CalendarShare`).

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
- **No analytics events** emitted by this layer. Calendar-view and event-open
  analytics are emitted by the consuming feature ViewModels (their own tickets),
  derived from `ApiResult` outcomes — and must follow the AND-052 redaction policy
  (no event names/descriptions/ids beyond anonymized form), mirroring AND-138's
  telemetry rules.
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

> **CORRECTED 2026-06-06.** Test descriptions below now use the real paths
> (`/ui/calendars...`), field names (`name`/`start_utc`/`next_cursor`/`event_id`),
> and the structured recurrence. T-10 (RSVP) is replaced with a calendar-delete
> test since no RSVP endpoint exists.

**T-1 — `listCalendars`** issues `GET /ui/calendars`, decodes `List<CalendarDto>`;
asserts `calendarId`/`name`/`timezone`/`ownerUserId` map.

**T-2 — `listEvents` query.**
```kotlin
@Test fun listEvents_sendsQueryAndDecodes() = runTest {
    val server = MockWebServer().apply {
        enqueue(MockResponse().setBody(EVENTS_PAGE_JSON)); start()
    }
    val resp = api(server).listEvents(
        calendarId = "cal_55", startUtc = "2026-06-08T00:00:00Z",
        endUtc = "2026-06-15T00:00:00Z", cursor = "abc")
    val req = server.takeRequest()
    assertEquals("GET", req.method)
    val url = req.requestUrl!!
    assertEquals("/ui/calendars/cal_55/events", url.encodedPath)
    assertEquals("2026-06-08T00:00:00Z", url.queryParameter("start_utc"))
    assertEquals("abc", url.queryParameter("cursor"))
    assertEquals("eyJvZmZzZXQiOjUwfQ==", resp.nextCursor)
    assertEquals(3, resp.events.size)
    server.shutdown()
}
```

**T-3 — recurrence mapping (KEY).** `EVENTS_PAGE_JSON.events[1]` (weekly rule) maps
to a `CalendarEvent` whose `recurrence` has `freq == WEEKLY`,
`byDay == ["MO","TU","WE","TH","FR"]`, `untilUtc` parsed to the right `Instant`,
and whose event-level `exDatesUtc.size == 1`. Recurrence is never null/dropped.

**T-4 — all-day mapping.** `events[2]` (`all_day:true`, `all_day_date`, no
`start_utc`) maps to `allDay == true`, non-null `allDayDate` (`LocalDate`), and a
null `startAt`; no off-by-one and no error thrown for the absent `start_utc`.

**T-5 — enum/optional tolerance.** unknown `freq:"HOURLY"` → `RecurrenceFreq.UNKNOWN`;
missing `category` → null; missing `recurrence_rule` → null. No throw.

**T-6 — `getEvent`** issues `GET /ui/calendars/cal_55/events/evt_91` (both path
params) and decodes a single event.

**T-7 — `createEvent`** issues `POST /ui/calendars/cal_55/events` with a JSON body
containing `name`, `start_utc`; decodes the returned event with server `event_id`.

**T-8 — `updateEvent`** issues `PATCH /ui/calendars/cal_55/events/evt_91` with a
**sparse** body (only the changed field serialized; nulls omitted) and decodes the
response.

**T-9 — `deleteEvent`** issues `DELETE /ui/calendars/cal_55/events/evt_91` and
decodes the `OkResp` body (e.g. `{"ok":true}` → `OkRespDto(ok = true)`).

**T-10 — `deleteCalendar`** issues `DELETE /ui/calendars/cal_55` and decodes the
`OkResp` body. (Replaces the obsolete RSVP test — no RSVP endpoint exists.)

**T-11 — error propagation.** A `401` from `listEvents` throws
`retrofit2.HttpException` with `code() == 401` (non-2xx not swallowed, leaving room
for AND-013/AND-015); a `422` from `createEvent` carries the
`HTTPValidationError` body for AND-015.

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

**Sequencing within the ticket:** (1) endpoint set, paths, and field names are now
confirmed against the OpenAPI index + `calendar.ts` (see §16); (2) define `core-model` domain
types; (3) define DTOs + codegen adapters; (4) write `CalendarMappers.kt`;
(5) declare `CalendarApi`; (6) add `CalendarApiModule`; (7) write tests T-1..T-11.

## 13. Risks & Open Questions

- **R-1 Recurrence representation.** RESOLVED: the backend uses a fully structured
  `RecurrenceRule` (`freq`/`interval`/`until_utc`/`count`/`byday`/`bymonthday`/
  `bysetpos`) — there is no raw `rrule` string. Exception dates and per-occurrence
  edits live at the EVENT level (`exdates_utc`, `recurrence_overrides`). Mapper
  preserves every field; unknown `freq` → `UNKNOWN`. Guarded by T-3/T-5. No
  recurrence expansion in this ticket.
- **R-2 Paging shape.** RESOLVED: `listEvents` returns the `EventsPageOut` envelope
  `{ events, next_cursor }`; the list is per-calendar (path), with optional
  `start_utc`/`end_utc`/`limit`/`cursor` query params. Guarded by T-2.
- **R-3 All-day timestamps.** RESOLVED: all-day events set `all_day:true` with a
  single `all_day_date` (ISO date) and omit `start_utc`; timed events use
  `start_utc`/`end_utc` (UTC `Z`). Mapper derives `LocalDate` for all-day and leaves
  `startAt` null. Guarded by T-4. Open: server-side semantics of all-day end
  boundary (inclusive vs exclusive) are unverified from the schema — see §16.
- **R-4 CSRF on mutations.** If AND-012's interceptor is absent, `create`/`update`/
  `delete` (calendar and event) may fail end-to-end. Unit tests (MockWebServer) are
  unaffected.
- **R-5 Type duplication with AND-138.** Until AND-138 migrates to these canonical
  types, the provisional copies coexist. Mitigation: land canonical types in
  `core-model` here; track AND-138 migration as the follow-up.
- **Q-1** Endpoint paths — RESOLVED: events are nested under a calendar at
  `ui/calendars/{calendar_id}/events`; calendars at `ui/calendars`. There is no flat
  `calendar/events`.
- **Q-2** Scope of the per-occurrence / sharing / conflict / booking endpoints
  (`.../occurrences/...`, `.../shares`, `.../events/conflicts`,
  `.../events/suggestions`, `availability`, booking links) — they exist in
  `calendar.ts` but are NOT in this ticket's backlog scope (`events, recurrence`).
  *Proposed:* land core calendar+event CRUD here; track the rest as follow-ups.
- **Q-3** `deleteEvent`/`deleteCalendar` return body — RESOLVED: an `OkResp`
  (`{ ok: true }`-style), per `api.del<OkResp>` in `calendar.ts`. Guarded by T-9/T-10.
- **Q-4** Create-event response code — RESOLVED: `200` with `EventOut` (NOT `201`),
  per OpenAPI `POST /ui/calendars/{calendar_id}/events resp=200:EventOut`.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Calendar payloads map (tested): every calendar JSON shape in
  Section 5 — including the recurring event and the all-day event — decodes via the
  production Moshi config and maps losslessly into the `core-model` domain types,
  proven by mapper unit tests (T-3, T-4, T-5).
- **AC-2.** `CalendarApi` declares the calendar operations (`listCalendars`,
  `getCalendar`, `createCalendar`, `updateCalendar`, `deleteCalendar`,
  `listEvents`, `getEvent`, `createEvent`, `updateEvent`, `deleteEvent`) and the
  module compiles against the new DTOs and `core-model` types. <!-- CORRECTED:
  removed `setRsvp`; added the calendar CRUD operations that exist in calendar.ts. -->
- **AC-3.** Each endpoint is callable and its **verb + resolved path + query/body**
  match Section 5, asserted with MockWebServer (T-1, T-2, T-6..T-10).
- **AC-4.** `listEvents` serializes `start_utc`/`end_utc`/`limit`/`cursor` query
  params (under the per-calendar path) and decodes the paged
  `{events, next_cursor}` envelope (T-2).
- **AC-5.** Recurrence is preserved end-to-end: structured
  `freq`/`interval`/`byDay`/`untilUtc`/`count`/`byMonthDay`/`bySetPos` mapped, plus
  event-level `exDatesUtc`, recurrence never dropped (T-3).
- **AC-6.** All-day events map to `allDay=true` with a `LocalDate` `allDayDate` and
  a null `startAt`, with no off-by-one and no error thrown for the absent
  `start_utc` (T-4).
- **AC-7.** Unknown enum strings (`freq`) and missing optional fields map to
  `UNKNOWN`/defaults without throwing (T-5).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source. Sources are
the OpenAPI index (`reference/openapi.index.txt`), the OpenAPI spec
(`reference/openapi.pretty.json` → `components.schemas.*`), and the frontend
(`reference/src/...`). "framework ref" labels Android/library framework choices.

1. **Calendar list endpoint is `GET /calendars`.** — **Corrected** → real path is
   `GET /ui/calendars`. Source: OpenAPI `GET /ui/calendars`
   (op=list_calendars_ui_calendars_get); `src/api/endpoints/calendar.ts: getCalendars`.
2. **Event list endpoint is a flat `GET /calendar/events` with a `calendar_id`
   query.** — **Corrected** → events are nested per-calendar:
   `GET /ui/calendars/{calendar_id}/events`; `calendar_id` is a path param, not a
   query. Source: OpenAPI `GET /ui/calendars/{calendar_id}/events`
   (resp=200:EventsPageOut); `src/api/endpoints/calendar.ts: getEvents`.
3. **List-events query params are `from`/`to`/`calendar_id`/`page`.** —
   **Corrected** → `start_utc`/`end_utc`/`limit`/`cursor` (all optional). Source:
   OpenAPI index line `params=start_utc,end_utc,limit,cursor,...`;
   `src/api/endpoints/calendar.ts: getEvents` sends only `cursor`.
4. **Paged response is `{ items, next_page }` (`EventRangeRespDto`).** —
   **Corrected** → `{ events, next_cursor }`. Source: OpenAPI
   `components.schemas.EventsPageOut` (`events`, `next_cursor`);
   `src/api/types.ts: EventsPage`.
5. **Single-event / mutate paths are `calendar/events/{eventId}`.** — **Corrected**
   → `ui/calendars/{calendar_id}/events/{event_id}` (both path params). Source:
   OpenAPI `GET|PATCH|DELETE /ui/calendars/{calendar_id}/events/{event_id}`;
   `src/api/endpoints/calendar.ts: getEvent/updateEvent/deleteEvent`.
6. **Create event verb/path `POST calendar/events`, response `201`.** —
   **Corrected** → `POST /ui/calendars/{calendar_id}/events`, response **`200`**
   with `EventOut`. Source: OpenAPI `POST /ui/calendars/{calendar_id}/events`
   (resp=200:EventOut; params include `force`); `calendar.ts: createEvent`.
7. **Update verb is `PATCH`.** — **Verified.** Source: OpenAPI
   `PATCH /ui/calendars/{calendar_id}/events/{event_id}` (req=EventUpdateIn);
   `calendar.ts: updateEvent` (`api.patch`, `Partial<EventCreateIn>`).
8. **A `POST .../{eventId}/rsvp` endpoint exists and events carry an `rsvp`
   field.** — **Corrected (removed).** No RSVP endpoint or field exists anywhere.
   Source: absent from OpenAPI index (grep `calendar` shows no `/rsvp`); absent from
   `src/api/endpoints/calendar.ts`; `EventOut`/`CalendarEvent` have no `rsvp` field.
9. **`deleteEvent` returns empty body (`Unit`).** — **Corrected** → returns an
   `OkResp` body. Source: `src/api/endpoints/calendar.ts: deleteEvent`
   (`api.del<OkResp>`); `src/api/types.ts: OkResp`.
10. **Event fields `title`, `location`, `start_at`, `end_at`, `visibility`,
    `recurring_event_id`, `updated_at`, `start_date`/`end_date`.** — **Corrected** →
    actual EventOut fields: `event_id`, `calendar_id`, `name`, `description`
    (required), `timezone` (required), `start_utc`, `end_utc`, `all_day`,
    `all_day_date` (single), `attendees`, `booking_enabled`, `approval_required`,
    `status`, `category`, `recurrence_rule`, `exdates_utc`, `recurrence_overrides`,
    `created_at_utc`, `sync_state`, `sync_conflict_reason`. No `title`/`location`/
    `visibility`/`recurring_event_id`/`updated_at`. Source:
    `components.schemas.EventOut`; `src/api/types.ts: CalendarEvent`.
11. **Recurrence carries a raw `rrule` string plus structured fields, with
    in-recurrence `exdates`.** — **Corrected** → `RecurrenceRule` is fully
    structured with NO `rrule`: `freq` (enum DAILY|WEEKLY|MONTHLY), `interval`
    (default 1), `until_utc`, `count`, `byday`, `bymonthday`, `bysetpos`. Exception
    dates live at the EVENT level (`exdates_utc`); per-occurrence edits in
    `recurrence_overrides`. Source: `components.schemas.RecurrenceRule`;
    `src/api/types.ts: RecurrenceRule`.
12. **`RecurrenceFreq` includes `YEARLY`.** — **Corrected** → enum is only
    `DAILY | WEEKLY | MONTHLY`. Source: `components.schemas.RecurrenceRule.freq.enum`.
13. **`Calendar` carries `owner_display_name`, `permission`, `color`.** —
    **Corrected** → CalendarOut fields: `calendar_id`, `name`, `timezone`,
    `owner_user_id`, `conflict_detection`, `buffer_before_minutes`,
    `buffer_after_minutes`, `created_at_utc`, `working_hours`. No display name /
    permission / color on the calendar. Permission is on `CalendarShare`
    (`read`|`write`). Source: `components.schemas.CalendarOut`;
    `src/api/types.ts: Calendar` and `CalendarShare`.
14. **CSRF is the `ui_csrf` cookie sent as `X-CSRF-Token` on mutations.** —
    **Verified.** Source: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
15. **401 triggers a single session refresh + retry.** — **Verified** (delegated to
    AND-013). The web client refreshes via `POST /ui/session/refresh` then retries
    once. Source: `src/api/client.ts: refreshSession` + 401 branch.
16. **Error envelope is the FastAPI `detail` union; `422` is
    `HTTPValidationError`.** — **Verified.** Source: OpenAPI index
    (`resp=...;422:HTTPValidationError` on every calendar op);
    `src/api/client.ts: normalizeErrorDetail` handles `string | [{msg}] | {code}`.
17. **Base URL `http://18.222.237.167:8000/`, cleartext on dev.** —
    **Unverified-assumption.** Not derivable from the OpenAPI/frontend sources
    (the web client reads `VITE_API_BASE_URL` from env). Carried over from
    AND-006; treated as an AND-006 input, not re-verified here.
18. **Retrofit 2.11.0 / OkHttp 4.12.0 / Moshi 1.15.x codegen via KSP; suspend +
    Moshi converter.** — **framework ref** (Retrofit `@HTTP`/coroutine + Moshi
    codegen are standard). Versions are pins owned by AND-009/AND-010, not
    re-verified against an upstream catalog here.

### Corrections made

- **Paths:** `calendars` → `ui/calendars`; `calendar/events*` →
  `ui/calendars/{calendarId}/events*` (events nested under a calendar; `calendarId`
  is a path param). [§4.3, §5; cites 1,2,5]
- **RSVP removed entirely:** no `setRsvp` method, no `RsvpReqDto`, no `rsvp`/`RsvpStatus`
  on the model, no RSVP test, no RSVP mentions in §1/§6/§8/§10/§14. [cite 8]
- **List query params:** `from`/`to`/`calendar_id`/`page` → `start_utc`/`end_utc`/
  `limit`/`cursor`. [§3 FR-4, §4.3, §5, §14 AC-4; cite 3]
- **Paging envelope:** `{items,next_page}`/`EventRangeRespDto` →
  `{events,next_cursor}`/`EventsPageDto`. [§4.2, §5, §6; cite 4]
- **Event field names:** `title`→`name`, `start_at`/`end_at`→`start_utc`/`end_utc`,
  `start_date`/`end_date`→single `all_day_date`, dropped `location`/`visibility`/
  `recurring_event_id`/`updated_at`, added `attendees`/`status`/`category`/
  `booking_enabled`/`approval_required`/`exdates_utc`/`recurrence_overrides`/
  `created_at_utc`. [§4.1, §4.2, §4.4, §5; cite 10]
- **Recurrence:** removed raw `rrule` + synthesis logic; modeled the structured
  `RecurrenceRule`; moved `exdates` to event-level `exdates_utc`; removed `YEARLY`.
  [§3 FR-6, §4.1, §4.2, §4.4, §7, §13 R-1; cites 11,12]
- **Calendar shape:** dropped `owner_display_name`/`permission`/`color`; added
  `timezone`/`owner_user_id`/`conflict_detection`/buffers/`created_at_utc`; added
  calendar CRUD methods. [§4.1, §4.2, §4.3, §5, §14 AC-2; cite 13]
- **Delete return:** `Unit`/empty → `OkRespDto`. [§4.3, §5, §11 T-9/T-10; cite 9]
- **Create response code:** `201` → `200`. [§5, §13 Q-4; cite 6]
- **Mapper safety:** removed the wrong `error(...)`-on-missing-start rule
  (`start_utc` is legitimately null for all-day). [§4.4, §7; cite 10]

### Open assumptions

- **Auth scheme of the Android port (bearer vs pure-cookie).** The web client
  sends BOTH `Authorization: Bearer <accessToken>` and the cookie session, and the
  OpenAPI calendar ops also declare `authorization`/`X-SESSION-ID` params. This spec
  delegates auth wholly to AND-027/AND-011/AND-012/AND-013, so the exact header set
  is not pinned here. Unverifiable from this ticket's scope — it is an AND-027
  decision. (cite: `src/api/client.ts`; OpenAPI index `params=...,X-SESSION-ID`)
- **Base URL / cleartext dev host.** See citation 17 — an AND-006 input, not
  derivable from the OpenAPI/frontend sources.
- **All-day end-boundary semantics** (is `all_day_date` a single day, or is there an
  implicit exclusive end?). The schema exposes only a single `all_day_date`; the
  inclusive/exclusive boundary is a server behavior not described by the schema.
  Flagged in §13 R-3; the mapper does not assume an end date.
- **`status`/`category` value domains.** `EventOut.status` is a free-form string in
  the schema (no enum); the domain model keeps it as `String`. Unverifiable list of
  allowed values from the sources.
- **Library version pins** (Retrofit/OkHttp/Moshi/AGP/Gradle). Inherited from
  AND-009/AND-010; not re-verified against an upstream version catalog.

## 17. Test Plan

Test IDs `TC-AND-270-NN`. This is a headless transport+serialization ticket, so the
bulk runs as **JVM unit / contract (MockWebServer)** with no device. The Hilt-graph
case and the real-dev-host smoke are the only ones that touch a device/emulator;
none of this ticket's behavior is hardware-dependent (no camera/biometrics/WebRTC/
FCM), so the **physical Samsung A15 (SM-A156U, API 34)** is used only for the
real-network dev-host smoke (to exercise true cleartext HTTP + flaky-host timeouts
on arm64/API-34), while the **emulator AVD `test35` (API 35)** covers the
instrumented Hilt graph.

Test targets per case: **JVM** = JVM unit/Robolectric (local); **MWS** =
contract/MockWebServer (local JVM); **emu(test35)** = headless API-35 emulator;
**device(A15)** = physical Samsung A15 over adb.

- **TC-AND-270-01 — listEvents happy path + query + decode.** Type:
  contract/MWS. Target: MWS. Preconditions: `EVENTS_PAGE_JSON` (3 events: timed,
  recurring, all-day) enqueued `200`. Steps: call
  `listEvents("cal_55", startUtc, endUtc, limit=50, cursor="abc")`; capture request.
  Expected: method `GET`; path `/ui/calendars/cal_55/events`; query `start_utc`,
  `end_utc`, `limit=50`, `cursor=abc` present; decodes to `EventsPageDto` with
  3 events and `nextCursor`. Traces: AC-3, AC-4.

- **TC-AND-270-02 — listCalendars decode.** Type: contract/MWS. Target: MWS.
  Preconditions: array-of-`CalendarOut` body enqueued `200`. Steps: call
  `listCalendars(limit=50)`. Expected: `GET /ui/calendars?limit=50`; decodes a
  `List<CalendarDto>`; `calendarId`/`name`/`timezone`/`ownerUserId` mapped. Traces:
  AC-2, AC-3.

- **TC-AND-270-03 — recurrence mapping (KEY).** Type: unit (mapper). Target: JVM.
  Preconditions: `events[1]` (weekly rule, event-level `exdates_utc`). Steps:
  `CalendarEventDto.toDomain()`. Expected: `recurrence.freq == WEEKLY`,
  `interval == 1`, `byDay == [MO,TU,WE,TH,FR]`, `untilUtc` parsed to the correct
  `Instant`, `exDatesUtc.size == 1`; recurrence non-null. Traces: AC-1, AC-5.

- **TC-AND-270-04 — all-day mapping, no off-by-one.** Type: unit (mapper). Target:
  JVM. Preconditions: `events[2]` (`all_day:true`, `all_day_date:"2026-07-03"`, no
  `start_utc`). Steps: `toDomain()`. Expected: `allDay == true`,
  `allDayDate == LocalDate(2026-07-03)`, `startAt == null`, **no** exception thrown.
  Traces: AC-1, AC-6.

- **TC-AND-270-05 — enum/optional tolerance.** Type: unit (mapper). Target: JVM.
  Preconditions: DTOs with unknown `freq:"HOURLY"`, missing `category`, missing
  `recurrence_rule`, missing `attendees`. Steps: `toDomain()`. Expected:
  `freq == UNKNOWN`, `category == null`, `recurrence == null`,
  `attendees == []`; no throw. Traces: AC-1, AC-7.

- **TC-AND-270-06 — getEvent both path params.** Type: contract/MWS. Target: MWS.
  Preconditions: single `EventOut` enqueued `200`. Steps:
  `getEvent("cal_55","evt_91")`. Expected: `GET /ui/calendars/cal_55/events/evt_91`;
  decodes one event with `eventId == "evt_91"`. Traces: AC-3.

- **TC-AND-270-07 — createEvent body + 200.** Type: contract/MWS. Target: MWS.
  Preconditions: created `EventOut` enqueued `200`. Steps:
  `createEvent("cal_55", EventCreateReqDto(name="1:1", startUtc=..., endUtc=...))`.
  Expected: `POST /ui/calendars/cal_55/events`; JSON body contains `"name"` and
  `"start_utc"` (NOT `title`/`start_at`); response decoded with server `event_id`.
  Traces: AC-3.

- **TC-AND-270-08 — updateEvent sparse PATCH.** Type: contract/MWS. Target: MWS.
  Preconditions: updated `EventOut` enqueued `200`. Steps:
  `updateEvent("cal_55","evt_91", EventUpdateReqDto(name="renamed"))`. Expected:
  `PATCH /ui/calendars/cal_55/events/evt_91`; body serializes only `"name"`
  (null fields omitted — verifies Moshi omits nulls / sparse update); decodes
  response. Traces: AC-3.

- **TC-AND-270-09 — deleteEvent OkResp.** Type: contract/MWS. Target: MWS.
  Preconditions: `{"ok":true}` enqueued `200`. Steps: `deleteEvent("cal_55","evt_91")`.
  Expected: `DELETE /ui/calendars/cal_55/events/evt_91`; decodes
  `OkRespDto(ok=true)` (does NOT assume an empty body). Traces: AC-3.

- **TC-AND-270-10 — 401 propagation (not swallowed).** Type: contract/MWS. Target:
  MWS. Preconditions: `401` enqueued for `listEvents`. Steps: call + expect throw.
  Expected: `retrofit2.HttpException` with `code() == 401`; raw body preserved for
  AND-013/AND-015 (this layer does not retry/refresh). Traces: AC-8.

- **TC-AND-270-11 — 422 validation error shape.** Type: contract/MWS. Target: MWS.
  Preconditions: `422` with `HTTPValidationError` body
  (`{"detail":[{"loc":["body","name"],"msg":"field required","type":"missing"}]}`)
  enqueued for `createEvent`. Steps: call + expect throw. Expected:
  `HttpException` `code() == 422`; `errorBody()` contains the `detail[].msg` so
  AND-015 can map it. Traces: AC-8.

- **TC-AND-270-12 — security: no per-method CSRF/cookie/auth headers; redaction.**
  Type: unit (reflection/source) + contract/MWS. Target: JVM/MWS. Preconditions:
  inspect `CalendarApi` annotations; enqueue a mutation. Steps: assert no method
  declares `@Header("X-CSRF-Token")`/`@Header("Cookie")`/`@Header("Authorization")`
  (headers are global, AND-011/AND-012); and confirm `@Headers` only set
  `Content-Type`. Expected: interface is header-agnostic; no event `name`/
  `description` appears in any log (redaction policy). Traces: AC-9, plus §8 security.

- **TC-AND-270-13 — Hilt provider singleton on shared Retrofit.** Type:
  instrumented (`@HiltAndroidTest`). Target: **emu(test35)**. Preconditions: test
  app graph with AND-010 `NetworkModule`. Steps: inject `CalendarApi` twice.
  Expected: non-null; same instance on repeated injection; built from the shared
  `Retrofit` (no second `OkHttpClient`/`Retrofit`). Note: runs on the emulator
  (fast, no hardware dependency). Traces: AC-9.

- **TC-AND-270-14 — real dev-host smoke + flaky/offline path.** Type:
  integration/e2e (manual-assisted). Target: **device(A15)** — MUST run on the
  physical device to exercise real cleartext HTTP over the network against the
  unreliable dev host on arm64/API-34. Preconditions: a valid cookie session
  (AND-027) on the device; `BuildConfig.API_BASE_URL = http://18.222.237.167:8000/`.
  Steps: (a) `listCalendars` then `listEvents` and confirm real decode; (b) enable
  airplane mode and repeat. Expected: (a) live `200` decodes into domain types;
  (b) offline raises `UnknownHostException`/`SocketTimeoutException` propagated
  unchanged (no crash, no retry storm), confirming AND-009 timeouts/AND-016 backoff
  behavior on idempotent GETs. Traces: AC-3, AC-8 (transport-failure resilience,
  §7).

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (payloads map, tested) | TC-03, TC-04, TC-05 |
| AC-2 (operations declared, compiles) | TC-01, TC-02 |
| AC-3 (verb+path+query/body) | TC-01, TC-02, TC-06, TC-07, TC-08, TC-09, TC-14 |
| AC-4 (list query + paged envelope) | TC-01 |
| AC-5 (recurrence preserved) | TC-03 |
| AC-6 (all-day, no off-by-one) | TC-04 |
| AC-7 (unknown enum/missing optional tolerance) | TC-05 |
| AC-8 (non-2xx surfaces, not swallowed) | TC-10, TC-11, TC-14 |
| AC-9 (Hilt singleton; no extra client; no per-method headers) | TC-12, TC-13 |
| AC-10 (CI build/tests green, lint/detekt clean) | all TCs run in CI (TC-13 on emu(test35); TC-14 device smoke is out-of-CI manual) |
