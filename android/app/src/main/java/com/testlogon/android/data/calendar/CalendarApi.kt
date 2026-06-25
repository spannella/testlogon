package com.testlogon.android.data.calendar

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-270 — Retrofit interface for the authenticated calendar domain.
 *
 * Verified against reference/src/api/endpoints/calendar.ts + openapi.index.txt. Paths are relative
 * (no leading slash) so they resolve against the shared Retrofit base URL; cookies / Authorization /
 * X-CSRF-Token are attached by the core-network interceptor chain (this interface stays header-agnostic
 * apart from Content-Type on bodies). All reads are idempotent GETs.
 *
 * KEY FACTS:
 *  - calendars live at `ui/calendars`; events are NESTED under a calendar at
 *    `ui/calendars/{calendar_id}/events` — `calendar_id` is a PATH param, never a query.
 *  - list_events query params are `start_utc`/`end_utc`/`limit`/`cursor` (all optional; the web client
 *    typically sends only `cursor`). Pagination is the `next_cursor` cursor envelope (EventsPageOut).
 *  - there is NO RSVP endpoint and NO flat "list events in a range" call.
 *  - deletes return an OkResp body (`{ ok: true }`), NOT an empty body.
 *  - createEvent responds 200 (not 201) and supports an optional `force` flag.
 */
interface CalendarApi {

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
        @Body body: CalendarCreateReqDto,
    ): CalendarDto

    @DELETE("ui/calendars/{calendarId}")
    suspend fun deleteCalendar(@Path("calendarId") calendarId: String): OkRespDto

    @GET("ui/calendars/{calendarId}/events")
    suspend fun listEvents(
        @Path("calendarId") calendarId: String,
        @Query("start_utc") startUtc: String? = null,
        @Query("end_utc") endUtc: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): EventsPageDto

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
        @Query("force") force: Boolean? = null,
    ): CalendarEventDto

    @Headers("Content-Type: application/json")
    @PATCH("ui/calendars/{calendarId}/events/{eventId}")
    suspend fun updateEvent(
        @Path("calendarId") calendarId: String,
        @Path("eventId") eventId: String,
        @Body body: EventCreateReqDto,
    ): CalendarEventDto

    @DELETE("ui/calendars/{calendarId}/events/{eventId}")
    suspend fun deleteEvent(
        @Path("calendarId") calendarId: String,
        @Path("eventId") eventId: String,
    ): OkRespDto

    /**
     * #13 ("This event only") - excludes a single occurrence of a recurring event by appending its UTC
     * start to the event's `exdates_utc` (the master series + recurrence rule are untouched). Returns
     * the updated master EventOut. [occurrenceStart] is the ISO-8601 UTC start of the tapped instance
     * (Retrofit URL-encodes the ':' in the path segment; FastAPI decodes it back).
     */
    @POST("ui/calendars/{calendarId}/events/{eventId}/occurrences/{occurrenceStart}/exclude")
    suspend fun excludeOccurrence(
        @Path("calendarId") calendarId: String,
        @Path("eventId") eventId: String,
        @Path("occurrenceStart") occurrenceStart: String,
    ): CalendarEventDto
}

/**
 * AND-272 — the public, unauthenticated single-event endpoint (a separate interface so it can be
 * driven without a session, mirroring web `getPublicEvent`). Path params only; reduced payload.
 *
 * `GET calendar/public/event/{calendar_id}/{event_id}` -> CalendarEventAttachment.
 */
interface PublicEventApi {

    @GET("calendar/public/event/{calendarId}/{eventId}")
    suspend fun getPublicEvent(
        @Path("calendarId") calendarId: String,
        @Path("eventId") eventId: String,
    ): PublicEventDto
}
