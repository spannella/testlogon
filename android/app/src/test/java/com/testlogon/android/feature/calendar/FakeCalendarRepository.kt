package com.testlogon.android.feature.calendar

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.calendar.Calendar
import com.testlogon.android.data.calendar.CalendarEvent
import com.testlogon.android.data.calendar.CalendarRepository
import com.testlogon.android.data.calendar.EventCreateReqDto
import com.testlogon.android.data.calendar.EventsPage
import java.time.Instant

/**
 * AND-271/AND-272 — pure-JVM fake [CalendarRepository] for ViewModel tests. Records the requested
 * args (so the VM's request shaping can be asserted) and returns scripted results.
 */
class FakeCalendarRepository : CalendarRepository {

    var calendarsResult: ApiResult<List<Calendar>> = ApiResult.Success(listOf(sampleCalendar()))
    var eventsResult: ApiResult<EventsPage> = ApiResult.Success(EventsPage())
    var eventResult: ApiResult<CalendarEvent> = ApiResult.Success(sampleEvent("evt_1"))
    var publicEventResult: ApiResult<CalendarEvent> = ApiResult.Success(sampleEvent("evt_1", isPublic = true))

    var lastEventsStartUtc: String? = null
    var lastEventsEndUtc: String? = null
    var lastEventCalendarId: String? = null
    var lastEventId: String? = null
    var eventCalls = 0
    var publicEventCalls = 0

    var createResult: ApiResult<CalendarEvent> = ApiResult.Success(sampleEvent("evt_new"))
    var updateResult: ApiResult<CalendarEvent> = ApiResult.Success(sampleEvent("evt_1"))
    var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var lastCreateBody: EventCreateReqDto? = null
    var lastUpdateBody: EventCreateReqDto? = null
    var lastDeletedEventId: String? = null
    var createCalls = 0
    var updateCalls = 0
    var deleteCalls = 0

    override suspend fun calendars(limit: Int?): ApiResult<List<Calendar>> = calendarsResult

    override suspend fun events(
        calendarId: String,
        startUtc: String?,
        endUtc: String?,
        limit: Int?,
        cursor: String?,
    ): ApiResult<EventsPage> {
        lastEventsStartUtc = startUtc
        lastEventsEndUtc = endUtc
        return eventsResult
    }

    override suspend fun event(calendarId: String, eventId: String): ApiResult<CalendarEvent> {
        eventCalls++
        lastEventCalendarId = calendarId
        lastEventId = eventId
        // Stamp the requested id onto the returned object when the result is a success placeholder.
        return when (val r = eventResult) {
            is ApiResult.Success -> ApiResult.Success(r.data.copy(eventId = eventId, calendarId = calendarId))
            else -> r
        }
    }

    override suspend fun publicEvent(calendarId: String, eventId: String): ApiResult<CalendarEvent> {
        publicEventCalls++
        return when (val r = publicEventResult) {
            is ApiResult.Success ->
                ApiResult.Success(r.data.copy(eventId = eventId, calendarId = calendarId, isPublic = true))
            else -> r
        }
    }

    override suspend fun createEvent(
        calendarId: String,
        body: EventCreateReqDto,
    ): ApiResult<CalendarEvent> {
        createCalls++
        lastEventCalendarId = calendarId
        lastCreateBody = body
        return createResult
    }

    override suspend fun updateEvent(
        calendarId: String,
        eventId: String,
        body: EventCreateReqDto,
    ): ApiResult<CalendarEvent> {
        updateCalls++
        lastEventCalendarId = calendarId
        lastEventId = eventId
        lastUpdateBody = body
        return updateResult
    }

    override suspend fun deleteEvent(calendarId: String, eventId: String): ApiResult<Unit> {
        deleteCalls++
        lastEventCalendarId = calendarId
        lastDeletedEventId = eventId
        return deleteResult
    }

    companion object {
        fun sampleCalendar(id: String = "cal_55") = Calendar(
            calendarId = id, name = "Team", timezone = "UTC", ownerUserId = "usr_1",
        )

        fun sampleEvent(id: String, isPublic: Boolean = false) = CalendarEvent(
            eventId = id,
            calendarId = "cal_55",
            name = "Sprint review",
            description = "Plan the sprint",
            timezone = "America/New_York",
            startAt = Instant.parse("2026-06-10T17:00:00Z"),
            endAt = Instant.parse("2026-06-10T18:00:00Z"),
            attendees = listOf("usr_7", "usr_8"),
            isPublic = isPublic,
        )
    }
}
