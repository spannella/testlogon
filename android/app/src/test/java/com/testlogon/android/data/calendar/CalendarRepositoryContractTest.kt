package com.testlogon.android.data.calendar

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-270 / AND-272 — MockWebServer contract tests for [CalendarRepositoryImpl]. Verifies verb/path/
 * query for ui/calendars + ui/calendars/{id}/events(/{eventId}) and the public event endpoint, the
 * EventsPageOut envelope + next_cursor, the 404 -> list-endpoint fallback for the single event, and
 * error mapping. Uses plain Moshi (no Instant adapter needed — DTOs keep ISO strings).
 */
class CalendarRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): CalendarRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return CalendarRepositoryImpl(
            api = retrofit.create(CalendarApi::class.java),
            publicApi = retrofit.create(PublicEventApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun calendars_decodes_andRequestLine() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """[{"calendar_id":"cal_55","name":"Team On-call","timezone":"America/New_York",
                   "owner_user_id":"usr_7","conflict_detection":true,"buffer_before_minutes":0,
                   "buffer_after_minutes":0,"created_at_utc":"2026-05-01T12:00:00Z"}]""",
            ),
        )
        val result = repo().calendars(limit = 50)
        assertTrue(result is ApiResult.Success)
        assertEquals("cal_55", (result as ApiResult.Success).data.single().calendarId)
        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/calendars", req.requestUrl?.encodedPath)
        assertEquals("50", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun events_sendsDateRangeQuery_decodesPage() = runTest {
        backend.enqueue(Fixtures.okBody(EVENTS_PAGE_JSON))
        val result = repo().events(
            calendarId = "cal_55",
            startUtc = "2026-06-08T00:00:00Z",
            endUtc = "2026-06-15T00:00:00Z",
            cursor = "abc",
        )
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(3, page.events.size)
        assertEquals("eyJvZmZzZXQiOjUwfQ==", page.nextCursor)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/calendars/cal_55/events", req.requestUrl?.encodedPath)
        assertEquals("2026-06-08T00:00:00Z", req.requestUrl?.queryParameter("start_utc"))
        assertEquals("2026-06-15T00:00:00Z", req.requestUrl?.queryParameter("end_utc"))
        assertEquals("abc", req.requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun event_getsBothPathParams() = runTest {
        backend.enqueue(Fixtures.okBody(SINGLE_EVENT_JSON))
        val result = repo().event("cal_55", "evt_91")
        assertTrue(result is ApiResult.Success)
        assertEquals("evt_91", (result as ApiResult.Success).data.eventId)
        assertEquals("/ui/calendars/cal_55/events/evt_91", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun event_404_fallsBackToListEndpoint_andFilters() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        backend.enqueue(Fixtures.okBody(EVENTS_PAGE_JSON))
        val result = repo().event("cal_55", "evt_92")
        assertTrue(result is ApiResult.Success)
        assertEquals("evt_92", (result as ApiResult.Success).data.eventId)
        // First the GET, then the list fallback.
        assertEquals("/ui/calendars/cal_55/events/evt_92", backend.takeRequest().requestUrl?.encodedPath)
        assertEquals("/ui/calendars/cal_55/events", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun event_404_fallback_missingFromList_isNotFound() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        backend.enqueue(Fixtures.okBody("""{"events":[],"next_cursor":null}"""))
        val result = repo().event("cal_55", "evt_missing")
        assertTrue(result is ApiResult.Failure)
        assertEquals(404, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun publicEvent_decodesReduced_noAuthHeader() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"event_id":"evt_1","calendar_id":"cal_main","name":"Standup",
                   "start_utc":"2026-06-08T13:30:00Z","end_utc":"2026-06-08T14:00:00Z",
                   "all_day":false,"timezone":"America/New_York","description":"Daily sync","owner":"u-sam"}""",
            ),
        )
        val result = repo().publicEvent("cal_main", "evt_1")
        assertTrue(result is ApiResult.Success)
        val event = (result as ApiResult.Success).data
        assertTrue(event.isPublic)
        assertEquals("u-sam", event.owner)
        val req = backend.takeRequest()
        assertEquals("/calendar/public/event/cal_main/evt_1", req.requestUrl?.encodedPath)
        assertNull(req.getHeader("Authorization"))
    }

    @Test
    fun deleteEvent_decodesOkResp() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val retrofit = backend.retrofit(moshi)
        val api = retrofit.create(CalendarApi::class.java)
        val resp = api.deleteEvent("cal_55", "evt_91")
        assertTrue(resp.ok)
        assertEquals("DELETE", backend.takeRequest().method)
    }

    @Test
    fun createEvent_postsBody_with_name_and_start_utc() = runTest {
        backend.enqueue(Fixtures.okBody(SINGLE_EVENT_JSON))
        val api = backend.retrofit(moshi).create(CalendarApi::class.java)
        api.createEvent("cal_55", EventCreateReqDto(name = "1:1", startUtc = "2026-06-12T15:00:00Z"))
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/calendars/cal_55/events", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"name\""))
        assertTrue(body.contains("\"start_utc\""))
    }

    @Test
    fun events_401_mapsToFailure_notSwallowed() = runTest {
        backend.enqueue(MockResponse().setResponseCode(401).setBody("""{"detail":"unauthorized"}"""))
        val result = repo().events("cal_55")
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun events_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        assertTrue(repo().events("cal_55") is ApiResult.NetworkError)
    }

    private companion object {
        const val SINGLE_EVENT_JSON =
            """{"event_id":"evt_91","calendar_id":"cal_55","name":"Sprint review","description":"",
               "timezone":"America/New_York","start_utc":"2026-06-10T17:00:00Z",
               "end_utc":"2026-06-10T18:00:00Z","all_day":false,"attendees":["usr_7","usr_8"],
               "booking_enabled":false,"approval_required":false,"status":"confirmed",
               "created_at_utc":"2026-06-05T12:00:00Z"}"""

        const val EVENTS_PAGE_JSON =
            """{"events":[
               {"event_id":"evt_91","calendar_id":"cal_55","name":"Sprint review","description":"",
                "timezone":"America/New_York","start_utc":"2026-06-10T17:00:00Z",
                "end_utc":"2026-06-10T18:00:00Z","all_day":false,"attendees":["usr_7","usr_8"],
                "booking_enabled":false,"approval_required":false,"status":"confirmed",
                "created_at_utc":"2026-06-05T12:00:00Z"},
               {"event_id":"evt_92","calendar_id":"cal_55","name":"Standup","description":"",
                "timezone":"America/New_York","start_utc":"2026-06-08T13:00:00Z",
                "end_utc":"2026-06-08T13:15:00Z","all_day":false,"attendees":[],
                "booking_enabled":false,"approval_required":false,"status":"confirmed",
                "recurrence_rule":{"freq":"WEEKLY","interval":1,"byday":["MO","TU","WE","TH","FR"],
                "until_utc":"2026-07-31T13:00:00Z"},"exdates_utc":["2026-06-19T13:00:00Z"],
                "created_at_utc":"2026-06-01T09:00:00Z"},
               {"event_id":"evt_93","calendar_id":"cal_55","name":"Company holiday","description":"",
                "timezone":"America/New_York","all_day":true,"all_day_date":"2026-07-03",
                "attendees":[],"booking_enabled":false,"approval_required":false,"status":"confirmed",
                "created_at_utc":"2026-06-01T09:00:00Z"}
               ],"next_cursor":"eyJvZmZzZXQiOjUwfQ=="}"""
    }
}
