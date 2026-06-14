package com.testlogon.android.data.calendar

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-270 / AND-272 — data layer over [CalendarApi] + [PublicEventApi].
 *
 * Wraps each call in [ApiResult] (Failure for HTTP errors via [ApiErrorParser], NetworkError for
 * transport failures, Failure(parse) for malformed JSON), mapping wire DTOs to the redaction-safe
 * domain. Never throws (CancellationException is re-thrown). No Room cache in this slice.
 *
 * Single-event read (AND-272): the authenticated `GET .../events/{eventId}` is used by the web client
 * but is NOT documented in OpenAPI. So [event] tries the GET and, on a 404/405, FALLS BACK to the list
 * endpoint and filters by event id client-side (the list op IS documented). The public variant uses the
 * verified `calendar/public/event/{cal}/{evt}` endpoint.
 */
interface CalendarRepository {

    /** Calendars the principal can see (GET ui/calendars). */
    suspend fun calendars(limit: Int? = null): ApiResult<List<Calendar>>

    /**
     * One page of events for a calendar over an optional UTC date range (GET
     * ui/calendars/{id}/events). [startUtc]/[endUtc] are RFC-3339 strings; pagination via [cursor].
     */
    suspend fun events(
        calendarId: String,
        startUtc: String? = null,
        endUtc: String? = null,
        limit: Int? = null,
        cursor: String? = null,
    ): ApiResult<EventsPage>

    /** A single authenticated event, with a list-endpoint fallback when the GET is unavailable. */
    suspend fun event(calendarId: String, eventId: String): ApiResult<CalendarEvent>

    /** A single public (unauthenticated) event (reduced payload). */
    suspend fun publicEvent(calendarId: String, eventId: String): ApiResult<CalendarEvent>
}

@Singleton
class CalendarRepositoryImpl @Inject constructor(
    private val api: CalendarApi,
    private val publicApi: PublicEventApi,
    private val errorParser: ApiErrorParser,
) : CalendarRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun calendars(limit: Int?): ApiResult<List<Calendar>> = withContext(io) {
        call { api.listCalendars(limit) }.map { dtos -> dtos.map { it.toDomain() } }
    }

    override suspend fun events(
        calendarId: String,
        startUtc: String?,
        endUtc: String?,
        limit: Int?,
        cursor: String?,
    ): ApiResult<EventsPage> = withContext(io) {
        call { api.listEvents(calendarId, startUtc, endUtc, limit, cursor) }.map { it.toDomain() }
    }

    override suspend fun event(calendarId: String, eventId: String): ApiResult<CalendarEvent> =
        withContext(io) {
            when (val direct = call { api.getEvent(calendarId, eventId) }) {
                is ApiResult.Success -> ApiResult.Success(direct.data.toDomain())
                is ApiResult.Failure ->
                    // The authenticated single-event GET is undocumented; on 404/405 fall back to the
                    // list endpoint and filter by id (the list op is the documented primitive).
                    if (direct.error.status == 404 || direct.error.status == 405) {
                        eventViaList(calendarId, eventId)
                    } else {
                        direct
                    }
                is ApiResult.NetworkError -> direct
            }
        }

    private suspend fun eventViaList(calendarId: String, eventId: String): ApiResult<CalendarEvent> =
        when (val page = call { api.listEvents(calendarId) }) {
            is ApiResult.Success -> {
                val match = page.data.events.firstOrNull { it.eventId == eventId }
                if (match != null) {
                    ApiResult.Success(match.toDomain())
                } else {
                    ApiResult.Failure(
                        com.testlogon.android.core.model.ApiError(
                            status = 404,
                            message = "Event not found",
                        ),
                    )
                }
            }
            is ApiResult.Failure -> page
            is ApiResult.NetworkError -> page
        }

    override suspend fun publicEvent(calendarId: String, eventId: String): ApiResult<CalendarEvent> =
        withContext(io) {
            call { publicApi.getPublicEvent(calendarId, eventId) }.map { it.toDomain() }
        }

    /**
     * Folds a single call into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); transport
     * failures -> NetworkError; malformed JSON -> Failure(parse). The JsonEncodingException catch
     * precedes the IOException catch (it is an IOException subtype). Cancellation is re-thrown.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        // JsonEncodingException is a JsonDataException subtype, so catch it first; both decode
        // failures map to a parse Failure and both sit before the IOException catch.
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
