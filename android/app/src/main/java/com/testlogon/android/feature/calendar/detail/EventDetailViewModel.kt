package com.testlogon.android.feature.calendar.detail

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.calendar.CalendarEvent
import com.testlogon.android.data.calendar.CalendarRepository
import com.testlogon.android.data.calendar.ics.IcsMapper
import com.testlogon.android.data.calendar.ics.Rfc5545IcsSerializer
import com.testlogon.android.feature.calendar.CalendarZoneProvider
import android.net.Uri
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-272 — drives [EventDetailUiState] for `calendar/event/{calendarId}/{eventId}`.
 *
 * Reads `calendarId`/`eventId` (and an optional `isPublic` flag set by the public deep link) from
 * [SavedStateHandle]. Blank ids resolve to [EventDetailUiState.Unavailable] with NO network call.
 * Picks the public vs authenticated endpoint by the arg; the repository additionally falls back from
 * the (undocumented) authenticated GET to the list endpoint. Error mapping: 404 / 422 -> Unavailable,
 * 403 -> Forbidden, transport -> Error(offline), other -> Error.
 *
 * The canonical public share URL is built eagerly from the App Link host (never the dev host).
 */
@HiltViewModel
class EventDetailViewModel @Inject constructor(
    private val repository: CalendarRepository,
    private val zoneProvider: CalendarZoneProvider,
    private val shareHostProvider: PublicEventHostProvider,
    private val icsExporter: IcsExporter,
    private val icsSerializer: Rfc5545IcsSerializer,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val calendarId: String = savedStateHandle.get<String>(ARG_CALENDAR_ID).orEmpty()
    private val eventId: String = savedStateHandle.get<String>(ARG_EVENT_ID).orEmpty()
    private val isPublicArg: Boolean = savedStateHandle.get<String>(ARG_IS_PUBLIC)?.toBooleanStrictOrNull() ?: false

    private val displayZoneId: String = zoneProvider.displayZoneId()
    private val deviceZoneId: String = zoneProvider.deviceZoneId()

    private val _state = MutableStateFlow<EventDetailUiState>(EventDetailUiState.Loading)
    val state: StateFlow<EventDetailUiState> = _state.asStateFlow()

    private var loading = false

    init {
        load()
    }

    fun retry() {
        if (loading) return
        load()
    }

    /**
     * SC19 #11 - generates a valid RFC 5545 .ics for the currently loaded event (client-side, from the
     * already-fetched domain object) and writes it to a shareable FileProvider URI. Returns null when no
     * event is loaded yet. The caller opens the URI via ACTION_VIEW (text/calendar). This avoids
     * depending on a reachable public web host or session cookies in the browser.
     */
    fun exportIcs(): Uri? {
        val event = (state.value as? EventDetailUiState.Content)?.event ?: return null
        val ics = icsSerializer.serialize(listOf(IcsMapper.toIcsEvent(event, publicUrl = null)))
        return runCatching { icsExporter.writeToCache(event.eventId, ics) }.getOrNull()
    }

    private fun load() {
        if (calendarId.isBlank() || eventId.isBlank()) {
            _state.value = EventDetailUiState.Unavailable
            return
        }
        loading = true
        _state.value = EventDetailUiState.Loading
        viewModelScope.launch {
            val result = if (isPublicArg) {
                repository.publicEvent(calendarId, eventId)
            } else {
                resolveAuthThenPublic()
            }
            _state.value = when (result) {
                is ApiResult.Success -> toContent(result.data)
                is ApiResult.Failure -> mapFailure(result.error)
                is ApiResult.NetworkError -> EventDetailUiState.Error(OFFLINE_MESSAGE, offline = true)
            }
            loading = false
        }
    }

    /**
     * Tries the authenticated single-event read; on a 401/403/404 (e.g. an unauthenticated deep-link
     * open of a shareable event) falls back to the public endpoint, mirroring the web behaviour where
     * "public vs authenticated" is decided by which endpoint succeeds.
     */
    private suspend fun resolveAuthThenPublic(): ApiResult<CalendarEvent> {
        val authed = repository.event(calendarId, eventId)
        if (authed is ApiResult.Failure && authed.error.status in PUBLIC_FALLBACK_STATUSES) {
            val public = repository.publicEvent(calendarId, eventId)
            if (public is ApiResult.Success) return public
        }
        return authed
    }

    private fun toContent(event: CalendarEvent): EventDetailUiState.Content =
        EventDetailUiState.Content(
            event = event,
            displayZoneId = displayZoneId,
            deviceZoneId = deviceZoneId,
            zoneMismatch = displayZoneId != deviceZoneId,
            isPublic = event.isPublic,
            publicShareUrl = EventShareUrl.build(shareHostProvider.host(), calendarId, eventId),
            // AND-391 — canonical public iCal download URL on the published host (never the dev host).
            publicIcalUrl = EventShareUrl.publicIcalUrl(shareHostProvider.host(), calendarId, eventId),
        )

    private fun mapFailure(error: ApiError): EventDetailUiState = when (error.status) {
        404, 422 -> EventDetailUiState.Unavailable
        403 -> EventDetailUiState.Forbidden
        ApiError.STATUS_NETWORK -> EventDetailUiState.Error(OFFLINE_MESSAGE, offline = true)
        else -> EventDetailUiState.Error(error.message, offline = false)
    }

    companion object {
        const val ARG_CALENDAR_ID = "calendarId"
        const val ARG_EVENT_ID = "eventId"
        const val ARG_IS_PUBLIC = "isPublic"
        private const val OFFLINE_MESSAGE = "Couldn't reach the server. Try again."
        private val PUBLIC_FALLBACK_STATUSES = setOf(401, 403, 404)
    }
}
