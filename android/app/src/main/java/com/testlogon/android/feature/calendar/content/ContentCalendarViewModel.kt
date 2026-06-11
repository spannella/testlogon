package com.testlogon.android.feature.calendar.content

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.contentcalendar.ContentDateRange
import com.testlogon.android.data.contentcalendar.ContentCalendarRepository
import com.testlogon.android.data.contentcalendar.ScheduledContent
import com.testlogon.android.feature.calendar.CalendarClock
import com.testlogon.android.feature.calendar.CalendarMath
import com.testlogon.android.feature.calendar.CalendarViewMode
import com.testlogon.android.feature.calendar.CalendarZoneProvider
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.time.Instant
import javax.inject.Inject

/**
 * AND-274 — drives [ContentCalendarUiState] for the content-calendar schedule/agenda screen.
 *
 * Loads the current month (in the display zone) of scheduled content, then groups items by their local
 * day. All date math (month bounds, day bucketing) reuses the PURE [CalendarMath] (epoch-day; no
 * java.time in the math); java.time is used only to resolve the display-zone offset via
 * [CalendarZoneProvider]. The focus month survives recreation via [SavedStateHandle].
 *
 * Read-only ticket: a row tap navigates toward the AND-275 scheduler detail route (the screen owns that
 * callback). On a transient failure when a prior successful load exists, the last-good content is shown
 * stale rather than blanking the list.
 */
@HiltViewModel
class ContentCalendarViewModel @Inject constructor(
    private val repository: ContentCalendarRepository,
    private val zoneProvider: CalendarZoneProvider,
    private val clock: CalendarClock,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val displayZoneId: String = zoneProvider.displayZoneId()

    private var focusEpochDay: Long
        get() = savedState.get<Long>(KEY_FOCUS) ?: clock.todayEpochDay(displayZoneId)
        set(value) { savedState[KEY_FOCUS] = value }

    private val _state =
        MutableStateFlow<ContentCalendarUiState>(ContentCalendarUiState.Loading(focusEpochDay))
    val state: StateFlow<ContentCalendarUiState> = _state.asStateFlow()

    private var lastContent: ContentCalendarUiState.Content? = null
    private var loading = false

    init {
        load()
    }

    fun nextMonth() {
        focusEpochDay = CalendarMath.step(CalendarViewMode.MONTH, focusEpochDay, +1)
        lastContent = null
        load()
    }

    fun previousMonth() {
        focusEpochDay = CalendarMath.step(CalendarViewMode.MONTH, focusEpochDay, -1)
        lastContent = null
        load()
    }

    fun goToToday() {
        focusEpochDay = clock.todayEpochDay(displayZoneId)
        lastContent = null
        load()
    }

    fun retry() {
        if (loading) return
        load()
    }

    private fun load() {
        loading = true
        val activeFocus = focusEpochDay
        _state.update { ContentCalendarUiState.Loading(activeFocus) }

        // Month bounds [first-of-month, first-of-next-month) as local epoch days, converted to UTC
        // instants for the from_ts/to_ts query. Widen by +/-1 day to avoid zone-boundary clipping.
        val ymd = CalendarMath.fromEpochDay(activeFocus)
        val firstOfMonth = CalendarMath.toEpochDay(ymd.year, ymd.month, 1)
        val firstOfNext = CalendarMath.toEpochDay(CalendarMath.addMonths(ymd.copy(day = 1), 1))
        val fromInstant = Instant.ofEpochMilli((firstOfMonth - 1L) * CalendarMath.MILLIS_PER_DAY)
        val toInstant = Instant.ofEpochMilli((firstOfNext + 1L) * CalendarMath.MILLIS_PER_DAY)

        val offsetMinutes = zoneProvider.offsetMinutesAt(
            displayZoneId, Instant.ofEpochMilli(activeFocus * CalendarMath.MILLIS_PER_DAY),
        )

        viewModelScope.launch {
            val result = repository.scheduledContent(ContentDateRange(fromInstant, toInstant))
            _state.update { reduce(activeFocus, offsetMinutes, result) }
            loading = false
        }
    }

    private fun reduce(
        activeFocus: Long,
        offsetMinutes: Int,
        result: ApiResult<List<ScheduledContent>>,
    ): ContentCalendarUiState = when (result) {
        is ApiResult.Success -> {
            val days = bucketByDay(result.data, offsetMinutes)
            if (days.isEmpty()) {
                ContentCalendarUiState.Empty(activeFocus)
            } else {
                ContentCalendarUiState.Content(activeFocus, days).also { lastContent = it }
            }
        }
        is ApiResult.Failure ->
            lastContent?.copy(isStale = true)
                ?: ContentCalendarUiState.Error(activeFocus, result.error.message, isOffline = false)
        is ApiResult.NetworkError ->
            lastContent?.copy(isStale = true)
                ?: ContentCalendarUiState.Error(activeFocus, OFFLINE_MESSAGE, isOffline = true)
    }

    /** Groups items by local epoch day (pure CalendarMath bucketing), ascending; items by time. */
    private fun bucketByDay(items: List<ScheduledContent>, offsetMinutes: Int): List<ContentDay> =
        items
            .groupBy { CalendarMath.localEpochDay(it.scheduledAt.toEpochMilli(), offsetMinutes) }
            .toSortedMap()
            .map { (epochDay, dayItems) ->
                ContentDay(epochDay, dayItems.sortedBy { it.scheduledAt })
            }

    private companion object {
        const val KEY_FOCUS = "content_calendar_focus_epoch_day"
        const val OFFLINE_MESSAGE = "Couldn't reach the server. Try again."
    }
}
