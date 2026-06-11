package com.testlogon.android.feature.calendar

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.calendar.Calendar
import com.testlogon.android.data.calendar.CalendarEvent
import com.testlogon.android.data.calendar.CalendarRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.time.Instant
import javax.inject.Inject

/**
 * AND-271 — drives [CalendarUiState] for the calendar screen (Month / Week / Agenda).
 *
 * Because the backend events endpoint is per-calendar, the VM fans out across the user's calendars
 * (GET ui/calendars) and merges the events for the active [DateWindow], following next_cursor per
 * calendar. All slotting / bucketing is delegated to the PURE [EventSlotter] (no Android, no java.time);
 * the only java.time use is resolving the display-zone offset via [CalendarZoneProvider]. The selected
 * mode + focus day are persisted to [SavedStateHandle] so they survive recreation / process death.
 */
@HiltViewModel
class CalendarViewModel @Inject constructor(
    private val repository: CalendarRepository,
    private val zoneProvider: CalendarZoneProvider,
    private val clock: CalendarClock,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _state = MutableStateFlow<CalendarUiState>(CalendarUiState.Loading)
    val state: StateFlow<CalendarUiState> = _state.asStateFlow()

    private val displayZoneId: String = zoneProvider.displayZoneId()
    private val deviceZoneId: String = zoneProvider.deviceZoneId()

    private var mode: CalendarViewMode
        get() = savedState.get<String>(KEY_MODE)?.let { runCatching { CalendarViewMode.valueOf(it) }.getOrNull() }
            ?: CalendarViewMode.MONTH
        set(value) { savedState[KEY_MODE] = value.name }

    private var focusEpochDay: Long
        get() = savedState.get<Long>(KEY_FOCUS) ?: clock.todayEpochDay(displayZoneId)
        set(value) { savedState[KEY_FOCUS] = value }

    private var loading = false

    init {
        load()
    }

    fun onModeSelected(newMode: CalendarViewMode) {
        if (newMode == mode) return
        mode = newMode
        load()
    }

    fun focusOn(epochDay: Long) {
        focusEpochDay = epochDay
        load()
    }

    fun stepForward() {
        focusEpochDay = CalendarMath.step(mode, focusEpochDay, +1)
        load()
    }

    fun stepBackward() {
        focusEpochDay = CalendarMath.step(mode, focusEpochDay, -1)
        load()
    }

    fun goToToday() {
        focusEpochDay = clock.todayEpochDay(displayZoneId)
        load()
    }

    /** Opens the agenda scoped to a tapped day (month cell / overflow). */
    fun openDayAgenda(epochDay: Long) {
        mode = CalendarViewMode.AGENDA
        focusEpochDay = epochDay
        load()
    }

    fun retry() {
        if (loading) return
        load()
    }

    private fun load() {
        loading = true
        _state.update { CalendarUiState.Loading }
        val activeMode = mode
        val activeFocus = focusEpochDay
        val range = CalendarMath.rangeFor(activeMode, activeFocus)

        viewModelScope.launch {
            when (val calsResult = repository.calendars()) {
                is ApiResult.Success -> loadEvents(activeMode, activeFocus, range, calsResult.data)
                is ApiResult.Failure ->
                    _state.update { CalendarUiState.Error(calsResult.error.message, offline = false) }
                is ApiResult.NetworkError ->
                    _state.update { CalendarUiState.Error(OFFLINE_MESSAGE, offline = true) }
            }
            loading = false
        }
    }

    private suspend fun loadEvents(
        activeMode: CalendarViewMode,
        activeFocus: Long,
        range: CalendarMath.DayRange,
        calendars: List<Calendar>,
    ) {
        // Widen by +/-1 day in UTC before query to avoid boundary clipping after zone conversion.
        val startUtc = epochDayToUtcIso(range.startEpochDay - 1L)
        val endUtc = epochDayToUtcIso(range.endEpochDayExclusive + 1L)

        val merged = ArrayList<CalendarEvent>()
        for (cal in calendars) {
            when (val page = repository.events(cal.calendarId, startUtc = startUtc, endUtc = endUtc)) {
                is ApiResult.Success -> merged.addAll(page.data.events)
                is ApiResult.Failure -> {
                    _state.update { CalendarUiState.Error(page.error.message, offline = false) }
                    return
                }
                is ApiResult.NetworkError -> {
                    _state.update { CalendarUiState.Error(OFFLINE_MESSAGE, offline = true) }
                    return
                }
            }
        }

        val slotted = merged.map { it.toSlotted(displayZoneId) }
        // The display-zone offset at the focus instant (sufficient for a window without a DST boundary).
        val focusInstant = Instant.ofEpochMilli(activeFocus * CalendarMath.MILLIS_PER_DAY)
        val offsetMinutes = zoneProvider.offsetMinutesAt(displayZoneId, focusInstant)

        val monthDays = EventSlotter.toDaySlots(slotted, range, offsetMinutes)
        val weekGrid = if (activeMode == CalendarViewMode.WEEK) {
            EventSlotter.toWeekGrid(slotted, CalendarMath.weekDays(activeFocus), offsetMinutes)
        } else {
            null
        }
        val agendaDays = monthDays.filter { it.events.isNotEmpty() }
        val isEmpty = slotted.isEmpty() || when (activeMode) {
            CalendarViewMode.AGENDA -> agendaDays.isEmpty()
            else -> monthDays.all { it.events.isEmpty() }
        }

        _state.update {
            CalendarUiState.Content(
                mode = activeMode,
                focusEpochDay = activeFocus,
                displayZoneId = displayZoneId,
                deviceZoneId = deviceZoneId,
                zoneMismatch = displayZoneId != deviceZoneId,
                monthDays = monthDays,
                weekGrid = weekGrid,
                agendaDays = agendaDays,
                isEmpty = isEmpty,
            )
        }
    }

    /** Maps a domain event to a pure [SlottedEvent] (UTC millis + anchored all-day day). */
    private fun CalendarEvent.toSlotted(zoneId: String): SlottedEvent {
        if (allDay && allDayDate != null) {
            val epochDay = allDayDate.toEpochDay()
            val midnight = epochDay * CalendarMath.MILLIS_PER_DAY
            return SlottedEvent(
                calendarId = calendarId,
                eventId = eventId,
                title = name,
                startMillis = midnight,
                endMillis = midnight + CalendarMath.MILLIS_PER_DAY,
                isAllDay = true,
                allDayEpochDay = epochDay,
                hasRecurrence = recurrence != null,
            )
        }
        val start = startAt?.toEpochMilli() ?: 0L
        val end = endAt?.toEpochMilli() ?: (start + CalendarMath.MILLIS_PER_MINUTE)
        return SlottedEvent(
            calendarId = calendarId,
            eventId = eventId,
            title = name,
            startMillis = start,
            endMillis = end,
            isAllDay = false,
            allDayEpochDay = null,
            hasRecurrence = recurrence != null,
        )
    }

    private fun epochDayToUtcIso(epochDay: Long): String =
        Instant.ofEpochMilli(epochDay * CalendarMath.MILLIS_PER_DAY).toString()

    private companion object {
        const val KEY_MODE = "calendar_mode"
        const val KEY_FOCUS = "calendar_focus_epoch_day"
        const val OFFLINE_MESSAGE = "Couldn't reach the server. Try again."
    }
}
