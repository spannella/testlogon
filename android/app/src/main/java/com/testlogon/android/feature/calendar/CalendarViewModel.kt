package com.testlogon.android.feature.calendar

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.calendar.Calendar
import com.testlogon.android.data.calendar.CalendarEvent
import com.testlogon.android.data.calendar.CalendarRepository
import com.testlogon.android.data.calendar.EventCreateReqDto
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.time.Instant
import javax.inject.Inject

/**
 * AND-271 / SC19 — drives [CalendarUiState] for the calendar screen (Month / Week / Day / Agenda) and
 * owns event CRUD (add / edit / delete).
 *
 * The backend events endpoint is per-calendar, so the VM fans out across the user's calendars
 * (GET ui/calendars) and merges events for the active [DateWindow]. All slotting / bucketing is
 * delegated to the PURE [EventSlotter]; the only java.time use is resolving the display-zone offset via
 * [CalendarZoneProvider]. The selected mode + focus day persist to [SavedStateHandle] across recreation.
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

    /** One-shot user messages (saved / deleted / failed). */
    private val _messages = Channel<String>(Channel.BUFFERED)
    val messages: Flow<String> = _messages.receiveAsFlow()

    private val displayZoneId: String = zoneProvider.displayZoneId()
    private val deviceZoneId: String = zoneProvider.deviceZoneId()

    /** Cached calendars from the latest successful load (for the editor dropdown + add gating). */
    private var calendars: List<Calendar> = emptyList()

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

    /** Opens the Day view scoped to a tapped day (month cell / overflow / week header). */
    fun openDayAgenda(epochDay: Long) {
        mode = CalendarViewMode.DAY
        focusEpochDay = epochDay
        load()
    }

    fun retry() {
        if (loading) return
        load()
    }

    // ---- Event CRUD / editor ----

    /** Opens the editor to ADD a new event on [epochDay] (defaults to the current focus day). */
    fun openAddEvent(epochDay: Long = focusEpochDay) {
        val content = _state.value as? CalendarUiState.Content ?: return
        val options = calendars.map { CalendarOption(it.calendarId, it.name) }
        val defaultCal = options.firstOrNull() ?: return
        _state.update {
            (it as? CalendarUiState.Content)?.copy(
                editor = EventEditorState(
                    eventId = null,
                    calendarId = defaultCal.calendarId,
                    calendarOptions = options,
                    epochDay = epochDay,
                ),
                actionSheet = null,
            ) ?: it
        }
    }

    /** Opens the long-press action sheet for an event. */
    fun openEventActions(calendarId: String, eventId: String, title: String) {
        _state.update {
            (it as? CalendarUiState.Content)?.copy(
                actionSheet = EventActionSheet(calendarId, eventId, title),
            ) ?: it
        }
    }

    fun dismissEventActions() {
        _state.update { (it as? CalendarUiState.Content)?.copy(actionSheet = null) ?: it }
    }

    /** Opens the editor to EDIT an existing slotted event. */
    fun openEditEvent(calendarId: String, eventId: String) {
        val event = findSlotted(calendarId, eventId)
        val options = calendars.map { CalendarOption(it.calendarId, it.name) }
        val epochDay = event?.let {
            if (it.isAllDay && it.allDayEpochDay != null) it.allDayEpochDay
            else CalendarMath.localEpochDay(it.startMillis, offsetForFocus())
        } ?: focusEpochDay
        _state.update {
            (it as? CalendarUiState.Content)?.copy(
                editor = EventEditorState(
                    eventId = eventId,
                    calendarId = calendarId,
                    calendarOptions = options,
                    name = event?.title.orEmpty(),
                    allDay = event?.isAllDay ?: false,
                    epochDay = epochDay,
                    startTime = event?.let { e -> if (!e.isAllDay) timeOf(e.startMillis) else "09:00" } ?: "09:00",
                    endTime = event?.let { e -> if (!e.isAllDay) timeOf(e.endMillis) else "10:00" } ?: "10:00",
                ),
                actionSheet = null,
            ) ?: it
        }
    }

    fun dismissEditor() {
        _state.update { (it as? CalendarUiState.Content)?.copy(editor = null) ?: it }
    }

    fun updateEditor(transform: (EventEditorState) -> EventEditorState) {
        _state.update {
            val c = it as? CalendarUiState.Content ?: return@update it
            val ed = c.editor ?: return@update it
            c.copy(editor = transform(ed))
        }
    }

    /** Persists the editor (create or update), then reloads the window. */
    fun saveEditor() {
        val content = _state.value as? CalendarUiState.Content ?: return
        val ed = content.editor ?: return
        if (ed.name.isBlank()) {
            updateEditor { it.copy(nameError = true) }
            return
        }
        updateEditor { it.copy(saving = true, nameError = false) }
        val body = buildBody(ed)
        viewModelScope.launch {
            val result = if (ed.isEditing && ed.eventId != null) {
                repository.updateEvent(ed.calendarId, ed.eventId, body)
            } else {
                repository.createEvent(ed.calendarId, body)
            }
            when (result) {
                is ApiResult.Success -> {
                    _state.update { (it as? CalendarUiState.Content)?.copy(editor = null) ?: it }
                    _messages.send(MSG_SAVED)
                    load()
                }
                is ApiResult.Failure, is ApiResult.NetworkError -> {
                    updateEditor { it.copy(saving = false) }
                    _messages.send(MSG_SAVE_FAILED)
                }
            }
        }
    }

    /** Deletes the event from the action sheet (or editor), then reloads. */
    fun deleteEvent(calendarId: String, eventId: String) {
        _state.update {
            (it as? CalendarUiState.Content)?.copy(actionSheet = null, editor = null) ?: it
        }
        viewModelScope.launch {
            when (repository.deleteEvent(calendarId, eventId)) {
                is ApiResult.Success -> {
                    _messages.send(MSG_DELETED)
                    load()
                }
                is ApiResult.Failure, is ApiResult.NetworkError -> _messages.send(MSG_DELETE_FAILED)
            }
        }
    }

    private fun buildBody(ed: EventEditorState): EventCreateReqDto {
        val desc = ed.description.ifBlank { null }
        return if (ed.allDay) {
            EventCreateReqDto(
                name = ed.name.trim(),
                description = desc,
                timezone = displayZoneId,
                allDay = true,
                allDayDate = isoDate(ed.epochDay),
                startUtc = null,
                endUtc = null,
            )
        } else {
            val offset = offsetForDay(ed.epochDay)
            val startMillis = localDateTimeToUtcMillis(ed.epochDay, ed.startTime, offset)
            val endMillis = localDateTimeToUtcMillis(ed.epochDay, ed.endTime, offset)
                .let { if (it <= startMillis) startMillis + CalendarMath.MILLIS_PER_MINUTE * 60 else it }
            EventCreateReqDto(
                name = ed.name.trim(),
                description = desc,
                timezone = displayZoneId,
                allDay = false,
                allDayDate = null,
                startUtc = Instant.ofEpochMilli(startMillis).toString(),
                endUtc = Instant.ofEpochMilli(endMillis).toString(),
            )
        }
    }

    private fun load() {
        loading = true
        _state.update { CalendarUiState.Loading }
        val activeMode = mode
        val activeFocus = focusEpochDay
        val range = CalendarMath.rangeFor(activeMode, activeFocus)

        viewModelScope.launch {
            when (val calsResult = repository.calendars()) {
                is ApiResult.Success -> {
                    calendars = calsResult.data
                    loadEvents(activeMode, activeFocus, range, calsResult.data)
                }
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
        slottedCache = slotted
        // The display-zone offset at the focus instant (sufficient for a window without a DST boundary).
        val offsetMinutes = offsetForFocus(activeFocus)

        val monthRange = CalendarMath.rangeFor(CalendarViewMode.MONTH, activeFocus)
        val monthDays = EventSlotter.toDaySlots(slotted, monthRange, offsetMinutes)
        val weekGrid = if (activeMode == CalendarViewMode.WEEK) {
            EventSlotter.toWeekGrid(slotted, CalendarMath.weekDays(activeFocus), offsetMinutes)
        } else {
            null
        }
        val agendaRange = CalendarMath.rangeFor(CalendarViewMode.AGENDA, activeFocus)
        val agendaDays = EventSlotter.toDaySlots(slotted, agendaRange, offsetMinutes, maxChips = 0)
            .filter { it.events.isNotEmpty() }
        val dayEvents = EventSlotter.toDaySlots(
            slotted,
            CalendarMath.DayRange(activeFocus, activeFocus + 1L),
            offsetMinutes,
            maxChips = 0,
        ).firstOrNull()?.events.orEmpty()

        val todayEpochDay = clock.todayEpochDay(displayZoneId)
        val isEmpty = when (activeMode) {
            CalendarViewMode.AGENDA -> agendaDays.isEmpty()
            CalendarViewMode.DAY -> dayEvents.isEmpty()
            CalendarViewMode.WEEK ->
                (weekGrid?.allDayLane?.isEmpty() != false) && (weekGrid?.columns?.all { it.blocks.isEmpty() } != false)
            CalendarViewMode.MONTH -> monthDays.all { it.events.isEmpty() }
        }

        _state.update {
            CalendarUiState.Content(
                mode = activeMode,
                focusEpochDay = activeFocus,
                todayEpochDay = todayEpochDay,
                headerLabel = headerLabelFor(activeMode, activeFocus),
                weekdayHeaders = WEEKDAY_HEADERS,
                displayZoneId = displayZoneId,
                deviceZoneId = deviceZoneId,
                zoneMismatch = displayZoneId != deviceZoneId,
                monthDays = monthDays,
                weekGrid = weekGrid,
                agendaDays = agendaDays,
                dayEvents = dayEvents,
                isEmpty = isEmpty,
                canAddEvents = calendars.isNotEmpty(),
            )
        }
    }

    // ---- helpers ----

    private var slottedCache: List<SlottedEvent> = emptyList()

    private fun findSlotted(calendarId: String, eventId: String): SlottedEvent? =
        slottedCache.firstOrNull { it.calendarId == calendarId && it.eventId == eventId }

    private fun offsetForFocus(focus: Long = focusEpochDay): Int {
        val instant = Instant.ofEpochMilli(focus * CalendarMath.MILLIS_PER_DAY)
        return zoneProvider.offsetMinutesAt(displayZoneId, instant)
    }

    private fun offsetForDay(epochDay: Long): Int = offsetForFocus(epochDay)

    private fun headerLabelFor(activeMode: CalendarViewMode, focus: Long): String {
        val utc = focus * CalendarMath.MILLIS_PER_DAY
        return when (activeMode) {
            CalendarViewMode.MONTH -> CalendarDateFormat.formatMonthYear(utc, "UTC")
            CalendarViewMode.WEEK -> {
                val days = CalendarMath.weekDays(focus)
                val start = CalendarDateFormat.formatDate(days.first() * CalendarMath.MILLIS_PER_DAY, "UTC")
                val end = CalendarDateFormat.formatDate(days.last() * CalendarMath.MILLIS_PER_DAY, "UTC")
                "$start - $end"
            }
            CalendarViewMode.DAY -> CalendarDateFormat.formatDate(utc, "UTC")
            CalendarViewMode.AGENDA -> CalendarDateFormat.formatMonthYear(utc, "UTC")
        }
    }

    /** "HH:MM" local time of a UTC-millis instant in the display zone. */
    private fun timeOf(utcMillis: Long): String {
        val offset = offsetForFocus()
        val minuteOfDay = CalendarMath.localMinuteOfDay(utcMillis, offset)
        val h = minuteOfDay / 60
        val m = minuteOfDay % 60
        return "%02d:%02d".format(h, m)
    }

    /** Parses "HH:MM" + epoch day + zone offset into a UTC epoch-millis instant. */
    private fun localDateTimeToUtcMillis(epochDay: Long, hhmm: String, offsetMinutes: Int): Long {
        val parts = hhmm.split(":")
        val h = parts.getOrNull(0)?.trim()?.toIntOrNull()?.coerceIn(0, 23) ?: 0
        val m = parts.getOrNull(1)?.trim()?.toIntOrNull()?.coerceIn(0, 59) ?: 0
        val localMillis = epochDay * CalendarMath.MILLIS_PER_DAY + (h * 60 + m) * CalendarMath.MILLIS_PER_MINUTE
        return localMillis - offsetMinutes.toLong() * CalendarMath.MILLIS_PER_MINUTE
    }

    private fun isoDate(epochDay: Long): String {
        val ymd = CalendarMath.fromEpochDay(epochDay)
        return "%04d-%02d-%02d".format(ymd.year, ymd.month, ymd.day)
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
        const val MSG_SAVED = "Event saved"
        const val MSG_DELETED = "Event deleted"
        const val MSG_SAVE_FAILED = "Couldn't save the event. Try again."
        const val MSG_DELETE_FAILED = "Couldn't delete the event. Try again."

        // Mon..Sun (week starts Monday, matching CalendarMath.weekStartIso default of 1).
        val WEEKDAY_HEADERS = listOf("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    }
}
