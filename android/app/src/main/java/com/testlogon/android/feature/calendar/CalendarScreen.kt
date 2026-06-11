@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.calendar

import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ChevronLeft
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-271 — stable test tags for the calendar views. */
object CalendarTestTags {
    const val SCREEN = "calendar_screen"
    const val MONTH_GRID = "calendar_month_grid"
    const val WEEK_GRID = "calendar_week_grid"
    const val AGENDA_LIST = "calendar_agenda_list"
    const val TODAY = "calendar_today"
    const val PREV = "calendar_prev"
    const val NEXT = "calendar_next"
    const val ZONE_BANNER = "calendar_zone_banner"
    fun day(epochDay: Long) = "calendar_day_$epochDay"
    fun event(eventId: String) = "calendar_event_$eventId"
}

/**
 * AND-271 — route-level calendar screen. Hoists [CalendarViewModel], collects state, and exposes the
 * AND-272 [onEventClick] selection callback (routing owned downstream).
 */
@Composable
fun CalendarRoute(
    onBack: () -> Unit,
    onEventClick: (calendarId: String, eventId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CalendarViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    CalendarScreen(
        state = state,
        onBack = onBack,
        onEventClick = onEventClick,
        onSetMode = viewModel::onModeSelected,
        onPrev = viewModel::stepBackward,
        onNext = viewModel::stepForward,
        onToday = viewModel::goToToday,
        onOpenDay = viewModel::openDayAgenda,
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}

@Composable
fun CalendarScreen(
    state: CalendarUiState,
    onBack: () -> Unit,
    onEventClick: (calendarId: String, eventId: String) -> Unit,
    onSetMode: (CalendarViewMode) -> Unit,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    onToday: () -> Unit,
    onOpenDay: (Long) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CalendarTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.calendar_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            val activeMode = (state as? CalendarUiState.Content)?.mode ?: CalendarViewMode.MONTH
            ModeSelector(activeMode = activeMode, onSetMode = onSetMode)
            NavRow(onPrev = onPrev, onNext = onNext, onToday = onToday)
            when (state) {
                CalendarUiState.Loading -> LoadingState()
                is CalendarUiState.Error ->
                    ErrorState(message = state.message, onRetry = onRetry)
                is CalendarUiState.Content -> CalendarContent(
                    content = state,
                    onEventClick = onEventClick,
                    onOpenDay = onOpenDay,
                )
            }
        }
    }
}

@Composable
private fun ModeSelector(activeMode: CalendarViewMode, onSetMode: (CalendarViewMode) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        ModeChip(R.string.calendar_view_month, CalendarViewMode.MONTH, activeMode, onSetMode)
        ModeChip(R.string.calendar_view_week, CalendarViewMode.WEEK, activeMode, onSetMode)
        ModeChip(R.string.calendar_view_agenda, CalendarViewMode.AGENDA, activeMode, onSetMode)
    }
}

@Composable
private fun ModeChip(
    labelRes: Int,
    mode: CalendarViewMode,
    activeMode: CalendarViewMode,
    onSetMode: (CalendarViewMode) -> Unit,
) {
    FilterChip(
        selected = mode == activeMode,
        onClick = { onSetMode(mode) },
        label = { Text(stringResource(labelRes)) },
    )
}

@Composable
private fun NavRow(onPrev: () -> Unit, onNext: () -> Unit, onToday: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onPrev, modifier = Modifier.testTag(CalendarTestTags.PREV)) {
            Icon(Icons.Filled.ChevronLeft, contentDescription = stringResource(R.string.calendar_nav_previous))
        }
        IconButton(onClick = onNext, modifier = Modifier.testTag(CalendarTestTags.NEXT)) {
            Icon(Icons.Filled.ChevronRight, contentDescription = stringResource(R.string.calendar_nav_next))
        }
        Box(Modifier.weight(1f))
        TextButton(onClick = onToday, modifier = Modifier.testTag(CalendarTestTags.TODAY)) {
            Text(stringResource(R.string.calendar_today))
        }
    }
}

@Composable
private fun CalendarContent(
    content: CalendarUiState.Content,
    onEventClick: (String, String) -> Unit,
    onOpenDay: (Long) -> Unit,
) {
    Column(Modifier.fillMaxSize()) {
        if (content.zoneMismatch) {
            Surface(
                color = MaterialTheme.colorScheme.tertiaryContainer,
                modifier = Modifier.fillMaxWidth().testTag(CalendarTestTags.ZONE_BANNER),
            ) {
                Text(
                    text = stringResource(R.string.calendar_zone_mismatch, content.displayZoneId),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
        }
        if (content.isEmpty) {
            EmptyState(
                title = stringResource(R.string.calendar_empty_title),
                body = stringResource(R.string.calendar_empty_body),
            )
            return@Column
        }
        when (content.mode) {
            CalendarViewMode.MONTH -> MonthGrid(content.monthDays, content.displayZoneId, onOpenDay, onEventClick)
            CalendarViewMode.WEEK -> WeekGridView(content.weekGrid, content.displayZoneId, onEventClick)
            CalendarViewMode.AGENDA -> AgendaList(content.agendaDays, content.displayZoneId, onEventClick)
        }
    }
}

@Composable
private fun MonthGrid(
    days: List<DaySlots>,
    zoneId: String,
    onOpenDay: (Long) -> Unit,
    onEventClick: (String, String) -> Unit,
) {
    Column(Modifier.fillMaxWidth().testTag(CalendarTestTags.MONTH_GRID)) {
        days.chunked(CalendarMath.DAYS_PER_WEEK).forEach { week ->
            Row(Modifier.fillMaxWidth()) {
                week.forEach { day ->
                    MonthDayCell(
                        day = day,
                        modifier = Modifier.weight(1f).aspectRatio(1f),
                        onOpenDay = onOpenDay,
                        onEventClick = onEventClick,
                    )
                }
            }
        }
    }
}

@Composable
private fun MonthDayCell(
    day: DaySlots,
    modifier: Modifier,
    onOpenDay: (Long) -> Unit,
    onEventClick: (String, String) -> Unit,
) {
    val ymd = CalendarMath.fromEpochDay(day.epochDay)
    Column(
        modifier
            .border(0.5.dp, MaterialTheme.colorScheme.outlineVariant)
            .clickable { onOpenDay(day.epochDay) }
            .padding(2.dp)
            .testTag(CalendarTestTags.day(day.epochDay))
            .semantics {
                contentDescription = "${ymd.year}-${ymd.month}-${ymd.day}, ${day.events.size} events"
            },
    ) {
        Text(ymd.day.toString(), style = MaterialTheme.typography.labelSmall)
        day.events.forEach { event ->
            Text(
                text = event.title,
                style = MaterialTheme.typography.labelSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onEventClick(event.calendarId, event.eventId) }
                    .testTag(CalendarTestTags.event(event.eventId)),
            )
        }
        if (day.overflowCount > 0) {
            Text(
                text = stringResource(R.string.calendar_more_events, day.overflowCount),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

@Composable
private fun WeekGridView(
    grid: WeekGrid?,
    zoneId: String,
    onEventClick: (String, String) -> Unit,
) {
    if (grid == null) return
    LazyColumn(
        Modifier.fillMaxSize().testTag(CalendarTestTags.WEEK_GRID),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (grid.allDayLane.isNotEmpty()) {
            item {
                Text(stringResource(R.string.calendar_all_day), style = MaterialTheme.typography.titleSmall)
            }
            items(grid.allDayLane, key = { "allday_${it.eventId}" }) { event ->
                EventRow(event = event, zoneId = zoneId, onEventClick = onEventClick)
            }
        }
        grid.columns.forEach { column ->
            if (column.blocks.isNotEmpty()) {
                item(key = "hdr_${column.epochDay}") {
                    DayHeader(column.epochDay, zoneId)
                }
                items(column.blocks, key = { "blk_${it.event.eventId}" }) { block ->
                    EventRow(event = block.event, zoneId = zoneId, onEventClick = onEventClick)
                }
            }
        }
    }
}

@Composable
private fun AgendaList(
    days: List<DaySlots>,
    zoneId: String,
    onEventClick: (String, String) -> Unit,
) {
    LazyColumn(
        Modifier.fillMaxSize().testTag(CalendarTestTags.AGENDA_LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        days.forEach { day ->
            item(key = "hdr_${day.epochDay}") { DayHeader(day.epochDay, zoneId) }
            items(day.events, key = { "ev_${day.epochDay}_${it.eventId}" }) { event ->
                EventRow(event = event, zoneId = zoneId, onEventClick = onEventClick)
            }
        }
    }
}

@Composable
private fun DayHeader(epochDay: Long, zoneId: String) {
    val label = CalendarDateFormat.formatAllDay(epochDay)
    Text(label, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp))
}

@Composable
private fun EventRow(
    event: SlottedEvent,
    zoneId: String,
    onEventClick: (String, String) -> Unit,
) {
    val time = if (event.isAllDay) {
        stringResource(R.string.calendar_all_day)
    } else {
        CalendarDateFormat.formatTime(event.startMillis, zoneId)
    }
    Surface(
        tonalElevation = 1.dp,
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onEventClick(event.calendarId, event.eventId) }
            .testTag(CalendarTestTags.event(event.eventId)),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(event.title, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(time, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
