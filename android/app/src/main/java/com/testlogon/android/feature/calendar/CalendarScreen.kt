@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)

package com.testlogon.android.feature.calendar

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ChevronLeft
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.calendar.RecurrenceFreq

/** AND-271 / SC19 — stable test tags for the calendar views. */
object CalendarTestTags {
    const val SCREEN = "calendar_screen"
    const val MONTH_GRID = "calendar_month_grid"
    const val WEEK_GRID = "calendar_week_grid"
    const val DAY_LIST = "calendar_day_list"
    const val AGENDA_LIST = "calendar_agenda_list"
    const val TODAY = "calendar_today"
    const val PREV = "calendar_prev"
    const val NEXT = "calendar_next"
    const val HEADER = "calendar_header_label"
    const val ADD = "calendar_add_event"
    const val EDITOR = "calendar_editor"
    const val ACTION_SHEET = "calendar_event_actions"
    const val ZONE_BANNER = "calendar_zone_banner"
    fun day(epochDay: Long) = "calendar_day_$epochDay"
    fun event(eventId: String) = "calendar_event_$eventId"
}

/**
 * AND-271 / SC19 — route-level calendar screen. Hoists [CalendarViewModel], collects state + one-shot
 * messages, and exposes the AND-272 [onEventClick] selection callback (routing owned downstream).
 */
@Composable
fun CalendarRoute(
    onBack: () -> Unit,
    onEventClick: (calendarId: String, eventId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CalendarViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = androidx.compose.runtime.remember { androidx.compose.material3.SnackbarHostState() }
    LaunchedEffect(viewModel) {
        viewModel.messages.collect { snackbarHostState.showSnackbar(it) }
    }
    CalendarScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onEventClick = onEventClick,
        onEventLongClick = viewModel::openEventActions,
        onSetMode = viewModel::onModeSelected,
        onPrev = viewModel::stepBackward,
        onNext = viewModel::stepForward,
        onToday = viewModel::goToToday,
        onOpenDay = viewModel::openDayAgenda,
        onAddOnDay = viewModel::openAddEvent,
        onAddClick = { viewModel.openAddEvent() },
        onRetry = viewModel::retry,
        onEditorChange = viewModel::updateEditor,
        onEditorSave = viewModel::saveEditor,
        onEditorDismiss = viewModel::dismissEditor,
        onEditEvent = viewModel::openEditEvent,
        onDeleteEvent = viewModel::deleteEvent,
        onRequestDelete = viewModel::requestDeleteEvent,
        onDeleteThisOccurrence = viewModel::deleteThisOccurrence,
        onDeleteThisAndFollowing = viewModel::deleteThisAndFollowing,
        onDeleteAllEvents = viewModel::deleteSeries,
        onDismissRecurringDelete = viewModel::dismissRecurringDelete,
        onDismissActions = viewModel::dismissEventActions,
        modifier = modifier,
    )
}

@Composable
fun CalendarScreen(
    state: CalendarUiState,
    snackbarHostState: androidx.compose.material3.SnackbarHostState,
    onBack: () -> Unit,
    onEventClick: (calendarId: String, eventId: String) -> Unit,
    onEventLongClick: (calendarId: String, eventId: String, title: String, occurrenceStartMillis: Long) -> Unit,
    onSetMode: (CalendarViewMode) -> Unit,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    onToday: () -> Unit,
    onOpenDay: (Long) -> Unit,
    onAddOnDay: (Long) -> Unit,
    onAddClick: () -> Unit,
    onRetry: () -> Unit,
    onEditorChange: ((EventEditorState) -> EventEditorState) -> Unit,
    onEditorSave: () -> Unit,
    onEditorDismiss: () -> Unit,
    onEditEvent: (calendarId: String, eventId: String) -> Unit,
    onDeleteEvent: (calendarId: String, eventId: String) -> Unit,
    // #13 - delete-flow: opens the choice dialog for a recurring event (else deletes directly).
    onRequestDelete: (calendarId: String, eventId: String, title: String, occurrenceStartUtc: String) -> Unit,
    onDeleteThisOccurrence: () -> Unit,
    onDeleteThisAndFollowing: () -> Unit,
    onDeleteAllEvents: () -> Unit,
    onDismissRecurringDelete: () -> Unit,
    onDismissActions: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val content = state as? CalendarUiState.Content
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
        floatingActionButton = {
            if (content?.canAddEvents == true) {
                FloatingActionButton(
                    onClick = onAddClick,
                    modifier = Modifier.testTag(CalendarTestTags.ADD),
                ) {
                    Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.calendar_add_event))
                }
            }
        },
        snackbarHost = { androidx.compose.material3.SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            val activeMode = content?.mode ?: CalendarViewMode.MONTH
            ModeSelector(activeMode = activeMode, onSetMode = onSetMode)
            NavRow(
                headerLabel = content?.headerLabel.orEmpty(),
                onPrev = onPrev,
                onNext = onNext,
                onToday = onToday,
            )
            when (state) {
                CalendarUiState.Loading -> LoadingState()
                is CalendarUiState.Error ->
                    ErrorState(message = state.message, onRetry = onRetry)
                is CalendarUiState.Content -> CalendarContent(
                    content = state,
                    onEventClick = onEventClick,
                    onEventLongClick = onEventLongClick,
                    onOpenDay = onOpenDay,
                    onAddOnDay = onAddOnDay,
                )
            }
        }
    }

    if (content?.editor != null) {
        EventEditorDialog(
            editor = content.editor,
            onChange = onEditorChange,
            onSave = onEditorSave,
            onDismiss = onEditorDismiss,
            onDelete = { ed ->
                // #13 - a recurring event prompts the choice dialog (the VM derives the edited
                // occurrence's start from the editor); a one-off deletes directly.
                if (ed.eventId != null) {
                    if (ed.recurrenceFreq != null && ed.recurrenceFreq != RecurrenceFreq.UNKNOWN) {
                        onRequestDelete(ed.calendarId, ed.eventId, ed.name, "")
                    } else {
                        onDeleteEvent(ed.calendarId, ed.eventId)
                    }
                }
            },
        )
    }

    val sheet = content?.actionSheet
    if (sheet != null) {
        EventActionSheetUi(
            sheet = sheet,
            onEdit = { onEditEvent(sheet.calendarId, sheet.eventId) },
            onDelete = {
                // #13 - recurring -> choice dialog (with the long-pressed occurrence); one-off -> direct.
                if (sheet.recurring) {
                    onRequestDelete(sheet.calendarId, sheet.eventId, sheet.title, sheet.occurrenceStartUtc)
                } else {
                    onDeleteEvent(sheet.calendarId, sheet.eventId)
                }
            },
            onDismiss = onDismissActions,
        )
    }

    // #13 - the "delete a recurring event" choice dialog.
    val recurringDelete = content?.recurringDelete
    if (recurringDelete != null) {
        RecurringDeleteDialog(
            prompt = recurringDelete,
            onThisOnly = onDeleteThisOccurrence,
            onThisAndFollowing = onDeleteThisAndFollowing,
            onAll = onDeleteAllEvents,
            onDismiss = onDismissRecurringDelete,
        )
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
        ModeChip(R.string.calendar_view_day, CalendarViewMode.DAY, activeMode, onSetMode)
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
private fun NavRow(
    headerLabel: String,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    onToday: () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onPrev, modifier = Modifier.testTag(CalendarTestTags.PREV)) {
            Icon(Icons.Filled.ChevronLeft, contentDescription = stringResource(R.string.calendar_nav_previous))
        }
        Text(
            text = headerLabel,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.testTag(CalendarTestTags.HEADER),
        )
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
    onEventLongClick: (String, String, String, Long) -> Unit,
    onOpenDay: (Long) -> Unit,
    onAddOnDay: (Long) -> Unit,
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
        when (content.mode) {
            CalendarViewMode.MONTH -> MonthView(
                days = content.monthDays,
                weekdayHeaders = content.weekdayHeaders,
                todayEpochDay = content.todayEpochDay,
                onOpenDay = onOpenDay,
                onAddOnDay = onAddOnDay,
                onEventClick = onEventClick,
                onEventLongClick = onEventLongClick,
            )
            CalendarViewMode.WEEK -> WeekGridView(content.weekGrid, content.displayZoneId, content.isEmpty, onEventClick, onEventLongClick)
            CalendarViewMode.DAY -> DayView(content.focusEpochDay, content.dayEvents, content.displayZoneId, onAddOnDay, onEventClick, onEventLongClick)
            CalendarViewMode.AGENDA ->
                if (content.isEmpty) CalendarEmpty()
                else AgendaList(content.agendaDays, content.displayZoneId, onEventClick, onEventLongClick)
        }
    }
}

@Composable
private fun CalendarEmpty() {
    EmptyState(
        title = stringResource(R.string.calendar_empty_title),
        body = stringResource(R.string.calendar_empty_body),
    )
}

@Composable
private fun MonthView(
    days: List<DaySlots>,
    weekdayHeaders: List<String>,
    todayEpochDay: Long,
    onOpenDay: (Long) -> Unit,
    onAddOnDay: (Long) -> Unit,
    onEventClick: (String, String) -> Unit,
    onEventLongClick: (String, String, String, Long) -> Unit,
) {
    Column(Modifier.fillMaxWidth().testTag(CalendarTestTags.MONTH_GRID)) {
        Row(Modifier.fillMaxWidth()) {
            weekdayHeaders.forEach { label ->
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f).padding(vertical = 4.dp),
                )
            }
        }
        days.chunked(CalendarMath.DAYS_PER_WEEK).forEach { week ->
            Row(Modifier.fillMaxWidth()) {
                week.forEach { day ->
                    MonthDayCell(
                        day = day,
                        isToday = day.epochDay == todayEpochDay,
                        modifier = Modifier.weight(1f).aspectRatio(1f),
                        onOpenDay = onOpenDay,
                        onAddOnDay = onAddOnDay,
                        onEventClick = onEventClick,
                        onEventLongClick = onEventLongClick,
                    )
                }
            }
        }
    }
}

@Composable
private fun MonthDayCell(
    day: DaySlots,
    isToday: Boolean,
    modifier: Modifier,
    onOpenDay: (Long) -> Unit,
    onAddOnDay: (Long) -> Unit,
    onEventClick: (String, String) -> Unit,
    onEventLongClick: (String, String, String, Long) -> Unit,
) {
    val ymd = CalendarMath.fromEpochDay(day.epochDay)
    Column(
        modifier
            .border(0.5.dp, MaterialTheme.colorScheme.outlineVariant)
            .combinedClickable(
                onClick = { onOpenDay(day.epochDay) },
                onLongClick = { onAddOnDay(day.epochDay) },
            )
            .padding(2.dp)
            .testTag(CalendarTestTags.day(day.epochDay))
            .semantics {
                contentDescription = "${ymd.year}-${ymd.month}-${ymd.day}, ${day.events.size} events"
            },
    ) {
        if (isToday) {
            Box(
                modifier = Modifier
                    .size(20.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    ymd.day.toString(),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onPrimary,
                )
            }
        } else {
            Text(ymd.day.toString(), style = MaterialTheme.typography.labelSmall)
        }
        day.events.forEach { event ->
            Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = MaterialTheme.shapes.extraSmall,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 1.dp)
                    .combinedClickable(
                        onClick = { onEventClick(event.calendarId, event.eventId) },
                        onLongClick = { onEventLongClick(event.calendarId, event.eventId, event.title, event.startMillis) },
                    )
                    .testTag(CalendarTestTags.event(event.eventId)),
            ) {
                Text(
                    text = event.title,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(horizontal = 2.dp),
                )
            }
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
    isEmpty: Boolean,
    onEventClick: (String, String) -> Unit,
    onEventLongClick: (String, String, String, Long) -> Unit,
) {
    if (grid == null || isEmpty) {
        CalendarEmpty()
        return
    }
    LazyColumn(
        Modifier.fillMaxSize().testTag(CalendarTestTags.WEEK_GRID),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (grid.allDayLane.isNotEmpty()) {
            item {
                Text(stringResource(R.string.calendar_all_day), style = MaterialTheme.typography.titleSmall)
            }
            // #12 - a recurring series yields multiple occurrences sharing one eventId; key by
            // eventId + occurrence start so LazyColumn keys stay unique (else IllegalArgumentException).
            items(grid.allDayLane, key = { "allday_${it.eventId}_${it.startMillis}" }) { event ->
                EventRow(event = event, zoneId = zoneId, onEventClick = onEventClick, onEventLongClick = onEventLongClick)
            }
        }
        grid.columns.forEach { column ->
            if (column.blocks.isNotEmpty()) {
                item(key = "hdr_${column.epochDay}") {
                    DayHeader(column.epochDay)
                }
                items(column.blocks, key = { "blk_${it.event.eventId}_${it.event.startMillis}" }) { block ->
                    EventRow(event = block.event, zoneId = zoneId, onEventClick = onEventClick, onEventLongClick = onEventLongClick)
                }
            }
        }
    }
}

@Composable
private fun DayView(
    epochDay: Long,
    events: List<SlottedEvent>,
    zoneId: String,
    onAddOnDay: (Long) -> Unit,
    onEventClick: (String, String) -> Unit,
    onEventLongClick: (String, String, String, Long) -> Unit,
) {
    if (events.isEmpty()) {
        Column(
            Modifier.fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        ) {
            Text(
                text = stringResource(R.string.calendar_day_no_events),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            FilledTonalButton(onClick = { onAddOnDay(epochDay) }) {
                Icon(Icons.Filled.Add, contentDescription = null)
                Text(stringResource(R.string.calendar_add_event), modifier = Modifier.padding(start = 8.dp))
            }
        }
        return
    }
    LazyColumn(
        Modifier.fillMaxSize().testTag(CalendarTestTags.DAY_LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(events, key = { "day_${it.eventId}_${it.startMillis}" }) { event ->
            EventRow(event = event, zoneId = zoneId, onEventClick = onEventClick, onEventLongClick = onEventLongClick)
        }
    }
}

@Composable
private fun AgendaList(
    days: List<DaySlots>,
    zoneId: String,
    onEventClick: (String, String) -> Unit,
    onEventLongClick: (String, String, String, Long) -> Unit,
) {
    LazyColumn(
        Modifier.fillMaxSize().testTag(CalendarTestTags.AGENDA_LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        days.forEach { day ->
            item(key = "hdr_${day.epochDay}") { DayHeader(day.epochDay) }
            items(day.events, key = { "ev_${day.epochDay}_${it.eventId}_${it.startMillis}" }) { event ->
                EventRow(event = event, zoneId = zoneId, onEventClick = onEventClick, onEventLongClick = onEventLongClick)
            }
        }
    }
}

@Composable
private fun DayHeader(epochDay: Long) {
    val label = CalendarDateFormat.formatAllDay(epochDay)
    Text(label, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp))
}

@Composable
private fun EventRow(
    event: SlottedEvent,
    zoneId: String,
    onEventClick: (String, String) -> Unit,
    onEventLongClick: (String, String, String, Long) -> Unit,
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
            .combinedClickable(
                onClick = { onEventClick(event.calendarId, event.eventId) },
                onLongClick = { onEventLongClick(event.calendarId, event.eventId, event.title, event.startMillis) },
            )
            .testTag(CalendarTestTags.event(event.eventId)),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(event.title, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(time, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun EventActionSheetUi(
    sheet: EventActionSheet,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState()
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(CalendarTestTags.ACTION_SHEET),
    ) {
        Column(Modifier.fillMaxWidth().padding(bottom = 24.dp)) {
            Text(
                text = sheet.title,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
            )
            ListItem(
                headlineContent = { Text(stringResource(R.string.calendar_edit_event)) },
                leadingContent = { Icon(Icons.Filled.Edit, contentDescription = null) },
                modifier = Modifier.clickable(onClick = onEdit).testTag("calendar_action_edit"),
            )
            ListItem(
                headlineContent = { Text(stringResource(R.string.calendar_delete_event)) },
                leadingContent = { Icon(Icons.Filled.Delete, contentDescription = null) },
                modifier = Modifier.clickable(onClick = onDelete).testTag("calendar_action_delete"),
            )
        }
    }
}

@Composable
private fun EventEditorDialog(
    editor: EventEditorState,
    onChange: ((EventEditorState) -> EventEditorState) -> Unit,
    onSave: () -> Unit,
    onDismiss: () -> Unit,
    onDelete: (EventEditorState) -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(CalendarTestTags.EDITOR),
        title = {
            Text(
                stringResource(
                    if (editor.isEditing) R.string.calendar_edit_event else R.string.calendar_new_event_title,
                ),
            )
        },
        text = {
            // #12 - the form grew (timezone + recurrence + weekly BYDAY chips), so scroll the content
            // to keep every field reachable inside the AlertDialog's capped height.
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.verticalScroll(rememberScrollState()),
            ) {
                Text(
                    text = CalendarDateFormat.formatAllDay(editor.epochDay),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = editor.name,
                    onValueChange = { v -> onChange { it.copy(name = v, nameError = false) } },
                    label = { Text(stringResource(R.string.calendar_field_name)) },
                    isError = editor.nameError,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("calendar_field_name"),
                )
                if (editor.nameError) {
                    Text(
                        stringResource(R.string.calendar_name_required),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
                OutlinedTextField(
                    value = editor.description,
                    onValueChange = { v -> onChange { it.copy(description = v) } },
                    label = { Text(stringResource(R.string.calendar_field_description)) },
                    modifier = Modifier.fillMaxWidth().testTag("calendar_field_description"),
                )
                TimezoneField(editor = editor, onChange = onChange)
                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(stringResource(R.string.calendar_field_all_day))
                    Switch(
                        checked = editor.allDay,
                        onCheckedChange = { v -> onChange { it.copy(allDay = v) } },
                        modifier = Modifier.testTag("calendar_field_all_day"),
                    )
                }
                if (!editor.allDay) {
                    OutlinedTextField(
                        value = editor.startTime,
                        onValueChange = { v -> onChange { it.copy(startTime = v) } },
                        label = { Text(stringResource(R.string.calendar_field_start)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("calendar_field_start"),
                    )
                    OutlinedTextField(
                        value = editor.endTime,
                        onValueChange = { v -> onChange { it.copy(endTime = v) } },
                        label = { Text(stringResource(R.string.calendar_field_end)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("calendar_field_end"),
                    )
                }
                RecurrenceField(editor = editor, onChange = onChange)
            }
        },
        confirmButton = {
            TextButton(
                onClick = onSave,
                enabled = !editor.saving,
                modifier = Modifier.testTag("calendar_editor_save"),
            ) {
                Text(stringResource(R.string.calendar_save))
            }
        },
        dismissButton = {
            Row {
                if (editor.isEditing) {
                    TextButton(
                        onClick = { onDelete(editor) },
                        modifier = Modifier.testTag("calendar_editor_delete"),
                    ) {
                        Text(
                            stringResource(R.string.calendar_delete),
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.calendar_cancel))
                }
            }
        },
    )
}


@Composable
private fun TimezoneField(
    editor: EventEditorState,
    onChange: ((EventEditorState) -> EventEditorState) -> Unit,
) {
    val options = editor.timezoneOptions.ifEmpty { listOf(editor.timezone) }
    LabeledDropdown(
        label = stringResource(R.string.calendar_field_timezone),
        selectedText = editor.timezone,
        options = options,
        optionLabel = { it },
        onSelected = { tz -> onChange { it.copy(timezone = tz) } },
        testTag = "calendar_field_timezone",
    )
}

@Composable
private fun RecurrenceField(
    editor: EventEditorState,
    onChange: ((EventEditorState) -> EventEditorState) -> Unit,
) {
    val freqOptions: List<RecurrenceFreq?> = listOf(
        null,
        RecurrenceFreq.DAILY,
        RecurrenceFreq.WEEKLY,
        RecurrenceFreq.MONTHLY,
        RecurrenceFreq.YEARLY,
    )
    LabeledDropdown(
        label = stringResource(R.string.calendar_field_repeat),
        selectedText = recurrenceLabel(editor.recurrenceFreq),
        options = freqOptions,
        optionLabel = { recurrenceLabel(it) },
        onSelected = { f -> onChange { it.copy(recurrenceFreq = f) } },
        testTag = "calendar_field_repeat",
    )
    if (editor.recurrenceFreq != null) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = if (editor.recurrenceInterval <= 0) "" else editor.recurrenceInterval.toString(),
                onValueChange = { v ->
                    val n = v.filter { it.isDigit() }.take(3).toIntOrNull() ?: 0
                    onChange { it.copy(recurrenceInterval = n) }
                },
                label = { Text(stringResource(R.string.calendar_repeat_interval)) },
                singleLine = true,
                modifier = Modifier.weight(1f).testTag("calendar_field_repeat_interval"),
            )
            OutlinedTextField(
                value = editor.recurrenceCount?.toString().orEmpty(),
                onValueChange = { v ->
                    val n = v.filter { it.isDigit() }.take(4).toIntOrNull()
                    onChange { it.copy(recurrenceCount = n) }
                },
                label = { Text(stringResource(R.string.calendar_repeat_count)) },
                singleLine = true,
                modifier = Modifier.weight(1f).testTag("calendar_field_repeat_count"),
            )
        }
        // #12 - WEEKLY BYDAY multi-select (e.g. Mo/We/Fr). Empty = use the start day's weekday.
        if (editor.recurrenceFreq == RecurrenceFreq.WEEKLY) {
            WeeklyByDaySelector(selected = editor.recurrenceByDay, onChange = onChange)
        }
    }
}

/** #12 - the Mo..Su BYDAY toggle row for WEEKLY recurrence. */
@Composable
private fun WeeklyByDaySelector(
    selected: List<String>,
    onChange: (((EventEditorState) -> EventEditorState) -> Unit),
) {
    val days = listOf(
        "MO" to R.string.calendar_byday_mo,
        "TU" to R.string.calendar_byday_tu,
        "WE" to R.string.calendar_byday_we,
        "TH" to R.string.calendar_byday_th,
        "FR" to R.string.calendar_byday_fr,
        "SA" to R.string.calendar_byday_sa,
        "SU" to R.string.calendar_byday_su,
    )
    Column(Modifier.fillMaxWidth()) {
        Text(
            stringResource(R.string.calendar_repeat_on_days),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp, bottom = 4.dp),
        )
        Row(
            Modifier.fillMaxWidth().testTag("calendar_field_byday"),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            days.forEach { (code, label) ->
                val isOn = code in selected
                FilterChip(
                    selected = isOn,
                    onClick = {
                        onChange { ed ->
                            val next = if (isOn) ed.recurrenceByDay - code else ed.recurrenceByDay + code
                            ed.copy(recurrenceByDay = next)
                        }
                    },
                    label = { Text(stringResource(label)) },
                    modifier = Modifier.testTag("calendar_byday_$code"),
                )
            }
        }
    }
}

/**
 * #13 - choice dialog shown when deleting a RECURRING event: this occurrence only (EXDATE), this and
 * all following (sets the series UNTIL to before this occurrence), or the whole series.
 */
@Composable
private fun RecurringDeleteDialog(
    prompt: RecurringDeletePrompt,
    onThisOnly: () -> Unit,
    onThisAndFollowing: () -> Unit,
    onAll: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag("calendar_recurring_delete"),
        title = { Text(stringResource(R.string.calendar_delete_recurring_title)) },
        text = {
            Column {
                Text(
                    prompt.title,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(bottom = 12.dp),
                )
                ListItem(
                    headlineContent = { Text(stringResource(R.string.calendar_delete_this)) },
                    modifier = Modifier
                        .clickable(onClick = onThisOnly)
                        .testTag("calendar_delete_this"),
                )
                ListItem(
                    headlineContent = { Text(stringResource(R.string.calendar_delete_following)) },
                    modifier = Modifier
                        .clickable(onClick = onThisAndFollowing)
                        .testTag("calendar_delete_following"),
                )
                ListItem(
                    headlineContent = {
                        Text(
                            stringResource(R.string.calendar_delete_all),
                            color = MaterialTheme.colorScheme.error,
                        )
                    },
                    modifier = Modifier
                        .clickable(onClick = onAll)
                        .testTag("calendar_delete_all"),
                )
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.calendar_cancel)) }
        },
    )
}

@Composable
private fun recurrenceLabel(freq: RecurrenceFreq?): String = stringResource(
    when (freq) {
        RecurrenceFreq.DAILY -> R.string.calendar_repeat_daily
        RecurrenceFreq.WEEKLY -> R.string.calendar_repeat_weekly
        RecurrenceFreq.MONTHLY -> R.string.calendar_repeat_monthly
        RecurrenceFreq.YEARLY -> R.string.calendar_repeat_yearly
        RecurrenceFreq.UNKNOWN, null -> R.string.calendar_repeat_none
    },
)

/** A small labeled exposed-dropdown used for the timezone + recurrence pickers. */
@Composable
private fun <T> LabeledDropdown(
    label: String,
    selectedText: String,
    options: List<T>,
    optionLabel: @Composable (T) -> String,
    onSelected: (T) -> Unit,
    testTag: String,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = Modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = selectedText,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor()
                .testTag(testTag),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(optionLabel(option)) },
                    onClick = {
                        onSelected(option)
                        expanded = false
                    },
                )
            }
        }
    }
}
