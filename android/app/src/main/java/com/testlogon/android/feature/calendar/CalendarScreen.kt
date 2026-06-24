@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)

package com.testlogon.android.feature.calendar

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
    onEventLongClick: (calendarId: String, eventId: String, title: String) -> Unit,
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
                if (ed.eventId != null) onDeleteEvent(ed.calendarId, ed.eventId)
            },
        )
    }

    val sheet = content?.actionSheet
    if (sheet != null) {
        EventActionSheetUi(
            sheet = sheet,
            onEdit = { onEditEvent(sheet.calendarId, sheet.eventId) },
            onDelete = { onDeleteEvent(sheet.calendarId, sheet.eventId) },
            onDismiss = onDismissActions,
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
    onEventLongClick: (String, String, String) -> Unit,
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
    onEventLongClick: (String, String, String) -> Unit,
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
    onEventLongClick: (String, String, String) -> Unit,
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
                        onLongClick = { onEventLongClick(event.calendarId, event.eventId, event.title) },
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
    onEventLongClick: (String, String, String) -> Unit,
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
            items(grid.allDayLane, key = { "allday_${it.eventId}" }) { event ->
                EventRow(event = event, zoneId = zoneId, onEventClick = onEventClick, onEventLongClick = onEventLongClick)
            }
        }
        grid.columns.forEach { column ->
            if (column.blocks.isNotEmpty()) {
                item(key = "hdr_${column.epochDay}") {
                    DayHeader(column.epochDay)
                }
                items(column.blocks, key = { "blk_${it.event.eventId}" }) { block ->
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
    onEventLongClick: (String, String, String) -> Unit,
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
        items(events, key = { "day_${it.eventId}" }) { event ->
            EventRow(event = event, zoneId = zoneId, onEventClick = onEventClick, onEventLongClick = onEventLongClick)
        }
    }
}

@Composable
private fun AgendaList(
    days: List<DaySlots>,
    zoneId: String,
    onEventClick: (String, String) -> Unit,
    onEventLongClick: (String, String, String) -> Unit,
) {
    LazyColumn(
        Modifier.fillMaxSize().testTag(CalendarTestTags.AGENDA_LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        days.forEach { day ->
            item(key = "hdr_${day.epochDay}") { DayHeader(day.epochDay) }
            items(day.events, key = { "ev_${day.epochDay}_${it.eventId}" }) { event ->
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
    onEventLongClick: (String, String, String) -> Unit,
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
                onLongClick = { onEventLongClick(event.calendarId, event.eventId, event.title) },
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
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
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
