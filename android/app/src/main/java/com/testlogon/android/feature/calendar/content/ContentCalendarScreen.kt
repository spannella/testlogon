@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)

package com.testlogon.android.feature.calendar.content

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ChevronLeft
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.contentcalendar.ContentItemType
import com.testlogon.android.data.contentcalendar.ScheduledContent
import com.testlogon.android.data.contentcalendar.ScheduledStatus
import com.testlogon.android.feature.calendar.CalendarDateFormat

/** AND-274 — stable test tags for the content-calendar screen. */
object ContentCalendarTestTags {
    const val SCREEN = "content_calendar_screen"
    const val LIST = "content_calendar_list"
    const val PREV = "content_calendar_prev"
    const val NEXT = "content_calendar_next"
    const val TODAY = "content_calendar_today"
    fun item(id: String) = "content_calendar_item_$id"
}

/**
 * AND-274 — route-level content-calendar screen. Hoists [ContentCalendarViewModel], collects state, and
 * exposes the row-tap callback that hands off to the AND-275 scheduler detail/edit route.
 */
@Composable
fun ContentCalendarRoute(
    onBack: () -> Unit,
    onItemClick: (contentId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ContentCalendarViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    ContentCalendarScreen(
        state = state,
        onBack = onBack,
        onItemClick = onItemClick,
        onPrev = viewModel::previousMonth,
        onNext = viewModel::nextMonth,
        onToday = viewModel::goToToday,
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}

@Composable
fun ContentCalendarScreen(
    state: ContentCalendarUiState,
    onBack: () -> Unit,
    onItemClick: (String) -> Unit,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    onToday: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ContentCalendarTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.content_calendar_title)) },
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
            PeriodRow(
                focusEpochDay = state.focusEpochDay,
                onPrev = onPrev,
                onNext = onNext,
                onToday = onToday,
            )
            when (state) {
                is ContentCalendarUiState.Loading -> LoadingState()
                is ContentCalendarUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.content_calendar_empty_title),
                        body = stringResource(R.string.content_calendar_empty_body),
                    )
                is ContentCalendarUiState.Error ->
                    if (state.isOffline) {
                        OfflineBanner(onRetry = onRetry)
                    } else {
                        ErrorState(message = state.message, onRetry = onRetry)
                    }
                is ContentCalendarUiState.Content -> {
                    if (state.isStale) OfflineBanner(onRetry = onRetry)
                    ContentList(state, onItemClick)
                }
            }
        }
    }
}

@Composable
private fun PeriodRow(
    focusEpochDay: Long,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    onToday: () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onPrev, modifier = Modifier.testTag(ContentCalendarTestTags.PREV)) {
            Icon(Icons.Filled.ChevronLeft, contentDescription = stringResource(R.string.calendar_nav_previous))
        }
        val monthLabel = CalendarDateFormat.formatMonthYear(
            focusEpochDay * CalendarMathMillisPerDay, "UTC",
        )
        Text(monthLabel, style = MaterialTheme.typography.titleMedium)
        IconButton(onClick = onNext, modifier = Modifier.testTag(ContentCalendarTestTags.NEXT)) {
            Icon(Icons.Filled.ChevronRight, contentDescription = stringResource(R.string.calendar_nav_next))
        }
        Box(Modifier.weight(1f))
        TextButton(onClick = onToday, modifier = Modifier.testTag(ContentCalendarTestTags.TODAY)) {
            Text(stringResource(R.string.calendar_today))
        }
    }
}

@Composable
private fun ContentList(content: ContentCalendarUiState.Content, onItemClick: (String) -> Unit) {
    LazyColumn(
        Modifier.fillMaxSize().testTag(ContentCalendarTestTags.LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        content.days.forEach { day ->
            stickyHeader(key = "h_${day.epochDay}") { DateHeader(day.epochDay) }
            items(day.items, key = { it.id }) { item ->
                ScheduledContentRow(item, onClick = { onItemClick(item.id) })
            }
        }
    }
}

@Composable
private fun DateHeader(epochDay: Long) {
    Surface(color = MaterialTheme.colorScheme.surface, modifier = Modifier.fillMaxWidth()) {
        Text(
            text = CalendarDateFormat.formatAllDay(epochDay),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.padding(vertical = 4.dp).semantics { heading() },
        )
    }
}

@Composable
private fun ScheduledContentRow(item: ScheduledContent, onClick: () -> Unit) {
    val timeText = item.localTime
        ?: CalendarDateFormat.formatTime(item.scheduledAt.toEpochMilli(), item.timezone ?: "UTC")
    val typeLabel = stringResource(contentTypeLabel(item.type))
    val statusLabel = stringResource(scheduledStatusLabel(item.status))
    Surface(
        tonalElevation = 1.dp,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag(ContentCalendarTestTags.item(item.id)),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(
                item.title,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                timeText,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(
                Modifier.fillMaxWidth().padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AssistChip(onClick = onClick, label = { Text(typeLabel) })
                AssistChip(onClick = onClick, label = { Text(statusLabel) })
            }
        }
    }
}

private fun contentTypeLabel(type: ContentItemType): Int = when (type) {
    ContentItemType.POST -> R.string.content_calendar_type_post
    ContentItemType.BROADCAST -> R.string.content_calendar_type_broadcast
    ContentItemType.VOD -> R.string.content_calendar_type_vod
    ContentItemType.UNKNOWN -> R.string.content_calendar_type_unknown
}

private fun scheduledStatusLabel(status: ScheduledStatus): Int = when (status) {
    ScheduledStatus.SCHEDULED -> R.string.content_calendar_status_scheduled
    ScheduledStatus.OVERDUE -> R.string.content_calendar_status_overdue
    ScheduledStatus.CANCELLED -> R.string.content_calendar_status_cancelled
    ScheduledStatus.UNKNOWN -> R.string.content_calendar_status_unknown
}

/** Local copy of the day-millis constant to avoid importing the pure-math object into the UI file. */
private const val CalendarMathMillisPerDay = 86_400_000L
