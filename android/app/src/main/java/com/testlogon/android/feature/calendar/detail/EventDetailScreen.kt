@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.calendar.detail

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Event
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.calendar.CalendarEvent
import com.testlogon.android.feature.calendar.CalendarDateFormat
import kotlinx.coroutines.launch

/** AND-272 — stable test tags for the event detail screen. */
object EventDetailTestTags {
    const val SCREEN = "event_detail_screen"
    const val TITLE = "event_detail_title"
    const val WHEN = "event_detail_when"
    const val DESCRIPTION = "event_detail_description"
    const val ATTENDEES = "event_detail_attendees"
    const val RECURRENCE = "event_detail_recurrence"
    const val SHARE = "event_detail_share"
    const val ADD_TO_CALENDAR = "event_detail_add_to_calendar"

    /** AND-391 — public iCal download affordance. */
    const val DOWNLOAD_ICS = "event_detail_download_ics"
    const val UNAVAILABLE = "event_detail_unavailable"
    const val FORBIDDEN = "event_detail_forbidden"
}

/**
 * AND-272 — route-level event detail. Hoists [EventDetailViewModel], collects state, wires the share /
 * add-to-calendar intents through the injectable [EventIntents] seam (resolved in composable scope,
 * never inside a non-composable lambda), with Snackbar fallback when no handler app exists.
 */
@Composable
fun EventDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: EventDetailViewModel = hiltViewModel(),
    intents: EventIntents = remember { EventIntents() },
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    // Resolve copy in composable scope (no stringResource inside the action lambdas).
    val noShareApp = stringResource(R.string.event_detail_no_share_app)
    val noCalendarApp = stringResource(R.string.event_detail_no_calendar_app)
    val shareSubjectTemplate = stringResource(R.string.event_detail_share_subject)
    // AND-391 — no-handler fallback for the public iCal download (ACTION_VIEW).
    val noBrowserApp = stringResource(R.string.event_detail_no_browser_app)

    EventDetailScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::retry,
        onShare = { content ->
            val subject = shareSubjectTemplate.format(content.event.name)
            val ok = intents.share(
                context,
                EventShareContent(url = content.publicShareUrl, subject = subject),
            )
            if (!ok) scope.launch { snackbarHostState.showSnackbar(noShareApp) }
        },
        onAddToCalendar = { content ->
            val event = content.event
            val ok = intents.addToCalendar(
                context,
                EventCalendarInsert(
                    title = event.name,
                    description = event.description.ifBlank { null },
                    beginMillis = event.startAt?.toEpochMilli(),
                    endMillis = event.endAt?.toEpochMilli(),
                    allDay = event.allDay,
                ),
            )
            if (!ok) scope.launch { snackbarHostState.showSnackbar(noCalendarApp) }
        },
        onDownloadIcs = { content ->
            // AND-391 — open the public iCal URL (unauthenticated GET) via the browser/download manager.
            val ok = intents.openUrl(context, content.publicIcalUrl)
            if (!ok) scope.launch { snackbarHostState.showSnackbar(noBrowserApp) }
        },
        modifier = modifier,
    )
}

@Composable
fun EventDetailScreen(
    state: EventDetailUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onShare: (EventDetailUiState.Content) -> Unit,
    onAddToCalendar: (EventDetailUiState.Content) -> Unit,
    onDownloadIcs: (EventDetailUiState.Content) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(EventDetailTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text(stringResource(R.string.event_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    if (state is EventDetailUiState.Content) {
                        IconButton(
                            onClick = { onShare(state) },
                            modifier = Modifier.testTag(EventDetailTestTags.SHARE),
                        ) {
                            Icon(Icons.Filled.Share, contentDescription = stringResource(R.string.event_detail_share))
                        }
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                EventDetailUiState.Loading -> LoadingState()
                EventDetailUiState.Unavailable -> ErrorState(
                    modifier = Modifier.testTag(EventDetailTestTags.UNAVAILABLE),
                    title = stringResource(R.string.event_detail_unavailable_title),
                    message = stringResource(R.string.event_detail_unavailable_body),
                    onRetry = onBack,
                    retryLabel = stringResource(R.string.action_back),
                )
                EventDetailUiState.Forbidden -> ErrorState(
                    modifier = Modifier.testTag(EventDetailTestTags.FORBIDDEN),
                    title = stringResource(R.string.event_detail_forbidden_title),
                    message = stringResource(R.string.event_detail_forbidden_body),
                    onRetry = onBack,
                    retryLabel = stringResource(R.string.action_back),
                )
                is EventDetailUiState.Error -> ErrorState(message = state.message, onRetry = onRetry)
                is EventDetailUiState.Content -> EventDetailContent(
                    content = state,
                    onAddToCalendar = onAddToCalendar,
                    onDownloadIcs = onDownloadIcs,
                )
            }
        }
    }
}

@Composable
private fun EventDetailContent(
    content: EventDetailUiState.Content,
    onAddToCalendar: (EventDetailUiState.Content) -> Unit,
    onDownloadIcs: (EventDetailUiState.Content) -> Unit,
) {
    val event = content.event
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = event.name,
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.testTag(EventDetailTestTags.TITLE),
        )

        Section(stringResource(R.string.event_detail_when), EventDetailTestTags.WHEN) {
            Text(whenText(event, content.displayZoneId))
            if (content.zoneMismatch) {
                Text(
                    text = content.displayZoneId,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        event.recurrence?.let { recurrence ->
            RecurrenceSummary.build(recurrence)?.let { summary ->
                Section(stringResource(R.string.event_detail_recurring), EventDetailTestTags.RECURRENCE) {
                    Text(summary)
                }
            }
        }

        if (event.description.isNotBlank()) {
            Section(stringResource(R.string.event_detail_description), EventDetailTestTags.DESCRIPTION) {
                Text(event.description)
            }
        }

        // Attendee PII is never shown on the public path (the reduced payload has none anyway).
        if (!content.isPublic && event.attendees.isNotEmpty()) {
            Section(stringResource(R.string.event_detail_attendees), EventDetailTestTags.ATTENDEES) {
                Text(stringResource(R.string.event_detail_attendee_count, event.attendees.size))
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { onAddToCalendar(content) },
                modifier = Modifier.testTag(EventDetailTestTags.ADD_TO_CALENDAR),
            ) {
                Icon(Icons.Filled.Event, contentDescription = null)
                Text(
                    stringResource(R.string.event_detail_add_to_calendar),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }

            // AND-391 — public iCal download (verified affordance, mirrors web getPublicIcalUrl).
            OutlinedButton(
                onClick = { onDownloadIcs(content) },
                modifier = Modifier.testTag(EventDetailTestTags.DOWNLOAD_ICS),
            ) {
                Icon(Icons.Filled.Download, contentDescription = null)
                Text(
                    stringResource(R.string.event_download_ics),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun Section(label: String, tag: String, content: @Composable () -> Unit) {
    Surface(tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth().testTag(tag)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            content()
        }
    }
}

private fun whenText(event: CalendarEvent, zoneId: String): String {
    if (event.allDay) {
        return event.allDayDate?.let { CalendarDateFormat.formatAllDay(it.toEpochDay()) }.orEmpty()
    }
    val start = event.startAt?.toEpochMilli()
    val end = event.endAt?.toEpochMilli()
    return when {
        start != null && end != null -> CalendarDateFormat.formatRange(start, end, zoneId)
        start != null -> CalendarDateFormat.formatDateTime(start, zoneId)
        else -> ""
    }
}
