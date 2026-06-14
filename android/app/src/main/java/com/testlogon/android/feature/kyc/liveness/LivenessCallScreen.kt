@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.liveness

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TimePicker
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.material3.rememberTimePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.feature.kyc.liveness.model.LivenessCall
import com.testlogon.android.feature.kyc.liveness.model.LivenessCallStatus
import com.testlogon.android.feature.kyc.liveness.model.LivenessResult
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** AND-324 - stable testTags for the scheduled liveness-call screen. */
object LivenessCallTestTags {
    const val SCREEN = "liveness_screen"
    const val SCHEDULE = "liveness_schedule"
    const val DURATION = "liveness_duration"
    const val DATE = "liveness_date"
    const val JOIN = "liveness_join"
    const val CANCEL = "liveness_cancel"

    /** Per-call row tag: [ROW_PREFIX] + callId. */
    const val ROW_PREFIX = "liveness_call_"

    /** Per-call status badge tag: [STATUS_PREFIX] + callId. */
    const val STATUS_PREFIX = "liveness_status_"

    fun row(callId: String): String = ROW_PREFIX + callId
    fun status(callId: String): String = STATUS_PREFIX + callId
}

/** Duration bounds for a scheduled call (wire contract: 5..60, default 15). */
private const val DURATION_MIN = 5
private const val DURATION_MAX = 60
private const val DURATION_STEP = 5
private const val DURATION_DEFAULT = 15

/**
 * AND-324 - route-level scheduled liveness (video-verification) call screen. The required `caseId`
 * (a kyc_ case id) is a path argument read by the VM from SavedStateHandle; a blank case id lands the
 * screen in a non-recoverable "no KYC case" error.
 *
 * This is REAL REST scheduling, NOT in-app WebRTC: the "Join call" action opens the call's opaque
 * join_url EXTERNALLY via an ACTION_VIEW intent (Custom Tab / browser) using the screen's
 * [LocalContext]. There is NO camera / WebRTC / permission / manifest change.
 */
@Composable
fun LivenessCallRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: LivenessCallViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    LivenessCallScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onSchedule = { epochSec, duration, note -> viewModel.schedule(epochSec, duration, note) },
        onCancel = viewModel::cancel,
        onJoin = { callId -> viewModel.onJoinClicked(callId)?.let { openExternalUrl(context, it) } },
        modifier = modifier,
    )
}

/**
 * AND-324 - stateless scheduled liveness-call screen: a schedule form (date+time picker -> epoch seconds,
 * a 5..60 duration stepper, an optional note) plus a list of the user's calls, each with a status badge,
 * locale-aware scheduled time, duration, optional result, a "Join call" button (when join_url present),
 * and a "Cancel" button (when cancellable). The Join action is delegated to [onJoin] (the route opens the
 * url EXTERNALLY).
 */
@Composable
fun LivenessCallScreen(
    state: LivenessUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onSchedule: (Long, Int, String?) -> Unit,
    onCancel: (String) -> Unit,
    onJoin: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(LivenessCallTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.liveness_title)) },
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
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is LivenessUiState.Loading ->
                    CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))

                is LivenessUiState.Error -> LivenessErrorContent(
                    message = state.message,
                    recoverable = state.recoverable,
                    onRetry = onRefresh,
                )

                is LivenessUiState.Ready -> LivenessReadyContent(
                    state = state,
                    onSchedule = onSchedule,
                    onCancel = onCancel,
                    onJoin = onJoin,
                )
            }
        }
    }
}

@Composable
private fun LivenessErrorContent(
    message: String,
    recoverable: Boolean,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(text = message, style = MaterialTheme.typography.bodyLarge)
        if (recoverable) {
            Button(
                onClick = onRetry,
                modifier = Modifier.padding(top = 16.dp).heightIn(min = 48.dp),
            ) {
                Text(stringResource(R.string.liveness_retry))
            }
        }
    }
}

@Composable
private fun LivenessReadyContent(
    state: LivenessUiState.Ready,
    onSchedule: (Long, Int, String?) -> Unit,
    onCancel: (String) -> Unit,
    onJoin: (String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            ScheduleForm(
                scheduling = state.scheduling,
                formError = state.formError,
                onSchedule = onSchedule,
            )
        }
        items(items = state.calls, key = { it.callId }) { call ->
            LivenessCallRow(call = call, onCancel = onCancel, onJoin = onJoin)
        }
    }
}

/**
 * The schedule form: a date+time picker (REUSING AND-309 HostControlScreen's RescheduleDialog idiom)
 * that resolves to a Unix epoch-SECOND instant, a 5..60 duration stepper (default 15), an optional note,
 * and a "Schedule call" button disabled while a schedule is in flight.
 */
@Composable
private fun ScheduleForm(
    scheduling: Boolean,
    formError: String?,
    onSchedule: (Long, Int, String?) -> Unit,
) {
    var pickedEpochSec by remember { mutableStateOf<Long?>(null) }
    var duration by remember { mutableStateOf(DURATION_DEFAULT) }
    var note by remember { mutableStateOf("") }
    var showPicker by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.liveness_schedule_heading),
                style = MaterialTheme.typography.titleMedium,
            )

            val dateLabel = pickedEpochSec?.let { formatEpochSeconds(it) }
                ?: stringResource(R.string.liveness_pick_datetime)
            OutlinedButton(
                onClick = { showPicker = true },
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(LivenessCallTestTags.DATE),
            ) {
                Text(dateLabel)
            }

            // Duration stepper (5..60, step 5).
            Row(
                modifier = Modifier.fillMaxWidth().testTag(LivenessCallTestTags.DURATION),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                IconButton(
                    onClick = { duration = (duration - DURATION_STEP).coerceAtLeast(DURATION_MIN) },
                    enabled = duration > DURATION_MIN,
                    modifier = Modifier.heightIn(min = 48.dp),
                ) {
                    Text(
                        text = "-",
                        style = MaterialTheme.typography.titleLarge,
                    )
                }
                Text(
                    text = stringResource(R.string.liveness_duration_value, duration),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyLarge,
                )
                IconButton(
                    onClick = { duration = (duration + DURATION_STEP).coerceAtMost(DURATION_MAX) },
                    enabled = duration < DURATION_MAX,
                    modifier = Modifier.heightIn(min = 48.dp),
                ) {
                    Text(
                        text = "+",
                        style = MaterialTheme.typography.titleLarge,
                    )
                }
            }

            OutlinedTextField(
                value = note,
                onValueChange = { note = it },
                label = { Text(stringResource(R.string.liveness_note_label)) },
                modifier = Modifier.fillMaxWidth(),
            )

            if (formError != null) {
                Text(
                    text = formError,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Button(
                onClick = {
                    val epochSec = pickedEpochSec ?: return@Button
                    onSchedule(epochSec, duration, note.ifBlank { null })
                },
                enabled = !scheduling && pickedEpochSec != null,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(LivenessCallTestTags.SCHEDULE),
            ) {
                if (scheduling) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.heightIn(min = 20.dp))
                } else {
                    Text(stringResource(R.string.liveness_schedule_button))
                }
            }
        }
    }

    if (showPicker) {
        ScheduleDateTimeDialog(
            onDismiss = { showPicker = false },
            onConfirm = { epochSec ->
                pickedEpochSec = epochSec
                showPicker = false
            },
        )
    }
}

/**
 * A DatePicker + TimePicker pair that resolves to a Unix epoch-SECOND instant (local zone). Two-stage:
 * pick the date, then the time; confirming the time emits the combined epoch seconds. REUSES the AND-309
 * HostControlScreen.RescheduleDialog idiom.
 */
@Composable
private fun ScheduleDateTimeDialog(
    onDismiss: () -> Unit,
    onConfirm: (Long) -> Unit,
) {
    var pickedDate by remember { mutableStateOf<LocalDate?>(null) }
    val datePickerState = rememberDatePickerState()
    val timePickerState = rememberTimePickerState(is24Hour = false)

    val current = pickedDate
    if (current == null) {
        DatePickerDialog(
            onDismissRequest = onDismiss,
            confirmButton = {
                TextButton(
                    onClick = {
                        val millis = datePickerState.selectedDateMillis
                        if (millis != null) {
                            pickedDate = Instant.ofEpochMilli(millis)
                                .atZone(ZoneOffset.UTC)
                                .toLocalDate()
                        }
                    },
                ) { Text(stringResource(R.string.liveness_picker_next)) }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.liveness_picker_cancel)) }
            },
        ) {
            DatePicker(state = datePickerState)
        }
    } else {
        DatePickerDialog(
            onDismissRequest = onDismiss,
            confirmButton = {
                TextButton(
                    onClick = {
                        val dateTime = LocalDateTime.of(
                            current,
                            LocalTime.of(timePickerState.hour, timePickerState.minute),
                        )
                        onConfirm(dateTime.atZone(ZoneId.systemDefault()).toEpochSecond())
                    },
                ) { Text(stringResource(R.string.liveness_picker_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.liveness_picker_cancel)) }
            },
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                TimePicker(state = timePickerState)
            }
        }
    }
}

@Composable
private fun LivenessCallRow(
    call: LivenessCall,
    onCancel: (String) -> Unit,
    onJoin: (String) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(LivenessCallTestTags.row(call.callId)),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = formatEpochSeconds(call.scheduledAt.epochSecond),
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.weight(1f),
                )
                AssistChip(
                    onClick = {},
                    enabled = false,
                    label = { Text(stringResource(statusLabel(call.status))) },
                    modifier = Modifier.testTag(LivenessCallTestTags.status(call.callId)),
                )
            }

            Text(
                text = stringResource(R.string.liveness_duration_value, call.durationMinutes),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            call.result?.let { result ->
                Text(
                    text = stringResource(R.string.liveness_result_value, stringResource(resultLabel(result))),
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (call.joinUrl != null) {
                    Button(
                        onClick = { onJoin(call.callId) },
                        modifier = Modifier.heightIn(min = 48.dp).testTag(LivenessCallTestTags.JOIN),
                    ) {
                        Text(stringResource(R.string.liveness_join_button))
                    }
                }
                if (call.cancellable) {
                    OutlinedButton(
                        onClick = { onCancel(call.callId) },
                        modifier = Modifier.heightIn(min = 48.dp).testTag(LivenessCallTestTags.CANCEL),
                    ) {
                        Text(stringResource(R.string.liveness_cancel_button))
                    }
                }
            }
        }
    }
}

private fun statusLabel(status: LivenessCallStatus): Int = when (status) {
    LivenessCallStatus.SCHEDULED -> R.string.liveness_status_scheduled
    LivenessCallStatus.IN_PROGRESS -> R.string.liveness_status_in_progress
    LivenessCallStatus.PASSED -> R.string.liveness_status_passed
    LivenessCallStatus.FAILED -> R.string.liveness_status_failed
    LivenessCallStatus.CANCELLED -> R.string.liveness_status_cancelled
    LivenessCallStatus.EXPIRED -> R.string.liveness_status_expired
    LivenessCallStatus.UNKNOWN -> R.string.liveness_status_unknown
}

private fun resultLabel(result: LivenessResult): Int = when (result) {
    LivenessResult.PASSED -> R.string.liveness_result_passed
    LivenessResult.FAILED -> R.string.liveness_result_failed
    LivenessResult.UNKNOWN -> R.string.liveness_result_unknown
}

/** Locale-aware rendering of an epoch-SECOND instant in the device's local zone (scheduled_at * 1000). */
private fun formatEpochSeconds(epochSec: Long): String {
    val formatter = DateTimeFormatter
        .ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)
        .withZone(ZoneId.systemDefault())
    return formatter.format(Instant.ofEpochSecond(epochSec))
}

/** Opens [url] in an external browser / Custom Tab via ACTION_VIEW (best-effort). */
internal fun openExternalUrl(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, url.toUri()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        // No browser available; the CTA is best-effort.
    }
}
