@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.calendar.scheduler

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TimePicker
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.material3.rememberTimePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.data.scheduler.ActionTypes
import com.testlogon.android.feature.calendar.CalendarDateFormat
import java.time.Instant

/** AND-275 — stable test tags for the scheduler create/edit sheet. */
object SchedulerSheetTestTags {
    const val SHEET = "scheduler_sheet"
    const val SUBMIT = "scheduler_submit"
    const val TITLE_FIELD = "scheduler_title_field"
    const val PICK_DATETIME = "scheduler_pick_datetime"
    const val ERROR_BANNER = "scheduler_error_banner"
    fun typeChip(type: String) = "scheduler_type_$type"
}

/**
 * AND-275 — route-level scheduler create/edit screen. Hoists [SchedulerViewModel] and dismisses on the
 * Saved state.
 */
@Composable
fun SchedulerRoute(
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SchedulerViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    if (state is SchedulerUiState.Saved) {
        onDismiss()
        return
    }
    SchedulerSheet(
        state = state,
        onActionType = viewModel::onActionTypeSelected,
        onScheduledAt = viewModel::onScheduledAtChanged,
        onTitle = viewModel::onTitleChanged,
        onDescription = viewModel::onDescriptionChanged,
        onSubmit = viewModel::onSubmit,
        onRetry = viewModel::onRetry,
        onDismiss = onDismiss,
        modifier = modifier,
    )
}

@Composable
fun SchedulerSheet(
    state: SchedulerUiState,
    onActionType: (String) -> Unit,
    onScheduledAt: (Instant) -> Unit,
    onTitle: (String) -> Unit,
    onDescription: (String) -> Unit,
    onSubmit: () -> Unit,
    onRetry: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(SchedulerSheetTestTags.SHEET),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        when (state) {
            is SchedulerUiState.Loading ->
                CircularProgressIndicator()
            is SchedulerUiState.LoadError -> {
                Text(state.message, color = MaterialTheme.colorScheme.error)
                TextButton(onClick = onRetry) { Text(stringResource(R.string.action_retry)) }
            }
            is SchedulerUiState.Editing ->
                EditingBody(state, onActionType, onScheduledAt, onTitle, onDescription, onSubmit)
            is SchedulerUiState.Saved -> Unit // route dismisses
        }
    }
}

@Composable
private fun EditingBody(
    state: SchedulerUiState.Editing,
    onActionType: (String) -> Unit,
    onScheduledAt: (Instant) -> Unit,
    onTitle: (String) -> Unit,
    onDescription: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    val form = state.form

    Text(
        text = stringResource(
            if (state.mode is SchedulerMode.Edit) R.string.scheduler_edit_title else R.string.scheduler_create_title,
        ),
        style = MaterialTheme.typography.titleLarge,
    )

    if (state.transientError != null) {
        Text(
            text = state.transientError,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.testTag(SchedulerSheetTestTags.ERROR_BANNER),
        )
    }

    Text(stringResource(R.string.scheduler_field_type), style = MaterialTheme.typography.titleSmall)
    // Action type is immutable on edit (not in ScheduledActionUpdateIn), so only enable in Create mode.
    val typeEnabled = state.mode is SchedulerMode.Create
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        ActionTypes.ALL.forEach { type ->
            FilterChip(
                selected = form.actionType == type,
                onClick = { if (typeEnabled) onActionType(type) },
                enabled = typeEnabled,
                label = { Text(type) },
                modifier = Modifier
                    .testTag(SchedulerSheetTestTags.typeChip(type))
                    .then(
                        state.fieldErrors[SchedulerField.ActionType]?.let { msg ->
                            Modifier.semantics { error(msg) }
                        } ?: Modifier,
                    ),
            )
        }
    }

    DateTimePickerField(
        scheduledAt = form.scheduledAt,
        error = state.fieldErrors[SchedulerField.ScheduledAt],
        onScheduledAt = onScheduledAt,
    )

    OutlinedTextField(
        value = form.title,
        onValueChange = onTitle,
        label = { Text(stringResource(R.string.scheduler_field_title)) },
        singleLine = true,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SchedulerSheetTestTags.TITLE_FIELD)
            .then(
                state.fieldErrors[SchedulerField.Title]?.let { msg ->
                    Modifier.semantics { error(msg) }
                } ?: Modifier,
            ),
    )

    OutlinedTextField(
        value = form.description,
        onValueChange = onDescription,
        label = { Text(stringResource(R.string.scheduler_field_description)) },
        modifier = Modifier.fillMaxWidth(),
    )

    Button(
        onClick = onSubmit,
        enabled = !state.isSubmitting && !state.isOffline,
        modifier = Modifier.fillMaxWidth().testTag(SchedulerSheetTestTags.SUBMIT),
    ) {
        if (state.isSubmitting) {
            CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
        }
        Text(stringResource(R.string.scheduler_submit))
    }
}

@Composable
private fun DateTimePickerField(
    scheduledAt: Instant?,
    error: String?,
    onScheduledAt: (Instant) -> Unit,
) {
    var showDate by remember { mutableStateOf(false) }
    var showTime by remember { mutableStateOf(false) }
    var pendingDateMillis by remember { mutableStateOf<Long?>(null) }

    val label = scheduledAt?.let { CalendarDateFormat.formatDateTime(it.toEpochMilli(), "UTC") }
        ?: stringResource(R.string.scheduler_pick_datetime)

    OutlinedButton(
        onClick = { showDate = true },
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SchedulerSheetTestTags.PICK_DATETIME)
            .then(error?.let { msg -> Modifier.semantics { error(msg) } } ?: Modifier),
    ) {
        Text(label)
    }
    if (error != null) {
        Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
    }

    if (showDate) {
        val dateState = rememberDatePickerState(initialSelectedDateMillis = scheduledAt?.toEpochMilli())
        DatePickerDialog(
            onDismissRequest = { showDate = false },
            confirmButton = {
                TextButton(onClick = {
                    pendingDateMillis = dateState.selectedDateMillis
                    showDate = false
                    if (pendingDateMillis != null) showTime = true
                }) { Text(stringResource(R.string.scheduler_next)) }
            },
            dismissButton = {
                TextButton(onClick = { showDate = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        ) {
            DatePicker(state = dateState)
        }
    }

    if (showTime) {
        val timeState = rememberTimePickerState()
        DatePickerDialog(
            onDismissRequest = { showTime = false },
            confirmButton = {
                TextButton(onClick = {
                    val dateMillis = pendingDateMillis
                    if (dateMillis != null) {
                        val combined = dateMillis +
                            timeState.hour * 3_600_000L +
                            timeState.minute * 60_000L
                        onScheduledAt(Instant.ofEpochMilli(combined))
                    }
                    showTime = false
                }) { Text(stringResource(R.string.action_done)) }
            },
            dismissButton = {
                TextButton(onClick = { showTime = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        ) {
            Column(Modifier.padding(16.dp)) { TimePicker(state = timeState) }
        }
    }
}
