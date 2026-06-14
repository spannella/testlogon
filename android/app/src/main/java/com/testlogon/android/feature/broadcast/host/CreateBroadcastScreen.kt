@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.host

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import kotlinx.coroutines.flow.collectLatest

/** AND-307 — stable testTags for the host create/schedule (Go Live) screen. */
object CreateBroadcastTestTags {
    const val SCREEN = "create_broadcast_screen"
    const val TITLE = "broadcast_title"
    const val DESCRIPTION = "broadcast_description"
    const val SCHEDULE_TOGGLE = "broadcast_schedule_toggle"
    const val SCHEDULED_AT = "broadcast_scheduled_at"
    const val SUBMIT = "broadcast_submit"
    const val CANCEL_SCHEDULE = "broadcast_cancel_schedule"
}

/**
 * AND-307 — Go-Live entry point. Collects the ViewModel state, consumes the one-shot finish effect to
 * pop back to the host, and delegates rendering to the stateless [CreateBroadcastScreen].
 */
@Composable
fun CreateBroadcastRoute(
    onFinished: () -> Unit,
    viewModel: CreateBroadcastViewModel = hiltViewModel(),
    // AND-308 — after a session is created/scheduled, the host can move on to the ingest (publish) screen.
    onSessionReady: (String) -> Unit = { onFinished() },
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collectLatest { effect ->
            when (effect) {
                is CreateBroadcastEffect.Finished -> onSessionReady(effect.sessionId)
            }
        }
    }
    CreateBroadcastScreen(
        state = state,
        onTitleChange = viewModel::setTitle,
        onDescriptionChange = viewModel::setDescription,
        onToggleScheduleLater = viewModel::toggleScheduleLater,
        onScheduledAtChange = viewModel::setScheduledAt,
        onSubmit = viewModel::create,
        onCancelSchedule = viewModel::cancelSchedule,
        onBack = onFinished,
    )
}

/**
 * AND-307 — stateless Go-Live form: title (maps to wire `name`), description, a "schedule for later"
 * toggle revealing a numeric epoch-second input (a Material date/time picker is deferred; a numeric
 * field keeps the surface fully testable), the create/schedule button (disabled while submitting or the
 * title is blank), and a cancel-schedule action once a scheduled session exists.
 */
@Composable
fun CreateBroadcastScreen(
    state: CreateBroadcastUiState,
    onTitleChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onToggleScheduleLater: (Boolean) -> Unit,
    onScheduledAtChange: (Long?) -> Unit,
    onSubmit: () -> Unit,
    onCancelSchedule: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(CreateBroadcastTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.broadcast_go_live_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.broadcast_go_live_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            OutlinedTextField(
                value = state.title,
                onValueChange = onTitleChange,
                singleLine = true,
                isError = state.fieldErrors.containsKey(CreateBroadcastViewModel.FIELD_NAME),
                label = { Text(stringResource(R.string.broadcast_title_label)) },
                supportingText = state.fieldErrors[CreateBroadcastViewModel.FIELD_NAME]?.let { msg ->
                    @Composable { Text(msg) }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateBroadcastTestTags.TITLE),
            )

            OutlinedTextField(
                value = state.description,
                onValueChange = onDescriptionChange,
                label = { Text(stringResource(R.string.broadcast_description_label)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 96.dp)
                    .testTag(CreateBroadcastTestTags.DESCRIPTION),
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = stringResource(R.string.broadcast_schedule_later),
                    style = MaterialTheme.typography.bodyLarge,
                )
                val toggleCd = stringResource(R.string.broadcast_schedule_later)
                Switch(
                    checked = state.scheduleForLater,
                    onCheckedChange = onToggleScheduleLater,
                    modifier = Modifier
                        .testTag(CreateBroadcastTestTags.SCHEDULE_TOGGLE)
                        .clearAndSetSemantics { contentDescription = toggleCd },
                )
            }

            if (state.scheduleForLater) {
                OutlinedTextField(
                    value = state.scheduledAtEpochSeconds?.toString().orEmpty(),
                    onValueChange = { raw -> onScheduledAtChange(raw.trim().toLongOrNull()) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    isError = state.fieldErrors.containsKey(CreateBroadcastViewModel.FIELD_SCHEDULED_AT),
                    label = { Text(stringResource(R.string.broadcast_scheduled_at_label)) },
                    supportingText = state.fieldErrors[CreateBroadcastViewModel.FIELD_SCHEDULED_AT]?.let { msg ->
                        @Composable { Text(msg) }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(CreateBroadcastTestTags.SCHEDULED_AT),
                )
            }

            state.error?.let { message ->
                Text(
                    text = message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            Button(
                onClick = onSubmit,
                enabled = state.canSubmit,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(CreateBroadcastTestTags.SUBMIT),
            ) {
                if (state.isSubmitting) {
                    CircularProgressIndicator(modifier = Modifier.heightIn(min = 20.dp))
                } else {
                    val label = if (state.scheduleForLater) {
                        R.string.broadcast_schedule
                    } else {
                        R.string.broadcast_create
                    }
                    Text(stringResource(label))
                }
            }

            if (state.canCancelSchedule) {
                OutlinedButton(
                    onClick = onCancelSchedule,
                    enabled = !state.isSubmitting,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(CreateBroadcastTestTags.CANCEL_SCHEDULE),
                ) {
                    Text(stringResource(R.string.broadcast_cancel_schedule))
                }
            }
        }
    }
}
