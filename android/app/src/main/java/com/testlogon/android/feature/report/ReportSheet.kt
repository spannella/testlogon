@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.report

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.data.messaging.report.ReportReason
import com.testlogon.android.data.report.ReportOutcome
import com.testlogon.android.data.report.ReportTarget

/** AND-383 - test tags for the cross-cutting report sheet (used by the Compose UI tests). */
object ReportFlowTestTags {
    const val SHEET = "report_flow_sheet"
    const val REASON_FIELD = "report_flow_reason_field"
    const val COUNTER = "report_flow_counter"
    const val SUBMIT = "report_flow_submit"
    const val CANCEL = "report_flow_cancel"
    const val PROGRESS = "report_flow_progress"
    const val SUCCESS = "report_flow_success"
    const val ERROR = "report_flow_error"
    const val RETRY = "report_flow_retry"
    const val DONE = "report_flow_done"
    fun topicRow(topic: ReportReason) = "report_flow_topic_${topic.code}"
}

/** AND-383 - localized label for a report topic (reuses the AND-163 reason strings). */
@Composable
fun topicLabel(topic: ReportReason): String = when (topic) {
    ReportReason.SEXUAL -> stringResource(R.string.report_reason_sexual)
    ReportReason.EXTORTION -> stringResource(R.string.report_reason_extortion)
    ReportReason.CRIMINAL -> stringResource(R.string.report_reason_criminal)
    ReportReason.SPAM -> stringResource(R.string.report_reason_spam)
    ReportReason.RACIST -> stringResource(R.string.report_reason_racist)
}

/**
 * AND-383 - the public entry point: the reusable report flow as a Material 3 [ModalBottomSheet],
 * parameterized by [target]. Call sites hold a `var reportTarget by remember` and render this when
 * non-null. [onCompleted] hands back a [ReportOutcome]; [onDismiss] closes the sheet. The composable is
 * stateless aside from the injected [viewModel].
 */
@Composable
fun ReportSheet(
    target: ReportTarget,
    onDismiss: () -> Unit,
    onCompleted: (ReportOutcome) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ReportViewModel = hiltViewModel(),
) {
    LaunchedEffect(target) { viewModel.start(target) }
    val state by viewModel.state.collectAsStateWithLifecycle()

    ModalBottomSheet(
        onDismissRequest = {
            onCompleted(ReportOutcome.CANCELLED)
            onDismiss()
        },
        modifier = modifier.testTag(ReportFlowTestTags.SHEET),
    ) {
        ReportSheetContent(
            state = state,
            onTopicToggled = viewModel::onTopicToggled,
            onReasonTextChanged = viewModel::onReasonTextChanged,
            onSubmit = viewModel::submit,
            onRetry = viewModel::retry,
            onDone = {
                onCompleted(viewModel.outcome())
                onDismiss()
            },
            onCancel = {
                onCompleted(ReportOutcome.CANCELLED)
                onDismiss()
            },
        )
    }
}

/** AND-383 - stateless content; renders one of three visual states off [ReportUiState.Phase]. */
@Composable
fun ReportSheetContent(
    state: ReportUiState,
    onTopicToggled: (ReportReason, Boolean) -> Unit,
    onReasonTextChanged: (String) -> Unit,
    onSubmit: () -> Unit,
    onRetry: () -> Unit,
    onDone: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        when (val phase = state.phase) {
            is ReportUiState.Phase.Success -> SuccessState(phase.alreadyReported, onDone)
            else -> EditingState(
                state = state,
                onTopicToggled = onTopicToggled,
                onReasonTextChanged = onReasonTextChanged,
                onSubmit = onSubmit,
                onRetry = onRetry,
                onCancel = onCancel,
            )
        }
    }
}

@Composable
private fun EditingState(
    state: ReportUiState,
    onTopicToggled: (ReportReason, Boolean) -> Unit,
    onReasonTextChanged: (String) -> Unit,
    onSubmit: () -> Unit,
    onRetry: () -> Unit,
    onCancel: () -> Unit,
) {
    val submitting = state.phase == ReportUiState.Phase.Submitting

    Text(stringResource(R.string.report_flow_title))

    Column(Modifier.fillMaxWidth()) {
        state.topics.forEach { topic ->
            val checked = topic in state.selectedTopics
            val label = topicLabel(topic)
            val desc = stringResource(
                if (checked) R.string.report_flow_topic_checked else R.string.report_flow_topic_unchecked,
                label,
            )
            Row(
                Modifier.fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .toggleable(
                        value = checked,
                        enabled = !submitting,
                        role = Role.Checkbox,
                        onValueChange = { onTopicToggled(topic, it) },
                    )
                    .semantics { contentDescription = desc }
                    .testTag(ReportFlowTestTags.topicRow(topic)),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Checkbox(checked = checked, onCheckedChange = null)
                Text(text = label, modifier = Modifier.padding(start = 8.dp))
            }
        }
    }

    OutlinedTextField(
        value = state.reasonText,
        onValueChange = onReasonTextChanged,
        enabled = !submitting,
        label = { Text(stringResource(R.string.report_flow_reason_label)) },
        placeholder = { Text(stringResource(R.string.report_statement_hint)) },
        modifier = Modifier.fillMaxWidth().testTag(ReportFlowTestTags.REASON_FIELD),
    )

    val counter = stringResource(R.string.report_counter, state.reasonLength, state.reasonMax)
    Text(
        text = counter,
        modifier = Modifier
            .testTag(ReportFlowTestTags.COUNTER)
            .semantics { contentDescription = counter },
    )

    val errorPhase = state.phase as? ReportUiState.Phase.Error
    errorPhase?.let { err ->
        Text(
            text = err.message,
            modifier = Modifier
                .testTag(ReportFlowTestTags.ERROR)
                .semantics { liveRegion = LiveRegionMode.Polite },
        )
    }

    if (submitting) {
        CircularProgressIndicator(
            Modifier.padding(8.dp)
                .testTag(ReportFlowTestTags.PROGRESS)
                .semantics { liveRegion = LiveRegionMode.Polite },
        )
    } else if (errorPhase?.retryable == true) {
        Button(
            onClick = onRetry,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ReportFlowTestTags.RETRY),
        ) { Text(stringResource(R.string.report_flow_retry)) }
    } else {
        Button(
            onClick = onSubmit,
            enabled = state.canSubmit,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ReportFlowTestTags.SUBMIT),
        ) { Text(stringResource(R.string.report_submit)) }
    }

    TextButton(
        onClick = onCancel,
        enabled = !submitting,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ReportFlowTestTags.CANCEL),
    ) { Text(stringResource(R.string.action_cancel)) }
}

@Composable
private fun SuccessState(alreadyReported: Boolean, onDone: () -> Unit) {
    Column(
        Modifier.fillMaxWidth()
            .testTag(ReportFlowTestTags.SUCCESS)
            .semantics { liveRegion = LiveRegionMode.Polite },
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            stringResource(
                if (alreadyReported) R.string.report_already_reported else R.string.report_confirm_title,
            ),
        )
        Button(
            onClick = onDone,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ReportFlowTestTags.DONE),
        ) { Text(stringResource(R.string.report_flow_done)) }
    }
}
