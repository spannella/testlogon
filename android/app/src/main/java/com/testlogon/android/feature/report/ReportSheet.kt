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

/**
 * MODX-7 - the ONE canonical set of report test tags. Every report surface (messaging + feed post /
 * comment / group comment / video / video-comment / profile / syndicate / catalog / broadcast) drives
 * the single [ReportSheet] and therefore exposes these SAME `report_*` tags. (Supersedes the old split
 * between the messaging `report_*` tags and the content `report_flow_*` tags - moderation-UI finding #7.)
 */
object ReportTestTags {
    const val SHEET = "report_sheet"
    const val STATEMENT_FIELD = "report_statement_field"
    const val COUNTER = "report_counter"
    const val SUBMIT = "report_submit"
    const val CANCEL = "report_cancel"
    const val LICENSING = "report_licensing"
    const val PROGRESS = "report_progress"
    const val SUCCESS = "report_success"
    const val ERROR = "report_error"
    const val RETRY = "report_retry"
    const val DONE = "report_done"
    fun topicRow(topic: ReportReason) = "report_topic_${topic.code}"
}

/** MODX-7 - localized label for a report topic (reuses the AND-163 reason strings). */
@Composable
fun topicLabel(topic: ReportReason): String = when (topic) {
    ReportReason.SPAM -> stringResource(R.string.report_reason_spam)
    ReportReason.HARASSMENT -> stringResource(R.string.report_reason_harassment)
    ReportReason.HATE -> stringResource(R.string.report_reason_hate)
    ReportReason.SEXUAL -> stringResource(R.string.report_reason_sexual)
    ReportReason.VIOLENCE_THREATS -> stringResource(R.string.report_reason_violence)
    ReportReason.OTHER -> stringResource(R.string.report_reason_other)
}

/**
 * MODX-7 - the SINGLE canonical report component: the reusable report flow as a Material 3
 * [ModalBottomSheet], parameterized by [target] (USER / Account / CONTENT / MESSAGE). Call sites hold a
 * `var reportTarget by remember` and render this (usually via [ContentReportSheetHost]) when non-null.
 * [onCompleted] hands back a [ReportOutcome]; [onDismiss] closes the sheet. Stateless aside from the
 * injected [viewModel]. This is the ONLY report sheet in the app - the old messaging radio sheet is gone.
 */
@Composable
fun ReportSheet(
    target: ReportTarget,
    onDismiss: () -> Unit,
    onCompleted: (ReportOutcome) -> Unit,
    modifier: Modifier = Modifier,
    // MOD-C3 - when non-null, an extra "copyright / licensing violation" entry is offered that routes to
    // the DMCA claim flow instead of a general moderation report. Only wired for CONTENT targets.
    onLicensing: (() -> Unit)? = null,
    viewModel: ReportViewModel = hiltViewModel(),
) {
    LaunchedEffect(target) { viewModel.start(target) }
    val state by viewModel.state.collectAsStateWithLifecycle()

    ModalBottomSheet(
        onDismissRequest = {
            onCompleted(ReportOutcome.CANCELLED)
            onDismiss()
        },
        modifier = modifier.testTag(ReportTestTags.SHEET),
    ) {
        ReportSheetContent(
            state = state,
            onLicensing = onLicensing,
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

/** MODX-7 - stateless content; renders one of three visual states off [ReportUiState.Phase]. */
@Composable
fun ReportSheetContent(
    state: ReportUiState,
    onTopicToggled: (ReportReason, Boolean) -> Unit,
    onReasonTextChanged: (String) -> Unit,
    onSubmit: () -> Unit,
    onRetry: () -> Unit,
    onDone: () -> Unit,
    onCancel: () -> Unit,
    onLicensing: (() -> Unit)? = null,
) {
    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        when (val phase = state.phase) {
            is ReportUiState.Phase.Success -> SuccessState(phase.alreadyReported, onDone)
            else -> EditingState(
                state = state,
                onLicensing = onLicensing,
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
    onLicensing: (() -> Unit)? = null,
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
                    .testTag(ReportTestTags.topicRow(topic)),
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
        modifier = Modifier.fillMaxWidth().testTag(ReportTestTags.STATEMENT_FIELD),
    )

    val counter = stringResource(R.string.report_counter, state.reasonLength, state.reasonMax)
    Text(
        text = counter,
        modifier = Modifier
            .testTag(ReportTestTags.COUNTER)
            .semantics { contentDescription = counter },
    )

    val errorPhase = state.phase as? ReportUiState.Phase.Error
    errorPhase?.let { err ->
        Text(
            text = err.message,
            modifier = Modifier
                .testTag(ReportTestTags.ERROR)
                .semantics { liveRegion = LiveRegionMode.Polite },
        )
    }

    if (submitting) {
        CircularProgressIndicator(
            Modifier.padding(8.dp)
                .testTag(ReportTestTags.PROGRESS)
                .semantics { liveRegion = LiveRegionMode.Polite },
        )
    } else if (errorPhase?.retryable == true) {
        Button(
            onClick = onRetry,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ReportTestTags.RETRY),
        ) { Text(stringResource(R.string.report_flow_retry)) }
    } else {
        Button(
            onClick = onSubmit,
            enabled = state.canSubmit,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ReportTestTags.SUBMIT),
        ) { Text(stringResource(R.string.report_submit)) }
    }

    // MOD-C3 - a copyright / licensing violation is NOT a general moderation report; it routes to the
    // DMCA claim flow (pre-filled with this content ref). Offered only when the host wired [onLicensing].
    if (onLicensing != null) {
        TextButton(
            onClick = onLicensing,
            enabled = !submitting,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ReportTestTags.LICENSING),
        ) { Text(stringResource(R.string.report_flow_licensing)) }
    }

    TextButton(
        onClick = onCancel,
        enabled = !submitting,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ReportTestTags.CANCEL),
    ) { Text(stringResource(R.string.action_cancel)) }
}

@Composable
private fun SuccessState(alreadyReported: Boolean, onDone: () -> Unit) {
    Column(
        Modifier.fillMaxWidth()
            .testTag(ReportTestTags.SUCCESS)
            .semantics { liveRegion = LiveRegionMode.Polite },
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        // MODX-15 - the reporter gets explicit "report received" feedback in-sheet, identical across every
        // surface (messaging + content). The dedup case shows the benign already-reported confirmation.
        Text(
            stringResource(
                if (alreadyReported) R.string.report_already_reported else R.string.report_confirmation,
            ),
        )
        Button(
            onClick = onDone,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ReportTestTags.DONE),
        ) { Text(stringResource(R.string.report_flow_done)) }
    }
}
