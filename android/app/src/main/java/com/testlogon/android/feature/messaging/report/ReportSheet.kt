@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.messaging.report

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.messaging.report.ReportReason

/** AND-163 — test tags for the report sheet (used by Compose UI tests). */
object ReportTestTags {
    const val SHEET = "report_sheet"
    const val STATEMENT_FIELD = "report_statement_field"
    const val COUNTER = "report_counter"
    const val SUBMIT = "report_submit"
    const val CANCEL = "report_cancel"
    fun reasonRow(reason: ReportReason) = "report_reason_${reason.code}"
}

/** AND-163 — localized label for a report reason. */
@Composable
fun reasonLabel(reason: ReportReason): String = when (reason) {
    ReportReason.SEXUAL -> stringResource(R.string.report_reason_sexual)
    ReportReason.EXTORTION -> stringResource(R.string.report_reason_extortion)
    ReportReason.CRIMINAL -> stringResource(R.string.report_reason_criminal)
    ReportReason.SPAM -> stringResource(R.string.report_reason_spam)
    ReportReason.RACIST -> stringResource(R.string.report_reason_racist)
}

/**
 * AND-163 — the report bottom sheet. Reason rows are a single-choice [selectableGroup] with
 * [Role.RadioButton] semantics; the statement is required (>=5 chars) with a live character counter.
 * Submit is disabled until [ReportUiState.canSubmit]. All copy is externalized to strings.xml.
 */
@Composable
fun ReportSheet(
    state: ReportUiState,
    onReason: (ReportReason) -> Unit,
    onStatement: (String) -> Unit,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
) {
    if (!state.visible) return
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(ReportTestTags.SHEET),
    ) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(stringResource(R.string.report_title))

            Column(Modifier.fillMaxWidth().selectableGroup()) {
                state.availableReasons.forEach { reason ->
                    val selected = reason == state.selectedReason
                    val label = reasonLabel(reason)
                    Column(
                        Modifier.fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .selectable(
                                selected = selected,
                                role = Role.RadioButton,
                                onClick = { onReason(reason) },
                            )
                            .testTag(ReportTestTags.reasonRow(reason)),
                    ) {
                        ReasonRow(label = label, selected = selected)
                    }
                }
            }

            OutlinedTextField(
                value = state.statement,
                onValueChange = onStatement,
                label = { Text(stringResource(R.string.report_statement_hint)) },
                isError = state.error != null,
                modifier = Modifier.fillMaxWidth().testTag(ReportTestTags.STATEMENT_FIELD),
            )

            val counter = stringResource(
                R.string.report_counter,
                state.statementLength,
                ReportUiState.STATEMENT_MAX,
            )
            Text(
                text = counter,
                modifier = Modifier
                    .testTag(ReportTestTags.COUNTER)
                    .semantics {
                        liveRegion = LiveRegionMode.Polite
                        contentDescription = counter
                    },
            )

            state.error?.let { Text(it) }

            if (state.isSubmitting) {
                CircularProgressIndicator(Modifier.padding(8.dp))
            } else {
                Button(
                    onClick = onSubmit,
                    enabled = state.canSubmit,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                        .testTag(ReportTestTags.SUBMIT),
                ) { Text(stringResource(R.string.report_submit)) }
            }
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                    .testTag(ReportTestTags.CANCEL),
            ) { Text(stringResource(R.string.action_cancel)) }
        }
    }
}

@Composable
private fun ReasonRow(label: String, selected: Boolean) {
    androidx.compose.foundation.layout.Row(
        Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Text(text = label, modifier = Modifier.padding(start = 8.dp))
    }
}
