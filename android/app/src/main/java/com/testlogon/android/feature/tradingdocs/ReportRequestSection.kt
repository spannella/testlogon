@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tradingdocs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/** FE-171 stable testTags for the "Statements & reports" request section. */
object ReportRequestTestTags {
    const val SECTION = "report_request_section"
    const val TYPE_DROPDOWN = "report_request_type"
    const val YEAR_DROPDOWN = "report_request_year"
    const val START_DATE = "report_request_start"
    const val END_DATE = "report_request_end"
    const val GENERATE = "report_request_generate"
    const val MESSAGE = "report_request_message"
}

/** UI-side selection state for the report request form. Days are UTC-midnight millis (DatePicker native). */
private data class ReportRequestForm(
    val type: ReportType = REPORT_TYPES.first(),
    val startMillis: Long? = null,
    val endMillis: Long? = null,
    val taxYear: Int? = null,
)

/** Recent tax years offered for a 1099 (current year back 5), newest first. */
private fun recentTaxYears(): List<Int> {
    val now = Calendar.getInstance().get(Calendar.YEAR)
    return (0..5).map { now - it }
}

private fun fmtDay(millis: Long?): String =
    millis?.let {
        SimpleDateFormat("MMM d, yyyy", Locale.getDefault()).format(Date(it))
    } ?: "Select"

/** UTC-midnight day-millis -> epoch SECONDS (BE-170 period_* are epoch-seconds). */
private fun daySeconds(millis: Long): Long = millis / 1000L

/**
 * FE-171 — "Statements & reports" request section for the account/portfolio screen. Pick a report type,
 * the required params (a start/end date range, or a tax year for 1099), then Generate. On submit the
 * request is validated via [validateReportRequest] and sent through [onGenerate]; the outcome
 * ([submission]) is surfaced as an inline honest message with a link to the Trading Documents area.
 *
 * Reuses the FE-170 trading-documents request/download flow: a successful request points the user to
 * the rendered file in Trading Documents ([onViewDocuments]); degrade-on-404 shows "not available yet".
 */
@Composable
fun ReportRequestSection(
    submission: ReportSubmissionState,
    onGenerate: (type: String, periodStart: Long?, periodEnd: Long?, taxYear: Int?) -> Unit,
    onViewDocuments: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var form by remember { mutableStateOf(ReportRequestForm()) }
    var localErrors by remember { mutableStateOf<List<String>>(emptyList()) }

    Card(modifier = modifier.fillMaxWidth().testTag(ReportRequestTestTags.SECTION)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                "Statements & reports",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                "Request an account statement, P&L report, fills export, or 1099. It will appear in " +
                    "Trading Documents when ready.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            ReportTypeDropdown(
                selected = form.type,
                onSelected = { form = form.copy(type = it) },
            )

            if (form.type.needsPeriod) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    DateField(
                        label = "Start",
                        millis = form.startMillis,
                        onPicked = { form = form.copy(startMillis = it) },
                        testTag = ReportRequestTestTags.START_DATE,
                        modifier = Modifier.weight(1f),
                    )
                    DateField(
                        label = "End",
                        millis = form.endMillis,
                        onPicked = { form = form.copy(endMillis = it) },
                        testTag = ReportRequestTestTags.END_DATE,
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            if (form.type.needsTaxYear) {
                TaxYearDropdown(
                    selected = form.taxYear,
                    onSelected = { form = form.copy(taxYear = it) },
                )
            }

            val startSec = form.startMillis?.let(::daySeconds)
            val endSec = form.endMillis?.let(::daySeconds)

            Button(
                onClick = {
                    val errs = validateReportRequest(form.type.code, startSec, endSec, form.taxYear)
                    localErrors = errs
                    if (errs.isEmpty()) {
                        onGenerate(form.type.code, startSec, endSec, form.taxYear)
                    }
                },
                enabled = submission !is ReportSubmissionState.Submitting,
                modifier = Modifier.fillMaxWidth().testTag(ReportRequestTestTags.GENERATE),
            ) {
                Text(
                    if (submission is ReportSubmissionState.Submitting) "Generating…" else "Generate",
                )
            }

            localErrors.forEach { err ->
                Text(
                    err,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.testTag(ReportRequestTestTags.MESSAGE),
                )
            }

            when (submission) {
                ReportSubmissionState.Idle, ReportSubmissionState.Submitting -> Unit
                is ReportSubmissionState.Success -> {
                    Text(
                        "Generating your report — it will appear in Trading Documents when ready.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.testTag(ReportRequestTestTags.MESSAGE),
                    )
                    TextButton(onClick = onViewDocuments) { Text("View Trading Documents") }
                }
                is ReportSubmissionState.Unavailable -> {
                    Text(
                        "Reports aren’t available yet. Trading Documents will list them once the " +
                            "service is enabled.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag(ReportRequestTestTags.MESSAGE),
                    )
                    TextButton(onClick = onViewDocuments) { Text("Open Trading Documents") }
                }
            }
        }
    }
}

@Composable
private fun ReportTypeDropdown(
    selected: ReportType,
    onSelected: (ReportType) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
    ) {
        OutlinedTextField(
            value = selected.label,
            onValueChange = {},
            readOnly = true,
            label = { Text("Report type") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor()
                .testTag(ReportRequestTestTags.TYPE_DROPDOWN),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            REPORT_TYPES.forEach { rt ->
                DropdownMenuItem(
                    text = { Text(rt.label) },
                    onClick = {
                        onSelected(rt)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun TaxYearDropdown(
    selected: Int?,
    onSelected: (Int) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
    ) {
        OutlinedTextField(
            value = selected?.toString() ?: "Select a year",
            onValueChange = {},
            readOnly = true,
            label = { Text("Tax year") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor()
                .testTag(ReportRequestTestTags.YEAR_DROPDOWN),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            recentTaxYears().forEach { year ->
                DropdownMenuItem(
                    text = { Text(year.toString()) },
                    onClick = {
                        onSelected(year)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun DateField(
    label: String,
    millis: Long?,
    onPicked: (Long) -> Unit,
    testTag: String,
    modifier: Modifier = Modifier,
) {
    var show by remember { mutableStateOf(false) }
    Box(modifier) {
        OutlinedButton(
            onClick = { show = true },
            modifier = Modifier.fillMaxWidth().testTag(testTag),
        ) {
            Text("$label: ${fmtDay(millis)}")
        }
    }
    if (show) {
        val dateState = rememberDatePickerState(
            initialSelectedDateMillis = millis ?: System.currentTimeMillis(),
        )
        DatePickerDialog(
            onDismissRequest = { show = false },
            confirmButton = {
                TextButton(onClick = {
                    dateState.selectedDateMillis?.let(onPicked)
                    show = false
                }) { Text("OK") }
            },
            dismissButton = { TextButton(onClick = { show = false }) { Text("Cancel") } },
        ) {
            DatePicker(state = dateState)
        }
    }
}
