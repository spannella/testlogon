@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.hr

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.hr.HrMath
import com.testlogon.android.core.model.hr.PayrollLine
import com.testlogon.android.core.model.hr.PayrollRun
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** HRM-009 — payroll-run detail route. Arg is the STRING payroll_run_id. */
@Composable
fun HrPayrollDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: HrPayrollDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    Scaffold(
        modifier = modifier.testTag("hr_payroll_detail_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.hr_payroll_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        when (val s = state) {
            is HrPayrollDetailUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is HrPayrollDetailUiState.Unavailable -> EmptyState(
                title = stringResource(R.string.hr_unavailable_title),
                body = stringResource(R.string.hr_unavailable_body),
                modifier = Modifier.padding(padding),
            )
            is HrPayrollDetailUiState.Error -> ErrorState(
                message = s.message,
                onRetry = viewModel::retry,
                modifier = Modifier.padding(padding),
            )
            is HrPayrollDetailUiState.Content -> PayrollDetailBody(
                run = s.run,
                lines = s.lines,
                modifier = Modifier.padding(padding),
            )
        }
    }
}

@Composable
private fun PayrollDetailBody(run: PayrollRun, lines: List<PayrollLine>, modifier: Modifier = Modifier) {
    val total = HrMath.formatMoney(HrMath.runGrossTotal(run))
    val period = listOfNotNull(formatHrDate(run.periodStartEpochSeconds), formatHrDate(run.periodEndEpochSeconds))
        .joinToString(" – ")
    LazyColumn(modifier = modifier.fillMaxSize()) {
        item {
            Field(stringResource(R.string.hr_field_status), payrollStatusLabel(run.status))
            if (period.isNotBlank()) Field(stringResource(R.string.hr_field_period), period)
            Field(stringResource(R.string.hr_field_gross_total), total)
            run.approvedBy?.let { Field(stringResource(R.string.hr_field_approved_by), it) }
            formatHrDate(run.postedAtEpochSeconds)?.let { Field(stringResource(R.string.hr_field_posted_at), it) }
            Text(
                stringResource(R.string.hr_payroll_lines_header),
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
        }
        if (lines.isEmpty()) {
            item { EmptyState(title = stringResource(R.string.hr_payroll_lines_empty)) }
        } else {
            items(lines, key = { it.employmentId }) { line ->
                ListItem(
                    headlineContent = { Text(line.partyId.ifBlank { line.employmentId }) },
                    trailingContent = { Text(HrMath.formatMoney(line.gross)) },
                )
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun Field(label: String, value: String) {
    ListItem(headlineContent = { Text(value) }, overlineContent = { Text(label) })
    HorizontalDivider()
}
