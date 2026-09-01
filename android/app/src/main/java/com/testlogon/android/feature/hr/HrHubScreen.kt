@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.hr

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.hr.Employment
import com.testlogon.android.core.model.hr.HrMath
import com.testlogon.android.core.model.hr.PayrollRun
import com.testlogon.android.core.model.hr.Position
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** HRM-009 — stable testTags for the HR hub. */
object HrTestTags {
    const val SCREEN = "hr_screen"
    const val TABS = "hr_tabs"
    const val LIST = "hr_list"
    const val ROW = "hr_row"
    const val EMPTY = "hr_empty"
    const val ERROR = "hr_error"
}

/** HRM-009 — route-level HR hub, reachable from the More hub (operator-only). */
@Composable
fun HrHubRoute(
    onEmploymentClick: (String) -> Unit,
    onPayrollClick: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: HrHubViewModel = hiltViewModel(),
) {
    val positions by viewModel.positions.collectAsStateWithLifecycle()
    val employments by viewModel.employments.collectAsStateWithLifecycle()
    val payroll by viewModel.payroll.collectAsStateWithLifecycle()

    var selected by rememberSaveable { mutableStateOf(HrTab.POSITIONS) }

    Scaffold(
        modifier = modifier.testTag(HrTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.hr_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            TabRow(selectedTabIndex = selected.ordinal, modifier = Modifier.testTag(HrTestTags.TABS)) {
                HrTab.entries.forEach { tab ->
                    Tab(
                        selected = selected == tab,
                        onClick = { selected = tab },
                        text = { Text(stringResource(hrTabLabel(tab))) },
                    )
                }
            }
            when (selected) {
                HrTab.POSITIONS -> ListPane(
                    state = positions,
                    onRetry = { viewModel.retry(HrTab.POSITIONS) },
                    emptyTitle = stringResource(R.string.hr_positions_empty),
                ) { list -> items(list, key = { it.positionId }) { PositionRow(it) } }

                HrTab.EMPLOYMENTS -> ListPane(
                    state = employments,
                    onRetry = { viewModel.retry(HrTab.EMPLOYMENTS) },
                    emptyTitle = stringResource(R.string.hr_employments_empty),
                ) { list ->
                    items(list, key = { it.employmentId }) { emp ->
                        EmploymentRow(emp, onClick = { onEmploymentClick(emp.employmentId) })
                    }
                }

                HrTab.PAYROLL -> ListPane(
                    state = payroll,
                    onRetry = { viewModel.retry(HrTab.PAYROLL) },
                    emptyTitle = stringResource(R.string.hr_payroll_empty),
                ) { list ->
                    items(list, key = { it.payrollRunId }) { run ->
                        PayrollRow(run, onClick = { onPayrollClick(run.payrollRunId) })
                    }
                }
            }
        }
    }
}

@Composable
private fun <T> ListPane(
    state: HrListUiState<T>,
    onRetry: () -> Unit,
    emptyTitle: String,
    itemsBlock: androidx.compose.foundation.lazy.LazyListScope.(List<T>) -> Unit,
) {
    when (state) {
        is HrListUiState.Loading -> LoadingState()
        is HrListUiState.Unavailable -> EmptyState(
            title = stringResource(R.string.hr_unavailable_title),
            body = stringResource(R.string.hr_unavailable_body),
            modifier = Modifier.testTag(HrTestTags.EMPTY),
        )
        is HrListUiState.Error -> ErrorState(
            message = state.message,
            onRetry = onRetry,
            modifier = Modifier.testTag(HrTestTags.ERROR),
        )
        is HrListUiState.Content -> if (state.items.isEmpty()) {
            EmptyState(title = emptyTitle, modifier = Modifier.testTag(HrTestTags.EMPTY))
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize().testTag(HrTestTags.LIST)) {
                itemsBlock(state.items)
            }
        }
    }
}

@Composable
private fun PositionRow(position: Position) {
    ListItem(
        modifier = Modifier.testTag(HrTestTags.ROW),
        headlineContent = { Text(position.title.ifBlank { position.positionId }) },
        supportingContent = {
            val dept = position.department
            Text(if (dept.isNullOrBlank()) positionStatusLabel(position.status) else "$dept · ${positionStatusLabel(position.status)}")
        },
    )
    HorizontalDivider()
}

@Composable
private fun EmploymentRow(employment: Employment, onClick: () -> Unit) {
    ListItem(
        modifier = Modifier.clickable(onClick = onClick).testTag(HrTestTags.ROW),
        headlineContent = { Text(employment.partyId.ifBlank { employment.employmentId }) },
        supportingContent = {
            Text("${employmentStatusLabel(employment.status)} · ${HrMath.payRateLabel(employment)}")
        },
    )
    HorizontalDivider()
}

@Composable
private fun PayrollRow(run: PayrollRun, onClick: () -> Unit) {
    val total = HrMath.formatMoney(HrMath.runGrossTotal(run))
    val period = listOfNotNull(formatHrDate(run.periodStartEpochSeconds), formatHrDate(run.periodEndEpochSeconds))
        .joinToString(" – ")
    ListItem(
        modifier = Modifier.clickable(onClick = onClick).testTag(HrTestTags.ROW),
        headlineContent = { Text(period.ifBlank { run.payrollRunId }) },
        supportingContent = { Text("${payrollStatusLabel(run.status)} · $total") },
    )
    HorizontalDivider()
}

private fun hrTabLabel(tab: HrTab): Int = when (tab) {
    HrTab.POSITIONS -> R.string.hr_tab_positions
    HrTab.EMPLOYMENTS -> R.string.hr_tab_employments
    HrTab.PAYROLL -> R.string.hr_tab_payroll
}
