@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.licenses.revenue

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Paid
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.licenses.FullRevenuePage
import com.testlogon.android.data.licenses.FullRevenueTransaction
import com.testlogon.android.data.licenses.RevenueSplitPreview
import com.testlogon.android.feature.earnings.formatEarningsMoney

object LicenseRevenueTestTags {
    const val SCREEN = "license_revenue_screen"
    const val TABS = "license_revenue_tabs"
    const val LIST = "license_revenue_list"
    const val LOADING = "license_revenue_loading"
    const val EMPTY = "license_revenue_empty"
    const val ERROR = "license_revenue_error"
    const val SUMMARY = "license_revenue_summary"
    const val CALC = "license_revenue_calc"
    const val CALC_RESULT = "license_revenue_calc_result"
    const val TAB_PREFIX = "license_revenue_tab_"
    const val SOURCE_PREFIX = "license_revenue_source_"
    const val ROW_PREFIX = "license_revenue_row_"
}

@Composable
fun LicenseRevenueRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: LicenseRevenueViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LicenseRevenueScreen(
        state = state,
        onBack = onBack,
        onSelectTab = viewModel::selectTab,
        onSelectSource = viewModel::selectSource,
        onRefresh = viewModel::refresh,
        onSetAmount = viewModel::setCalcAmount,
        onSetRevenue = viewModel::setCalcRevenue,
        onSetProfit = viewModel::setCalcProfit,
        onCalculate = viewModel::calculate,
        modifier = modifier,
    )
}

@Composable
fun LicenseRevenueScreen(
    state: LicenseRevenueUiState,
    onBack: () -> Unit,
    onSelectTab: (RevenueTab) -> Unit,
    onSelectSource: (String) -> Unit,
    onRefresh: () -> Unit,
    onSetAmount: (Long) -> Unit,
    onSetRevenue: (Int) -> Unit,
    onSetProfit: (Int) -> Unit,
    onCalculate: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(LicenseRevenueTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("License Revenue") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("license_revenue_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            TabsRow(state.tab, onSelectTab)
            if (state.tab != RevenueTab.CALCULATOR) {
                SourceFilterRow(state.sourceFilter, onSelectSource)
            }
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.tab) {
                    RevenueTab.EARNED -> RevenueListPane(
                        page = state.earned,
                        phase = state.earnedPhase,
                        error = state.earnedError,
                        isRefreshing = state.isRefreshing,
                        isEarned = true,
                        onRefresh = onRefresh,
                    )
                    RevenueTab.PAID -> RevenueListPane(
                        page = state.paid,
                        phase = state.paidPhase,
                        error = state.paidError,
                        isRefreshing = state.isRefreshing,
                        isEarned = false,
                        onRefresh = onRefresh,
                    )
                    RevenueTab.CALCULATOR -> CalculatorPane(
                        state = state,
                        onSetAmount = onSetAmount,
                        onSetRevenue = onSetRevenue,
                        onSetProfit = onSetProfit,
                        onCalculate = onCalculate,
                    )
                }
            }
        }
    }
}

@Composable
private fun TabsRow(selected: RevenueTab, onSelect: (RevenueTab) -> Unit) {
    val tabs = RevenueTab.entries
    SingleChoiceSegmentedButtonRow(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(LicenseRevenueTestTags.TABS),
    ) {
        tabs.forEachIndexed { index, tab ->
            SegmentedButton(
                selected = tab == selected,
                onClick = { onSelect(tab) },
                shape = SegmentedButtonDefaults.itemShape(index = index, count = tabs.size),
                modifier = Modifier.testTag(LicenseRevenueTestTags.TAB_PREFIX + tab.name.lowercase()),
            ) {
                Text(
                    when (tab) {
                        RevenueTab.EARNED -> "Earned"
                        RevenueTab.PAID -> "Paid"
                        RevenueTab.CALCULATOR -> "Calculator"
                    },
                )
            }
        }
    }
}

@Composable
private fun SourceFilterRow(selected: String, onSelect: (String) -> Unit) {
    LazyRow(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(horizontal = 8.dp),
    ) {
        items(REVENUE_SOURCE_OPTIONS, key = { it }) { opt ->
            val isSel = opt == selected
            AssistChip(
                onClick = { onSelect(opt) },
                label = { Text(if (opt == "all") "All" else opt.replaceFirstChar { it.uppercase() }) },
                modifier = Modifier.testTag(LicenseRevenueTestTags.SOURCE_PREFIX + opt),
                colors = if (isSel) {
                    AssistChipDefaults.assistChipColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
                } else {
                    AssistChipDefaults.assistChipColors()
                },
            )
        }
    }
}

@Composable
private fun RevenueListPane(
    page: FullRevenuePage?,
    phase: LicenseRevenueUiState.Phase,
    error: String?,
    isRefreshing: Boolean,
    isEarned: Boolean,
    onRefresh: () -> Unit,
) {
    when (phase) {
        LicenseRevenueUiState.Phase.Loading ->
            LoadingState(modifier = Modifier.testTag(LicenseRevenueTestTags.LOADING))

        LicenseRevenueUiState.Phase.Error ->
            ErrorState(
                message = error ?: "Could not load revenue.",
                onRetry = onRefresh,
                modifier = Modifier.testTag(LicenseRevenueTestTags.ERROR),
            )

        LicenseRevenueUiState.Phase.Empty ->
            PullToRefreshBox(isRefreshing = isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                    page?.let { SummaryRow(it, isEarned) }
                    EmptyState(
                        title = if (isEarned) "No revenue earned" else "No revenue paid",
                        body = "Transactions will appear here.",
                        imageVector = Icons.Outlined.Paid,
                        modifier = Modifier.fillMaxWidth().padding(top = 48.dp).testTag(LicenseRevenueTestTags.EMPTY),
                    )
                }
            }

        LicenseRevenueUiState.Phase.Content ->
            PullToRefreshBox(isRefreshing = isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(LicenseRevenueTestTags.LIST),
                    contentPadding = PaddingValues(bottom = 16.dp),
                ) {
                    page?.let { item { SummaryRow(it, isEarned) } }
                    items(page?.transactions.orEmpty(), key = { it.id }) { txn ->
                        TransactionRow(txn)
                        HorizontalDivider()
                    }
                }
            }
    }
}

@Composable
private fun SummaryRow(page: FullRevenuePage, isEarned: Boolean) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
            .testTag(LicenseRevenueTestTags.SUMMARY),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            SummaryStat(if (isEarned) "Total Earned" else "Total Paid",
                formatEarningsMoney(page.summary.totalCents, page.summary.currency))
            SummaryStat("Transactions", page.summary.totalTransactions.toString())
            SummaryStat("Last", page.summary.formattedLastTransaction().ifBlank { "-" })
        }
    }
}

@Composable
private fun SummaryStat(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun TransactionRow(txn: FullRevenueTransaction) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(LicenseRevenueTestTags.ROW_PREFIX + txn.id)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            val title = listOf(txn.sourceLabel().ifBlank { "Revenue" }, txn.splitTypeLabel())
                .filter { it.isNotBlank() }.joinToString(" - ")
            Text(title, style = MaterialTheme.typography.bodyLarge)
            val meta = listOf(txn.contentId, txn.counterpartyId, txn.formattedCreated())
                .filter { it.isNotBlank() }.joinToString("  -  ")
            if (meta.isNotBlank()) {
                Text(meta, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Text(
            formatEarningsMoney(txn.splitAmountCents, txn.currency),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
private fun CalculatorPane(
    state: LicenseRevenueUiState,
    onSetAmount: (Long) -> Unit,
    onSetRevenue: (Int) -> Unit,
    onSetProfit: (Int) -> Unit,
    onCalculate: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(LicenseRevenueTestTags.CALC),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Split Calculator", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = state.calcAmountCents.toString(),
            onValueChange = { onSetAmount(it.filter { c -> c.isDigit() }.toLongOrNull() ?: 0L) },
            label = { Text("Source Amount (cents)") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth().testTag("license_revenue_calc_amount"),
        )
        OutlinedTextField(
            value = state.calcRevenuePct.toString(),
            onValueChange = { onSetRevenue(it.filter { c -> c.isDigit() }.toIntOrNull() ?: 0) },
            label = { Text("Revenue Share %") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth().testTag("license_revenue_calc_revenue"),
        )
        OutlinedTextField(
            value = state.calcProfitPct.toString(),
            onValueChange = { onSetProfit(it.filter { c -> c.isDigit() }.toIntOrNull() ?: 0) },
            label = { Text("Profit Share %") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth().testTag("license_revenue_calc_profit"),
        )
        Button(
            onClick = onCalculate,
            enabled = !state.calcLoading,
            modifier = Modifier.testTag("license_revenue_calc_button"),
        ) { Text(if (state.calcLoading) "Calculating..." else "Calculate") }

        state.calcError?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        state.calcResult?.let { CalcResult(it) }
    }
}

@Composable
private fun CalcResult(r: RevenueSplitPreview) {
    Card(modifier = Modifier.fillMaxWidth().testTag(LicenseRevenueTestTags.CALC_RESULT)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Calculation Result", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            CalcRow("Source Amount", r.sourceAmountCents)
            CalcRow("Platform Fee", r.platformFeeCents)
            CalcRow("Revenue Share", r.revenueShareCents)
            CalcRow("Profit Share", r.profitShareCents)
            CalcRow("Licensor Total", r.totalLicensorShareCents, emphasize = true)
            CalcRow("Licensee Net", r.licenseeNetCents, emphasize = true)
        }
    }
}

@Composable
private fun CalcRow(label: String, cents: Long, emphasize: Boolean = false) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = if (emphasize) FontWeight.SemiBold else FontWeight.Normal,
            color = if (emphasize) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            formatEarningsMoney(cents, "USD"),
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = if (emphasize) FontWeight.SemiBold else FontWeight.Normal,
        )
    }
}
