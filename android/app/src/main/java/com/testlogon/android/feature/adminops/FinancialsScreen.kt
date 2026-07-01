@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminops

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

object FinancialsTestTags {
    const val SCREEN = "adminops_financials_screen"
    const val CONTENT = "adminops_financials_content"
    const val FORBIDDEN = "adminops_financials_forbidden"
    const val RETRY = "adminops_financials_retry"
    fun range(r: FinancialsRange) = "adminops_financials_range_${r.name}"
}

@Composable
fun FinancialsRoute(
    onBack: () -> Unit,
    viewModel: FinancialsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    FinancialsScreen(
        state = state,
        onBack = onBack,
        onSetRange = viewModel::setRange,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
    )
}

@Composable
fun FinancialsScreen(
    state: FinancialsUiState,
    onBack: () -> Unit,
    onSetRange: (FinancialsRange) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(FinancialsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Platform financials") },
                navigationIcon = { AdminOpsBackIcon(onBack) },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            val activeRange = (state as? FinancialsUiState.Content)?.range ?: FinancialsRange.D30
            RangeRow(active = activeRange, onSetRange = onSetRange)
            val isRefreshing = (state as? FinancialsUiState.Content)?.isRefreshing == true
            PullToRefreshBox(
                isRefreshing = isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (state) {
                    is FinancialsUiState.Loading -> LoadingState()
                    is FinancialsUiState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(FinancialsTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You need platform-admin access to view financials.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is FinancialsUiState.Error -> ErrorState(
                        modifier = Modifier.testTag(FinancialsTestTags.RETRY),
                        message = adminOpsErrorMessage(state.type),
                        onRetry = onRetry,
                    )
                    is FinancialsUiState.Content -> FinancialsContent(state)
                }
            }
        }
    }
}

@Composable
private fun RangeRow(active: FinancialsRange, onSetRange: (FinancialsRange) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FinancialsRange.entries.forEach { r ->
            FilterChip(
                selected = active == r,
                onClick = { onSetRange(r) },
                label = { Text(r.label) },
                modifier = Modifier.testTag(FinancialsTestTags.range(r)),
            )
        }
    }
}

@Composable
private fun FinancialsContent(state: FinancialsUiState.Content) {
    val d = state.data
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(FinancialsTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "${state.startDate} → ${state.endDate}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        KpiGrid(
            tiles = listOf(
                "GMV" to cents(d.kpis.gmvCents),
                "Net revenue" to cents(d.kpis.netRevenueCents),
                "Refunds" to cents(d.kpis.refundsCents),
                "Take rate" to bpsPct(d.kpis.takeRateBps),
                "Transactions" to d.kpis.txCount.toString(),
                "Unique payers" to d.kpis.uniquePayers.toString(),
                "Avg txn" to cents(d.kpis.avgTxCents),
            ),
        )

        if (d.providers.isNotEmpty()) {
            CardSection("By provider") {
                d.providers.forEach { p ->
                    StatRow(
                        label = "${p.provider.ifBlank { "unknown" }} · ${p.txCount} txn",
                        value = "${cents(p.totalCents)}  (${pct(p.pct)})",
                    )
                }
            }
        }

        if (d.types.isNotEmpty()) {
            CardSection("By type") {
                d.types.forEach { t ->
                    StatRow(
                        label = "${t.entryType.replace('_', ' ').ifBlank { "unknown" }} · ${t.txCount} txn",
                        value = cents(t.totalCents),
                    )
                }
            }
        }

        if (d.trends.isNotEmpty()) {
            CardSection("Daily trend (GMV)") {
                d.trends.takeLast(14).forEach { pt ->
                    StatRow(label = pt.date, value = "${cents(pt.gmvCents)} · ${pt.txCount} txn")
                }
            }
        }

        if (d.topCreators.isNotEmpty()) {
            CardSection("Top creators") {
                d.topCreators.forEachIndexed { i, c ->
                    StatRow(
                        label = "${i + 1}. ${c.userId} · ${c.txCount} txn",
                        value = cents(c.revenueCents),
                    )
                }
            }
        }
    }
}
