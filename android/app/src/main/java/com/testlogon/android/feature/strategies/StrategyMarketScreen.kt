@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.strategies

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Card
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.strategies.Strategy

/**
 * The USER-CREATED STRATEGY MARKETPLACE. Two tabs: the PUBLISHED marketplace (browse) and the caller's
 * AUTHORED strategies. A row taps through to detail; a FAB opens the builder. Every read degrades to an
 * honest empty state when the (not-yet-built) `me/strategies/(all)` backend 404s.
 */
@Composable
fun StrategyMarketRoute(
    onBack: () -> Unit,
    onOpenStrategy: (strategyId: String) -> Unit,
    onCreate: () -> Unit,
    viewModel: StrategyMarketViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Strategies") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onCreate,
                icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                text = { Text("Create") },
                modifier = Modifier.testTag("strategies_create_fab"),
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            TabRow(selectedTabIndex = if (state.tab == StrategyListTab.MARKET) 0 else 1) {
                Tab(
                    selected = state.tab == StrategyListTab.MARKET,
                    onClick = { viewModel.selectTab(StrategyListTab.MARKET) },
                    text = { Text("Marketplace (${state.market.size})") },
                    modifier = Modifier.testTag("strategies_tab_market"),
                )
                Tab(
                    selected = state.tab == StrategyListTab.MINE,
                    onClick = { viewModel.selectTab(StrategyListTab.MINE) },
                    text = { Text("Mine (${state.mine.size})") },
                    modifier = Modifier.testTag("strategies_tab_mine"),
                )
            }
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    StrategyMarketUiState.Phase.Loading -> LoadingState(message = "Loading strategies")
                    StrategyMarketUiState.Phase.Error -> ErrorState(
                        message = state.errorMessage ?: "Something went wrong.",
                        onRetry = viewModel::onRetry,
                    )
                    StrategyMarketUiState.Phase.Content ->
                        if (state.rows.isEmpty()) {
                            EmptyState(
                                title = if (state.tab == StrategyListTab.MARKET) "No published strategies" else "No strategies yet",
                                body = if (state.tab == StrategyListTab.MARKET) {
                                    "No investable strategies are published yet. Check back once creators publish their baskets."
                                } else {
                                    "You haven't created a strategy yet. Tap Create to define a basket, backtest it, then publish."
                                },
                            )
                        } else {
                            StrategyList(rows = state.rows, isMarket = state.tab == StrategyListTab.MARKET, onOpen = onOpenStrategy)
                        }
                }
            }
        }
    }
}

@Composable
private fun StrategyList(rows: List<Strategy>, isMarket: Boolean, onOpen: (String) -> Unit) {
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier.fillMaxSize(),
    ) {
        items(rows, key = { it.strategyId }) { s ->
            StrategyRow(s = s, isMarket = isMarket, onOpen = onOpen)
        }
    }
}

@Composable
private fun StrategyRow(s: Strategy, isMarket: Boolean, onOpen: (String) -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onOpen(s.strategyId) }
            .testTag("strategy_row_${s.strategyId}"),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    s.name.ifBlank { "(unnamed)" },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f),
                )
                StrategyStatusPill(s.status.label())
            }
            if (s.description.isNotBlank()) {
                Spacer(Modifier.height(4.dp))
                Text(
                    s.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Stat("NAV", s.navPerUnit?.let { StrategyMath.formatNav(it) } ?: "—")
                Stat("AUM", s.aumCents?.let { StrategyMath.formatCents(it) } ?: "—")
                Stat(
                    "Return",
                    s.inceptionReturnBps?.let { StrategyMath.formatBps(it) } ?: "—",
                )
            }
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Stat("Mgmt fee", StrategyMath.formatBps(s.mgmtFeeBps))
                Stat("Perf fee", StrategyMath.formatBps(s.perfFeeBps))
                Stat(
                    "Capacity left",
                    s.capacityRemainingCents?.let { StrategyMath.formatCents(it) } ?: "Uncapped",
                )
            }
        }
    }
}

@Composable
private fun Stat(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium)
    }
}
