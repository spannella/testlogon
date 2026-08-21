@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.strategies

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/**
 * The PAPER-RUN + BACKTEST screen. Shows a client-side weighted-basket equity curve (built from the
 * strategy's legs' historical closes) plus summary stats (return / annualized vol / max drawdown) and
 * a $10,000 paper account marked along the same curve. When any leg's history was degraded from the
 * recent-window candles read (md/history 404), a banner makes that honest.
 */
@Composable
fun StrategyPaperRoute(
    onBack: () -> Unit,
    viewModel: StrategyPaperViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Paper-run & backtest") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                StrategyPaperUiState.Phase.Loading -> LoadingState(message = "Running backtest")
                StrategyPaperUiState.Phase.Error -> ErrorState(
                    message = state.errorMessage ?: "Something went wrong.",
                    onRetry = viewModel::onRetry,
                )
                StrategyPaperUiState.Phase.Empty -> EmptyState(
                    title = "Nothing to backtest",
                    body = "This strategy has no basket legs yet. Add legs in the builder to paper-trade and backtest it.",
                )
                StrategyPaperUiState.Phase.Content -> PaperContent(state)
            }
        }
    }
}

@Composable
private fun PaperContent(state: StrategyPaperUiState) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text(
            state.strategy?.name.orEmpty(),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            "Weighted-basket backtest over historical closes. The paper account follows the target weights.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (state.degraded) {
            Spacer(Modifier.height(8.dp))
            Surface(
                color = MaterialTheme.colorScheme.tertiaryContainer,
                contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    "Recent window only — long-range history is unavailable, so this backtest uses the recent candle window.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(10.dp),
                )
            }
        }

        Spacer(Modifier.height(16.dp))
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text("Equity curve (base 1.0)", style = MaterialTheme.typography.labelLarge)
                EquitySparkline(curve = state.equityCurve)
            }
        }

        Spacer(Modifier.height(16.dp))
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text("Backtest stats", style = MaterialTheme.typography.labelLarge)
                Spacer(Modifier.height(6.dp))
                StrategyKeyValueRow("Total return", pct(state.totalReturnPct), emphasize = true)
                StrategyKeyValueRow("Annualized volatility", pct(state.annualizedVolPct))
                StrategyKeyValueRow("Max drawdown", state.maxDrawdownPct?.let { "-" + pct(it) } ?: "—")
            }
        }

        Spacer(Modifier.height(16.dp))
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text("Paper account (following weights)", style = MaterialTheme.typography.labelLarge)
                Spacer(Modifier.height(6.dp))
                StrategyKeyValueRow("Starting notional", StrategyMath.formatCents(state.paperStartCents))
                StrategyKeyValueRow(
                    "Ending value",
                    state.paperEndCents?.let { StrategyMath.formatCents(it) } ?: "—",
                    emphasize = true,
                )
                val pnl = state.paperEndCents?.let { it - state.paperStartCents }
                StrategyKeyValueRow("Paper P&L", pnl?.let { StrategyMath.formatCents(it) } ?: "—")
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}

private fun pct(v: Double?): String = v?.let { String.format("%.2f%%", it) } ?: "—"
