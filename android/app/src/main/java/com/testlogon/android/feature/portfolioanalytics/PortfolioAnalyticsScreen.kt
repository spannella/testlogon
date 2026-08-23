@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.portfolioanalytics

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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.testlogon.android.feature.onboarding.SurfaceIntro
import com.testlogon.android.feature.onboarding.OnboardingModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.util.Locale

private val Warn = Color(0xFFDC2626)
private val Ok = Color(0xFF16A34A)

@Composable
fun PortfolioAnalyticsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PortfolioAnalyticsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PortfolioAnalyticsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onSelectAllocationBy = viewModel::onSelectAllocationBy,
        modifier = modifier,
    )
}

@Composable
fun PortfolioAnalyticsScreen(
    state: PortfolioAnalyticsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onSelectAllocationBy: (AllocationBy) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text("Allocation & Risk") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onRefresh) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Refresh")
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { SurfaceIntro(OnboardingModel.INTRO_PORTFOLIO_ANALYTICS) }
            item { HeaderCard(state) }

            when {
                state.loading -> item { LoadingBlock() }
                state.allEmpty -> item { EmptyBlock(state) }
                else -> {
                    if (state.sourceIssues.isNotEmpty()) item { SourceIssuesCard(state.sourceIssues) }
                    item { AllocationCard(state, onSelectAllocationBy) }
                    item { ConcentrationCard(state) }
                    item { ExposureCard(state) }
                    item { RiskCard(state) }
                }
            }
        }
    }
}

@Composable
private fun HeaderCard(state: PortfolioAnalyticsUiState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(
                "Indicative portfolio value (USD)",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                usd(state.totalValueCents),
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                if (state.pricesStub) {
                    "Cross-venue gross value — indicative (stub prices)."
                } else {
                    "Cross-venue gross value across custody / spot / margin / tokens / funds / staking."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
        }
    }
}

@Composable
private fun SourceIssuesCard(issues: List<String>) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Some sources unavailable", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(6.dp))
            issues.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            Spacer(Modifier.height(4.dp))
            Text(
                "These sources contribute nothing to the numbers below.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun AllocationCard(state: PortfolioAnalyticsUiState, onSelect: (AllocationBy) -> Unit) {
    SectionCard("Allocation") {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AllocationBy.entries.forEach { by ->
                FilterChip(
                    selected = state.allocationBy == by,
                    onClick = { onSelect(by) },
                    label = { Text(by.name.lowercase().replaceFirstChar { it.uppercase() }) },
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        if (state.allocation.isEmpty()) {
            EmptyLine("No priced holdings to break down.")
        } else {
            state.allocation.forEach { slice -> WeightBar(slice.key, slice.weightBps, slice.valueCents) }
        }
    }
}

@Composable
private fun WeightBar(label: String, weightBps: Int, valueCents: Long) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Text(
                pct(weightBps) + "  " + usd(valueCents),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(2.dp))
        LinearProgressIndicator(
            progress = { (weightBps / 10_000f).coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth().height(6.dp),
        )
    }
}

@Composable
private fun ConcentrationCard(state: PortfolioAnalyticsUiState) {
    val c = state.concentration
    SectionCard("Concentration") {
        if (c == null || c.n == 0) {
            EmptyLine("Nothing to measure yet.")
            return@SectionCard
        }
        StatRow("Largest position", (c.topKey ?: "—") + "  " + pct(c.topWeightBps))
        StatRow("Top-3 combined", pct(c.topNCumulativeBps))
        StatRow("Effective bets", String.format(Locale.US, "%.1f", c.effectiveBets))
        Spacer(Modifier.height(8.dp))
        Text("HHI concentration", style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(2.dp))
        LinearProgressIndicator(
            progress = { (c.hhi / 10_000f).coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth().height(8.dp),
            color = if (c.hhi >= 4_000) Warn else MaterialTheme.colorScheme.primary,
        )
        Spacer(Modifier.height(2.dp))
        Text(
            hhiLabel(c.hhi) + " (" + c.hhi + " / 10000)",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ExposureCard(state: PortfolioAnalyticsUiState) {
    val e = state.exposure
    SectionCard("Exposure") {
        if (e == null) {
            EmptyLine("Nothing to measure yet.")
            return@SectionCard
        }
        StatRow("Gross", usd(e.grossCents))
        StatRow("Net", usd(e.netCents))
        StatRow("Long", usd(e.longCents))
        StatRow("Short", usd(e.shortCents))
        StatRow("Leverage", leverage(e.leverageBps))
    }
}

@Composable
private fun RiskCard(state: PortfolioAnalyticsUiState) {
    SectionCard("Risk") {
        if (state.riskUnavailable) {
            EmptyLine("Risk needs per-asset price history for your priced holdings — none available yet.")
            return@SectionCard
        }
        if (state.limitedHistory) {
            Surface(
                color = MaterialTheme.colorScheme.tertiaryContainer,
                contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                shape = RoundedCornerShape(6.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    "Limited history: some series use the recent window only — figures are approximate.",
                    modifier = Modifier.padding(8.dp),
                    style = MaterialTheme.typography.labelSmall,
                )
            }
            Spacer(Modifier.height(8.dp))
        }
        StatRow("Portfolio volatility (annualized)", state.portfolioVolBps?.let { pct(it) } ?: "—")
        StatRow("Parametric VaR (95%, 1d)", usd(state.parametricVar95Cents))
        StatRow("Parametric VaR (99%, 1d)", usd(state.parametricVar99Cents))
        StatRow("Historical VaR (95%, 1d)", usd(state.historicalVar95Cents))
        Spacer(Modifier.height(8.dp))
        Text("Diversification score", style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(2.dp))
        LinearProgressIndicator(
            progress = { (state.diversificationScore / 100f).coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth().height(8.dp),
            color = if (state.diversificationScore >= 60) Ok else Warn,
        )
        Spacer(Modifier.height(2.dp))
        Text(
            state.diversificationScore.toString() + " / 100 · based on " + state.riskAssetsCovered + " priced asset(s)",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// ---------------- shared bits ----------------

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            HorizontalDivider()
            Spacer(Modifier.height(8.dp))
            content()
        }
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun EmptyLine(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun LoadingBlock() {
    Column(
        modifier = Modifier.fillMaxWidth().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator()
        Spacer(Modifier.height(12.dp))
        Text("Analyzing your positions…", style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun EmptyBlock(state: PortfolioAnalyticsUiState) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("No priced holdings yet", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(4.dp))
        Text(
            "Fund custody, spot, or margin (with indicative prices available) to see allocation & risk.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (state.sourceIssues.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            state.sourceIssues.forEach { Text("• $it", style = MaterialTheme.typography.labelSmall) }
        }
    }
}

// ---------------- formatting ----------------

private fun usd(cents: Long): String {
    val v = cents / 100.0
    return "$" + String.format(Locale.US, "%,.2f", v)
}

private fun pct(bps: Int): String = String.format(Locale.US, "%.1f%%", bps / 100.0)

private fun leverage(bps: Int): String =
    if (bps <= 0) "—" else String.format(Locale.US, "%.2fx", bps / 10_000.0)

private fun hhiLabel(hhi: Int): String = when {
    hhi >= 5_000 -> "Highly concentrated"
    hhi >= 2_500 -> "Moderately concentrated"
    hhi >= 1_500 -> "Somewhat diversified"
    else -> "Diversified"
}
