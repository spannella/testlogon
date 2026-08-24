@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.feetiers

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.util.Locale

/**
 * The maker/taker FEE TIER (VIP schedule) surface, reached from the More -> Wallet hub (near Tax).
 * Shows the caller's current tier + rates, their trailing 30-day trading volume, progress to the next
 * tier, and the full canonical schedule with the caller's row highlighted. Volume is computed
 * client-side from the live fills feed (same source as the Tax report); an authoritative backend read
 * overrides when deployed. No money movement.
 */
@Composable
fun FeeTiersRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: FeeTiersViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    FeeTiersScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        modifier = modifier,
    )
}

@Composable
fun FeeTiersScreen(
    state: FeeTiersUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text("Fee tiers") },
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
        when {
            state.loading -> Box(Modifier.fillMaxSize().padding(padding), Alignment.Center) {
                CircularProgressIndicator()
            }
            state.error != null -> Box(Modifier.fillMaxSize().padding(padding), Alignment.Center) {
                Text(state.error, color = MaterialTheme.colorScheme.error)
            }
            else -> Content(state, padding)
        }
    }
}

@Composable
private fun Content(state: FeeTiersUiState, padding: PaddingValues) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(
            start = 16.dp,
            end = 16.dp,
            top = padding.calculateTopPadding() + 12.dp,
            bottom = padding.calculateBottomPadding() + 24.dp,
        ),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { CurrentTierCard(state) }
        if (!state.isTopTier) item { ProgressCard(state) }
        item {
            Text(
                "Maker/taker rates are set by your trailing 30-day trading volume. All tiers:",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        item { TableHeader() }
        items(state.tiers, key = { it.id }) { row -> TierRow(row) }
        item {
            val note = if (state.estimated) {
                if (state.empty) {
                    "No trades yet, so you are on the Standard tier. Rates shown are estimated from your trade history."
                } else {
                    "Estimated from your trade history (30-day fills). The exchange rate applies at match time."
                }
            } else {
                "Confirmed by the exchange."
            }
            Text(
                note,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}

@Composable
private fun CurrentTierCard(state: FeeTiersUiState) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(
                "Your tier",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Text(
                state.currentTierName,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), Arrangement.SpaceBetween) {
                Stat("Maker", bpsPct(state.makerBps))
                Stat("Taker", bpsPct(state.takerBps))
                Stat("30-day volume", usd(state.volume30dCents))
            }
        }
    }
}

@Composable
private fun Stat(label: String, value: String) {
    Column {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
        )
        Text(
            value,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
        )
    }
}

@Composable
private fun ProgressCard(state: FeeTiersUiState) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(
                "Progress to " + (state.nextTierName ?: ""),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(8.dp))
            LinearProgressIndicator(
                progress = { state.progressToNext },
                modifier = Modifier.fillMaxWidth().height(8.dp),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                usd(state.volumeToNextCents) + " more 30-day volume to reach " + (state.nextTierName ?: "") + ".",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun TableHeader() {
    Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp)) {
        HeaderCell("Tier", 2.2f)
        HeaderCell("30d vol", 1.8f)
        HeaderCell("Maker", 1.2f)
        HeaderCell("Taker", 1.2f)
    }
}

@Composable
private fun RowScope.HeaderCell(text: String, weight: Float) {
    Text(
        text,
        style = MaterialTheme.typography.labelSmall,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.weight(weight),
    )
}

@Composable
private fun TierRow(row: FeeTierRow) {
    val bg = if (row.isCurrent) MaterialTheme.colorScheme.secondaryContainer else Color.Transparent
    val fw = if (row.isCurrent) FontWeight.Bold else FontWeight.Normal
    Row(
        Modifier.fillMaxWidth().background(bg).padding(horizontal = 4.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Cell(row.name + (if (row.isCurrent) "  (you)" else ""), 2.2f, fw)
        Cell(usdShort(row.minVolumeCents), 1.8f, fw)
        Cell(bpsPct(row.makerBps), 1.2f, fw)
        Cell(bpsPct(row.takerBps), 1.2f, fw)
    }
}

@Composable
private fun RowScope.Cell(text: String, weight: Float, fw: FontWeight) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        fontWeight = fw,
        fontSize = 14.sp,
        modifier = Modifier.weight(weight),
    )
}

// ---- formatting helpers ----

private fun bpsPct(bps: Int): String = String.format(Locale.US, "%.2f%%", bps / 100.0)

private fun usd(cents: Long): String = "$" + String.format(Locale.US, "%,.2f", cents / 100.0)

private fun usdShort(cents: Long): String {
    val d = cents / 100.0
    return when {
        d >= 1_000_000 -> "$" + trimZeros(d / 1_000_000.0) + "M"
        d >= 1_000 -> "$" + trimZeros(d / 1_000.0) + "K"
        else -> "$" + String.format(Locale.US, "%,.0f", d)
    }
}

private fun trimZeros(v: Double): String {
    val s = String.format(Locale.US, "%.1f", v)
    return if (s.endsWith(".0")) s.dropLast(2) else s
}
