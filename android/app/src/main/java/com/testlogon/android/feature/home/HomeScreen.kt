@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.home

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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ShowChart
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.outlined.AccountBalanceWallet
import androidx.compose.material.icons.outlined.Circle
import androidx.compose.material.icons.outlined.NotificationsActive
import androidx.compose.material.icons.outlined.PieChart
import androidx.compose.material.icons.outlined.SwapHoriz
import androidx.compose.foundation.clickable
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.util.Locale

/** Green/red for change + PnL, independent of the app theme (matches the markets/portfolio convention). */
private val Up = Color(0xFF16A34A)
private val Down = Color(0xFFDC2626)

/**
 * Trading Home / Dashboard route. Read-only launch surface composed from existing account reads; each
 * card degrades independently. Navigation is delegated to the caller so this feature owns no routes.
 */
@Composable
fun HomeRoute(
    onBack: () -> Unit,
    onOpenTarget: (HomeTarget) -> Unit,
    onOpenSymbol: (Int) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: HomeViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    // Enrich the watchlist snapshot with live-ish quotes once the initial frame (with the starred
    // rows) is present; safe to call repeatedly (it no-ops when there are no rows).
    LaunchedEffect(state.watchlist.rows.size) { viewModel.enrichWatchlist() }
    HomeScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onOpenTarget = onOpenTarget,
        onOpenSymbol = onOpenSymbol,
        onDismissOnboarding = viewModel::dismissOnboarding,
        modifier = modifier,
    )
}

@Composable
fun HomeScreen(
    state: HomeUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onOpenTarget: (HomeTarget) -> Unit,
    onOpenSymbol: (Int) -> Unit,
    onDismissOnboarding: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text("Home") },
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
            // 5. Getting-started checklist — prominent while incomplete; dismissible "all set" when done.
            if (state.onboarding.showChecklist) {
                item { OnboardingChecklistCard(state.onboarding, onOpenTarget) }
            } else if (state.onboarding.showAllSet) {
                item { OnboardingAllSetCard(onDismissOnboarding) }
            }

            // 1. Portfolio summary.
            item { PortfolioSummaryCard(state.portfolio, onOpenTarget) }

            // 4. Quick actions.
            item { QuickActionsCard(onOpenTarget) }

            // 2. Watchlist snapshot.
            item { WatchlistCard(state.watchlist, onOpenSymbol) }

            // 3. Recent activity.
            item { RecentActivityCard(state.activity, onOpenTarget) }

            item { Spacer(Modifier.height(8.dp)) }
        }
    }
}

// ---------------- 1. Portfolio summary ----------------

@Composable
private fun PortfolioSummaryCard(portfolio: HomePortfolio, onOpenTarget: (HomeTarget) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(
                if (portfolio.priced) "Total equity (USD)" else "Total equity",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(4.dp))
            when {
                portfolio.loading -> InlineLoading()
                portfolio.unavailable -> Text(
                    "Unavailable right now.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
                else -> {
                    Text(
                        text = portfolio.equityText,
                        fontSize = 30.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    if (portfolio.priced && portfolio.pricesStub) {
                        Text(
                            "indicative (stub prices)",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    } else if (!portfolio.priced) {
                        Text(
                            "source-native total (prices unavailable)",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                        HeadlineStat(
                            label = "Available",
                            value = portfolio.available?.let { fmt(it) } ?: "--",
                        )
                        val upnl = portfolio.unrealizedPnl
                        HeadlineStat(
                            label = "Unrealized PnL",
                            value = upnl?.let { signed(it) } ?: "--",
                            valueColor = upnl?.let { if (it >= 0) Up else Down },
                        )
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = { onOpenTarget(HomeTarget.PORTFOLIO) }) { Text("View portfolio") }
        }
    }
}

@Composable
private fun HeadlineStat(label: String, value: String, valueColor: Color? = null) {
    Column {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
        )
        Text(
            value,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.SemiBold,
            color = valueColor ?: MaterialTheme.colorScheme.onPrimaryContainer,
        )
    }
}

// ---------------- 4. Quick actions ----------------

@Composable
private fun QuickActionsCard(onOpenTarget: (HomeTarget) -> Unit) {
    SectionCard(title = "Quick actions") {
        Row(
            Modifier.fillMaxWidth().padding(top = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            QuickAction("Trade", Icons.AutoMirrored.Filled.ShowChart, Modifier.weight(1f)) { onOpenTarget(HomeTarget.TRADE) }
            QuickAction("Deposit", Icons.Outlined.AccountBalanceWallet, Modifier.weight(1f)) { onOpenTarget(HomeTarget.DEPOSIT) }
            QuickAction("Portfolio", Icons.Outlined.PieChart, Modifier.weight(1f)) { onOpenTarget(HomeTarget.PORTFOLIO) }
        }
        Spacer(Modifier.height(8.dp))
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            QuickAction("PnL", Icons.Outlined.SwapHoriz, Modifier.weight(1f)) { onOpenTarget(HomeTarget.PNL) }
            QuickAction("Alerts", Icons.Outlined.NotificationsActive, Modifier.weight(1f)) { onOpenTarget(HomeTarget.PRICE_ALERTS) }
            Spacer(Modifier.weight(1f))
        }
    }
}

@Composable
private fun QuickAction(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    FilledTonalButton(onClick = onClick, modifier = modifier) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(6.dp))
        Text(label, maxLines = 1)
    }
}

// ---------------- 2. Watchlist snapshot ----------------

@Composable
private fun WatchlistCard(watchlist: HomeWatchlist, onOpenSymbol: (Int) -> Unit) {
    SectionCard(title = "Watchlist") {
        when {
            watchlist.loading -> InlineLoading()
            !watchlist.hasStarred -> Text(
                "Star symbols in Markets to see them here.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            else -> Column {
                watchlist.rows.forEachIndexed { i, row ->
                    if (i > 0) HorizontalDivider()
                    WatchRowView(row, onOpenSymbol)
                }
            }
        }
    }
}

@Composable
private fun WatchRowView(row: HomeWatchRow, onOpenSymbol: (Int) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable { onOpenSymbol(row.symbolId) }
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(row.symbol, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
        Text(
            row.lastPriceText ?: "--",
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(end = 12.dp),
        )
        Text(
            text = row.changePct?.let { String.format(Locale.US, "%+.2f%%", it) } ?: "--",
            color = row.changePct?.let { if (it >= 0) Up else Down } ?: MaterialTheme.colorScheme.onSurfaceVariant,
            fontFamily = FontFamily.Monospace,
        )
    }
}

// ---------------- 3. Recent activity ----------------

@Composable
private fun RecentActivityCard(activity: HomeActivity, onOpenTarget: (HomeTarget) -> Unit) {
    SectionCard(title = "Recent activity") {
        when {
            activity.loading -> InlineLoading()
            activity.unavailable -> Text(
                "Unavailable right now.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            activity.isEmpty -> Text(
                "No fills yet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            else -> Column {
                activity.rows.forEachIndexed { i, row ->
                    if (i > 0) HorizontalDivider()
                    Row(
                        Modifier.fillMaxWidth().padding(vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            row.sideLabel,
                            color = if (row.isBuy) Up else Down,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.width(44.dp),
                        )
                        Text(row.symbol, fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
                        Text(
                            "${row.qtyText} @ ${row.priceText}",
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
        Spacer(Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { onOpenTarget(HomeTarget.TRADE_HISTORY) }) { Text("Trade history") }
            TextButton(onClick = { onOpenTarget(HomeTarget.PNL) }) { Text("PnL") }
        }
    }
}

// ---------------- 5. Onboarding checklist ----------------

@Composable
private fun OnboardingChecklistCard(onboarding: HomeOnboarding, onOpenTarget: (HomeTarget) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(
                "Get started",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
            )
            Spacer(Modifier.height(8.dp))
            onboarding.steps.forEach { step ->
                StepRow(step, onOpenTarget)
            }
        }
    }
}

@Composable
private fun StepRow(step: OnboardingStep, onOpenTarget: (HomeTarget) -> Unit) {
    val done = step.isDone
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(enabled = !done) { onOpenTarget(step.target) }
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = if (done) Icons.Filled.CheckCircle else Icons.Outlined.Circle,
            contentDescription = null,
            tint = if (done) Up else MaterialTheme.colorScheme.onSecondaryContainer,
            modifier = Modifier.size(22.dp),
        )
        Spacer(Modifier.width(12.dp))
        Text(
            step.title,
            modifier = Modifier.weight(1f),
            color = MaterialTheme.colorScheme.onSecondaryContainer,
            fontWeight = if (done) FontWeight.Normal else FontWeight.Medium,
        )
        if (step.state == StepState.UNKNOWN) {
            Text(
                "—",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
            )
        }
    }
}

@Composable
private fun OnboardingAllSetCard(onDismiss: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = Up, modifier = Modifier.size(24.dp))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    "You're all set",
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                )
                Text(
                    "Custody funded, trading funded, first trade placed.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                )
            }
            TextButton(onClick = onDismiss) { Text("Dismiss") }
        }
    }
}

// ---------------- shared bits ----------------

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(
                title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(8.dp))
            content()
        }
    }
}

@Composable
private fun InlineLoading() {
    Box(Modifier.fillMaxWidth().padding(vertical = 12.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(modifier = Modifier.size(24.dp))
    }
}

private fun fmt(v: Long): String = String.format(Locale.US, "%,d", v)

private fun signed(v: Long): String = (if (v >= 0) "+" else "") + String.format(Locale.US, "%,d", v)
