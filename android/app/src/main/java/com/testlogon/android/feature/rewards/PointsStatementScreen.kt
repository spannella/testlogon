@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.rewards

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
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Divider
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.rewards.PointsExpiryLot

/** Stable testTags for the Points statement / expiry screen. */
object PointsStatementTestTags {
    const val SCREEN = "points_statement_screen"
    const val CONTENT = "points_statement_content"
    const val LOADING = "points_statement_loading"
    const val ERROR = "points_statement_error"
    const val COMING_SOON = "points_statement_coming_soon"
    const val EMPTY = "points_statement_empty"
    const val EXPIRY_BANNER = "points_statement_expiry_banner"
    const val SHARE = "points_statement_share"
    const val COPY = "points_statement_copy"
    const val PERIOD_PREFIX = "points_statement_period_"
}

/** Route-level Points statement entry (reached from the Rewards screen / More -> Growth hub). */
@Composable
fun PointsStatementRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PointsStatementViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PointsStatementScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onPeriod = viewModel::onPeriodChanged,
        modifier = modifier,
    )
}

@Composable
fun PointsStatementScreen(
    state: PointsStatementUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onPeriod: (PointsExpiryMath.StatementPeriod) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    Scaffold(
        modifier = modifier.fillMaxSize().testTag(PointsStatementTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Points statement") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("points_statement_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (state.hasRows) {
                        IconButton(
                            onClick = { sharePointsStatementCsv(context, state.csv, state.csvName) },
                            modifier = Modifier.testTag(PointsStatementTestTags.SHARE),
                        ) {
                            Icon(Icons.Filled.Share, contentDescription = "Share CSV")
                        }
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when {
                state.loading -> LoadingState(modifier = Modifier.testTag(PointsStatementTestTags.LOADING))

                state.offline -> ErrorState(
                    message = state.errorMessage ?: "Couldn't load your points.",
                    onRetry = onRetry,
                    modifier = Modifier.testTag(PointsStatementTestTags.ERROR),
                )

                !state.available -> EmptyState(
                    title = "Points coming soon",
                    body = "Earn points from referrals and activity, then track your balance, statement and upcoming expirations here. This lights up once rewards are enabled for your account.",
                    modifier = Modifier.testTag(PointsStatementTestTags.COMING_SOON),
                )

                state.isEmpty -> EmptyState(
                    title = "No points activity yet",
                    body = "Once you earn or redeem points, your running-balance statement and upcoming expirations will appear here.",
                    modifier = Modifier.testTag(PointsStatementTestTags.EMPTY),
                )

                else -> PointsStatementContent(
                    state = state,
                    onPeriod = onPeriod,
                    onShare = { sharePointsStatementCsv(context, state.csv, state.csvName) },
                    onCopy = { copyPointsStatementCsv(context, state.csv) },
                )
            }
        }
    }
}

@Composable
private fun PointsStatementContent(
    state: PointsStatementUiState,
    onPeriod: (PointsExpiryMath.StatementPeriod) -> Unit,
    onShare: () -> Unit,
    onCopy: () -> Unit,
) {
    Column(
        modifier = Modifier
            .testTag(PointsStatementTestTags.CONTENT)
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        BalanceCard(state)
        if (state.hasExpiringSoon) {
            ExpiringSoonBanner(state)
        }
        ExpiryPolicyCard(state)
        StatementCard(state, onPeriod = onPeriod, onShare = onShare, onCopy = onCopy)
        if (state.upcoming.isNotEmpty()) {
            UpcomingExpirationsCard(state.upcoming, estimated = state.expiryEstimated)
        }
    }
}

@Composable
private fun BalanceCard(state: PointsStatementUiState) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Points balance", style = MaterialTheme.typography.labelMedium)
            Text(RewardsMath.formatPoints(state.points), style = MaterialTheme.typography.headlineMedium)
            Text(
                "Lifetime earned: ${RewardsMath.formatPoints(state.lifetimePoints)}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ExpiringSoonBanner(state: PointsStatementUiState) {
    Surface(
        modifier = Modifier.fillMaxWidth().testTag(PointsStatementTestTags.EXPIRY_BANNER),
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "${RewardsMath.formatPoints(state.expiringSoonPoints)} expiring soon",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                )
                if (state.expiryEstimated) {
                    AssistChip(onClick = {}, label = { Text("Est.") })
                }
            }
            Text(
                "${RewardsMath.formatPoints(state.nextExpiryPoints)} expire on ${PointsExpiryMath.formatDateUtc(state.nextExpiryTs)}. Redeem them before then so you don't lose value.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun ExpiryPolicyCard(state: PointsStatementUiState) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Expiry policy", style = MaterialTheme.typography.titleMedium)
            Text(
                "Points expire ${state.expiryPolicyMonths} months after they are earned. We warn you when points are within ${PointsExpiryMath.EXPIRING_SOON_DAYS} days of expiring.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (state.expiryEstimated) {
                Text(
                    "Expirations are estimated from your activity history until the server publishes an authoritative schedule.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun StatementCard(
    state: PointsStatementUiState,
    onPeriod: (PointsExpiryMath.StatementPeriod) -> Unit,
    onShare: () -> Unit,
    onCopy: () -> Unit,
) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Statement", style = MaterialTheme.typography.titleMedium)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                PeriodChip("All", PointsExpiryMath.StatementPeriod.ALL, state.period, onPeriod)
                PeriodChip("This year", PointsExpiryMath.StatementPeriod.THIS_YEAR, state.period, onPeriod)
                PeriodChip("This month", PointsExpiryMath.StatementPeriod.THIS_MONTH, state.period, onPeriod)
            }

            if (!state.hasRows) {
                Text(
                    "No activity in this period.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                // Header row.
                Row(modifier = Modifier.fillMaxWidth()) {
                    Text("Date", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1.1f))
                    Text("Activity", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1.6f))
                    Text("Points", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(0.9f), textAlign = TextAlign.End)
                    Text("Balance", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(0.9f), textAlign = TextAlign.End)
                }
                state.rows.forEachIndexed { i, r ->
                    if (i > 0) Divider()
                    StatementRowView(r)
                }

                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onShare,
                        modifier = Modifier.testTag(PointsStatementTestTags.SHARE + "_btn"),
                    ) {
                        Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.height(18.dp))
                        Spacer(Modifier.height(0.dp))
                        Text("Share CSV")
                    }
                    OutlinedButton(
                        onClick = onCopy,
                        modifier = Modifier.testTag(PointsStatementTestTags.COPY),
                    ) { Text("Copy CSV") }
                }
            }
        }
    }
}

@Composable
private fun PeriodChip(
    label: String,
    value: PointsExpiryMath.StatementPeriod,
    selected: PointsExpiryMath.StatementPeriod,
    onPeriod: (PointsExpiryMath.StatementPeriod) -> Unit,
) {
    FilterChip(
        selected = value == selected,
        onClick = { onPeriod(value) },
        label = { Text(label) },
        modifier = Modifier.testTag(PointsStatementTestTags.PERIOD_PREFIX + value.name),
    )
}

@Composable
private fun StatementRowView(r: PointsExpiryMath.StatementRow) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            PointsExpiryMath.formatDateUtc(r.ts).ifBlank { "—" },
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.weight(1.1f),
        )
        Text(r.description, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1.6f))
        Text(
            PointsExpiryMath.signedPointsLabel(r.delta),
            style = MaterialTheme.typography.labelLarge,
            color = if (r.delta < 0L) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.End,
            modifier = Modifier.weight(0.9f),
        )
        Text(
            RewardsMath.groupThousands(r.runningBalance),
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.End,
            modifier = Modifier.weight(0.9f),
        )
    }
}

@Composable
private fun UpcomingExpirationsCard(upcoming: List<PointsExpiryLot>, estimated: Boolean) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Upcoming expirations", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                if (estimated) AssistChip(onClick = {}, label = { Text("Est.") })
            }
            upcoming.forEachIndexed { i, lot ->
                if (i > 0) Divider()
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "Expires ${PointsExpiryMath.formatDateUtc(lot.expiresTs)}",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            "Earned ${PointsExpiryMath.formatDateUtc(lot.earnedTs)}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Text(RewardsMath.formatPoints(lot.pointsRemaining), style = MaterialTheme.typography.labelLarge)
                }
            }
        }
    }
}
