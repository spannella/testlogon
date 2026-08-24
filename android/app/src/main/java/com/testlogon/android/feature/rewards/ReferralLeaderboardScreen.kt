@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.rewards

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.rewards.LeaderboardEntry
import com.testlogon.android.data.rewards.LeaderboardPeriod
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Stable testTags for the Referral leaderboard screen. */
object ReferralLeaderboardTestTags {
    const val SCREEN = "referral_leaderboard_screen"
    const val CONTENT = "referral_leaderboard_content"
    const val LOADING = "referral_leaderboard_loading"
    const val ERROR = "referral_leaderboard_error"
    const val COMING_SOON = "referral_leaderboard_coming_soon"
    const val PERIOD_ALL = "referral_leaderboard_period_all"
    const val PERIOD_MONTH = "referral_leaderboard_period_month"
    const val YOU_ROW = "referral_leaderboard_you_row"
}

/** Route-level Referral leaderboard entry (reached from the Refer & earn hub). */
@Composable
fun ReferralLeaderboardRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ReferralLeaderboardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ReferralLeaderboardScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onPeriodSelected = viewModel::onPeriodSelected,
        modifier = modifier,
    )
}

@Composable
fun ReferralLeaderboardScreen(
    state: ReferralLeaderboardUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onPeriodSelected: (LeaderboardPeriod) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ReferralLeaderboardTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Referral leaderboard") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("referral_leaderboard_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            PeriodToggle(selected = state.period, onPeriodSelected = onPeriodSelected)
            Box(modifier = Modifier.fillMaxSize()) {
                when {
                    state.loading -> LoadingState(modifier = Modifier.testTag(ReferralLeaderboardTestTags.LOADING))

                    // A genuine read failure (transport / server error) — offer retry.
                    state.offline || (state.errorMessage != null && !state.available) ->
                        ErrorState(
                            message = state.errorMessage ?: "Couldn't load the leaderboard.",
                            onRetry = onRetry,
                            modifier = Modifier.testTag(ReferralLeaderboardTestTags.ERROR),
                        )

                    // Clean 404 degrade, or an available-but-empty board -> honest coming-soon.
                    !state.available || !state.hasRows -> LeaderboardComingSoon()

                    else -> LeaderboardContent(state = state)
                }
            }
        }
    }
}

@Composable
private fun PeriodToggle(
    selected: LeaderboardPeriod,
    onPeriodSelected: (LeaderboardPeriod) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FilterChip(
            selected = selected == LeaderboardPeriod.ALL,
            onClick = { onPeriodSelected(LeaderboardPeriod.ALL) },
            label = { Text(ReferralLeaderboardMath.periodLabel(LeaderboardPeriod.ALL)) },
            modifier = Modifier.testTag(ReferralLeaderboardTestTags.PERIOD_ALL),
        )
        FilterChip(
            selected = selected == LeaderboardPeriod.MONTH,
            onClick = { onPeriodSelected(LeaderboardPeriod.MONTH) },
            label = { Text(ReferralLeaderboardMath.periodLabel(LeaderboardPeriod.MONTH)) },
            modifier = Modifier.testTag(ReferralLeaderboardTestTags.PERIOD_MONTH),
        )
    }
}

@Composable
private fun LeaderboardComingSoon() {
    EmptyState(
        title = "Leaderboard coming soon",
        body = "The top referrers and your own rank will appear here once the referral leaderboard is enabled for your account.",
        modifier = Modifier.testTag(ReferralLeaderboardTestTags.COMING_SOON),
    )
}

@Composable
private fun LeaderboardContent(state: ReferralLeaderboardUiState) {
    LazyColumn(
        modifier = Modifier
            .testTag(ReferralLeaderboardTestTags.CONTENT)
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item { HeaderRow() }
        items(state.shown, key = { it.id.ifBlank { "rank_" + it.rank } }) { entry ->
            LeaderboardRow(entry = entry, highlighted = entry.isYou)
        }
        state.youRow?.let { you ->
            item {
                Text(
                    "Your rank",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
            item {
                LeaderboardRow(
                    entry = you,
                    highlighted = true,
                    modifier = Modifier.testTag(ReferralLeaderboardTestTags.YOU_ROW),
                )
            }
        }
        if (state.updatedTs > 0L) {
            item {
                Text(
                    "Updated " + formatUpdated(state.updatedTs),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun HeaderRow() {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text("Rank", style = MaterialTheme.typography.labelMedium, modifier = Modifier.width(52.dp))
        Text("Referrer", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1f))
        Text("Qual.", style = MaterialTheme.typography.labelMedium, modifier = Modifier.width(48.dp))
        Text("Earned", style = MaterialTheme.typography.labelMedium, modifier = Modifier.width(72.dp))
    }
}

@Composable
private fun LeaderboardRow(
    entry: LeaderboardEntry,
    highlighted: Boolean,
    modifier: Modifier = Modifier,
) {
    val colors = if (highlighted) {
        CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
    } else {
        CardDefaults.cardColors()
    }
    Card(modifier = modifier.fillMaxWidth(), colors = colors) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                modifier = Modifier.width(52.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                medalEmoji(entry.rank)?.let { Text(it) }
                Text(
                    ReferralLeaderboardMath.formatRank(entry.rank),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = if (highlighted) FontWeight.Bold else FontWeight.Normal,
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    if (entry.isYou) "You" else entry.maskedName,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = if (highlighted) FontWeight.Bold else FontWeight.Normal,
                )
                Text(
                    ReferralLeaderboardMath.formatCount(entry.referredCount) + " referred",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                ReferralLeaderboardMath.formatCount(entry.qualifiedCount),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.width(48.dp),
            )
            Text(
                ReferralLeaderboardMath.formatRewardCents(entry.rewardCents),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.width(72.dp),
            )
        }
    }
}

private fun medalEmoji(rank: Int): String? = when (ReferralLeaderboardMath.rankMedal(rank)) {
    ReferralLeaderboardMath.Medal.GOLD -> "🥇"
    ReferralLeaderboardMath.Medal.SILVER -> "🥈"
    ReferralLeaderboardMath.Medal.BRONZE -> "🥉"
    ReferralLeaderboardMath.Medal.NONE -> null
}

private fun formatUpdated(tsSeconds: Long): String {
    val millis = if (tsSeconds < 100_000_000_000L) tsSeconds * 1000L else tsSeconds
    return SimpleDateFormat("MMM d, yyyy h:mm a", Locale.getDefault()).format(Date(millis))
}
