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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.rewards.CatalogReward
import com.testlogon.android.data.rewards.RewardsHistoryEntry

/** Stable testTags for the Rewards screen. */
object RewardsTestTags {
    const val SCREEN = "rewards_screen"
    const val CONTENT = "rewards_content"
    const val LOADING = "rewards_loading"
    const val ERROR = "rewards_error"
    const val COMING_SOON = "rewards_coming_soon"
    const val REDEEM_PREFIX = "rewards_redeem_"
    const val REDEEM_CONFIRM = "rewards_redeem_confirm"
}

/** Route-level Rewards entry (reached from the More -> Growth hub). */
@Composable
fun RewardsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: RewardsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(state.successMessage, state.errorMessage) {
        val msg = state.successMessage ?: state.errorMessage
        if (msg != null) {
            snackbarHostState.showSnackbar(msg)
            viewModel.consumeMessages()
        }
    }

    RewardsScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onRedeem = viewModel::confirmRedeem,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun RewardsScreen(
    state: RewardsUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRedeem: (CatalogReward) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    var pendingRedeem by remember { mutableStateOf<CatalogReward?>(null) }

    Scaffold(
        modifier = modifier.testTag(RewardsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Rewards") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("rewards_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when {
                state.loading -> LoadingState(modifier = Modifier.testTag(RewardsTestTags.LOADING))

                state.offline ->
                    ErrorState(
                        message = state.errorMessage ?: "Couldn't load your rewards.",
                        onRetry = onRetry,
                        modifier = Modifier.testTag(RewardsTestTags.ERROR),
                    )

                !state.available ->
                    EmptyState(
                        title = "Rewards coming soon",
                        body = "Earn points from referrals and activity, then redeem them for cash or perks. This will light up once rewards are enabled for your account.",
                        modifier = Modifier.testTag(RewardsTestTags.COMING_SOON),
                    )

                else -> RewardsContent(
                    state = state,
                    onRedeemClick = { pendingRedeem = it },
                )
            }
        }
    }

    val toRedeem = pendingRedeem
    if (toRedeem != null) {
        val cashNote = if (RewardsMath.isCashReward(toRedeem)) {
            "${RewardsMath.formatCentsUsd(toRedeem.valueCents)} will be credited to your USD cash wallet."
        } else {
            "This perk will be applied to your account."
        }
        AlertDialog(
            onDismissRequest = { pendingRedeem = null },
            title = { Text("Confirm redemption") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    RedeemRow("Reward", toRedeem.name)
                    RedeemRow("Cost", RewardsMath.formatPoints(toRedeem.costPoints), emphasize = true)
                    RedeemRow("Points after", RewardsMath.formatPoints(RewardsMath.pointsAfterRedeem(state.points, toRedeem)))
                    Spacer(Modifier.height(6.dp))
                    Text(cashNote, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            },
            confirmButton = {
                Button(
                    enabled = !state.redeeming,
                    onClick = {
                        pendingRedeem = null
                        onRedeem(toRedeem)
                    },
                    modifier = Modifier.testTag(RewardsTestTags.REDEEM_CONFIRM),
                ) { Text("Redeem") }
            },
            dismissButton = { TextButton(onClick = { pendingRedeem = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun RewardsContent(
    state: RewardsUiState,
    onRedeemClick: (CatalogReward) -> Unit,
) {
    Column(
        modifier = Modifier
            .testTag(RewardsTestTags.CONTENT)
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        BalanceCard(state)
        if (state.rewards.waysToEarn.isNotEmpty()) {
            WaysToEarnCard(state)
        }
        if (state.catalog.isNotEmpty()) {
            CatalogCard(state = state, onRedeemClick = onRedeemClick)
        }
        if (state.history.isNotEmpty()) {
            HistoryCard(state.history)
        }
    }
}

@Composable
private fun BalanceCard(state: RewardsUiState) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Points balance", style = MaterialTheme.typography.labelMedium)
            Text(RewardsMath.formatPoints(state.rewards.points), style = MaterialTheme.typography.headlineMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                Column {
                    Text("Cash", style = MaterialTheme.typography.labelMedium)
                    Text(RewardsMath.formatCentsUsd(state.rewards.cashCents), style = MaterialTheme.typography.titleMedium)
                }
                Column {
                    Text("Lifetime points", style = MaterialTheme.typography.labelMedium)
                    Text(RewardsMath.formatPoints(state.rewards.lifetimePoints), style = MaterialTheme.typography.titleMedium)
                }
            }
        }
    }
}

@Composable
private fun WaysToEarnCard(state: RewardsUiState) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Ways to earn", style = MaterialTheme.typography.titleMedium)
            state.rewards.waysToEarn.forEachIndexed { i, w ->
                if (i > 0) Divider()
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(w.title, style = MaterialTheme.typography.bodyMedium)
                        if (w.detail.isNotBlank()) {
                            Text(w.detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    Text("+${RewardsMath.formatPoints(w.points)}", style = MaterialTheme.typography.labelLarge)
                }
            }
        }
    }
}

@Composable
private fun CatalogCard(
    state: RewardsUiState,
    onRedeemClick: (CatalogReward) -> Unit,
) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Redeem points", style = MaterialTheme.typography.titleMedium)
            state.catalog.forEachIndexed { i, reward ->
                if (i > 0) Divider()
                val affordable = RewardsMath.canRedeem(reward, state.points)
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(reward.name, style = MaterialTheme.typography.bodyLarge)
                            if (RewardsMath.isCashReward(reward)) {
                                AssistChip(onClick = {}, label = { Text("Cash") })
                            }
                        }
                        if (reward.description.isNotBlank()) {
                            Text(reward.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        val sub = if (RewardsMath.isCashReward(reward)) {
                            "${RewardsMath.formatPoints(reward.costPoints)} · ${RewardsMath.formatCentsUsd(reward.valueCents)} to wallet"
                        } else {
                            RewardsMath.formatPoints(reward.costPoints)
                        }
                        Text(sub, style = MaterialTheme.typography.labelMedium)
                        if (!affordable) {
                            Text(
                                "Earn ${RewardsMath.formatPoints(RewardsMath.pointsNeeded(reward, state.points))} more to unlock",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                    }
                    OutlinedButton(
                        enabled = affordable && !state.redeeming,
                        onClick = { onRedeemClick(reward) },
                        modifier = Modifier.testTag(RewardsTestTags.REDEEM_PREFIX + reward.id),
                    ) { Text(if (affordable) "Redeem" else "Locked") }
                }
            }
        }
    }
}

@Composable
private fun HistoryCard(history: List<RewardsHistoryEntry>) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Activity", style = MaterialTheme.typography.titleMedium)
            history.forEachIndexed { i, e ->
                if (i > 0) Divider()
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(e.description, style = MaterialTheme.typography.bodyMedium)
                        if (e.status.isNotBlank()) {
                            Text(e.status, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        if (e.points != 0L) {
                            Text(signedPoints(e.points), style = MaterialTheme.typography.labelLarge)
                        }
                        if (e.cashCents != 0L) {
                            Text(RewardsMath.formatCentsUsd(e.cashCents), style = MaterialTheme.typography.labelMedium)
                        }
                    }
                }
            }
        }
    }
}

private fun signedPoints(points: Long): String {
    val sign = if (points > 0) "+" else ""
    return "$sign${RewardsMath.formatPoints(points)}"
}

@Composable
private fun RedeemRow(label: String, value: String, emphasize: Boolean = false) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            value,
            style = if (emphasize) MaterialTheme.typography.titleMedium else MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.End,
        )
    }
}
