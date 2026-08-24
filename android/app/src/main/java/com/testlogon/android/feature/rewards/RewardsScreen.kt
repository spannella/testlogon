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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.input.KeyboardType
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
    const val TRADING = "rewards_trading_card"
    const val TRADING_CTA = "rewards_trading_cta"
    const val CONVERT_CARD = "rewards_convert_cash_card"
    const val CONVERT_INPUT = "rewards_convert_cash_input"
    const val CONVERT_CTA = "rewards_convert_cash_cta"
    const val CONVERT_CONFIRM = "rewards_convert_cash_confirm"
    const val CASH_LINK = "rewards_open_cash"
}

/** Route-level Rewards entry (reached from the More -> Growth hub). */
@Composable
fun RewardsRoute(
    onBack: () -> Unit,
    onOpenFeeTiers: () -> Unit = {},
    onOpenCash: () -> Unit = {},
    onOpenStatement: () -> Unit = {},
    onOpenStatusTiers: () -> Unit = {},
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
        onOpenFeeTiers = onOpenFeeTiers,
        onOpenCash = onOpenCash,
        onOpenStatement = onOpenStatement,
        onOpenStatusTiers = onOpenStatusTiers,
        onCashPointsChanged = viewModel::onCashPointsChanged,
        onCashPreset = viewModel::onCashPreset,
        onCashMax = viewModel::onCashMax,
        onConvertCash = viewModel::confirmRedeemCash,
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
    onOpenFeeTiers: () -> Unit = {},
    onOpenCash: () -> Unit = {},
    onOpenStatement: () -> Unit = {},
    onOpenStatusTiers: () -> Unit = {},
    onCashPointsChanged: (String) -> Unit = {},
    onCashPreset: (Long) -> Unit = {},
    onCashMax: () -> Unit = {},
    onConvertCash: (Long) -> Unit = {},
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    var pendingRedeem by remember { mutableStateOf<CatalogReward?>(null) }
    var pendingCashPoints by remember { mutableStateOf<Long?>(null) }

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
                    onOpenFeeTiers = onOpenFeeTiers,
                    onOpenCash = onOpenCash,
                    onOpenStatement = onOpenStatement,
                    onOpenStatusTiers = onOpenStatusTiers,
                    onCashPointsChanged = onCashPointsChanged,
                    onCashPreset = onCashPreset,
                    onCashMax = onCashMax,
                    onConvertClick = { pendingCashPoints = it },
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

    val cashPts = pendingCashPoints
    if (cashPts != null) {
        val credited = RewardsCashMath.cashCentsForPoints(cashPts)
        AlertDialog(
            onDismissRequest = { pendingCashPoints = null },
            title = { Text("Convert points to cash") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    RedeemRow("Convert", RewardsCashMath.formatPoints(cashPts), emphasize = true)
                    RedeemRow("You'll receive", RewardsCashMath.formatCentsUsd(credited), emphasize = true)
                    RedeemRow("Points after", RewardsCashMath.formatPoints(RewardsCashMath.pointsAfterRedeem(state.points, cashPts)))
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Redeem ${RewardsCashMath.formatPoints(cashPts)} for ${RewardsCashMath.formatCentsUsd(credited)} to your USD cash wallet.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                Button(
                    enabled = !state.convertingCash,
                    onClick = {
                        pendingCashPoints = null
                        onConvertCash(cashPts)
                    },
                    modifier = Modifier.testTag(RewardsTestTags.CONVERT_CONFIRM),
                ) { Text("Convert") }
            },
            dismissButton = { TextButton(onClick = { pendingCashPoints = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun RewardsContent(
    state: RewardsUiState,
    onRedeemClick: (CatalogReward) -> Unit,
    onOpenFeeTiers: () -> Unit,
    onOpenCash: () -> Unit,
    onOpenStatement: () -> Unit,
    onOpenStatusTiers: () -> Unit,
    onCashPointsChanged: (String) -> Unit,
    onCashPreset: (Long) -> Unit,
    onCashMax: () -> Unit,
    onConvertClick: (Long) -> Unit,
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
        OutlinedButton(
            onClick = onOpenStatement,
            modifier = Modifier.fillMaxWidth().testTag("rewards_open_statement"),
        ) { Text("View statement & expiry") }
        OutlinedButton(
            onClick = onOpenStatusTiers,
            modifier = Modifier.fillMaxWidth().testTag("rewards_open_status_tiers"),
        ) { Text("Status & tiers") }
        ConvertToCashCard(
            state = state,
            onOpenCash = onOpenCash,
            onCashPointsChanged = onCashPointsChanged,
            onCashPreset = onCashPreset,
            onCashMax = onCashMax,
            onConvertClick = onConvertClick,
        )
        state.tradingRewards?.let { TradingRewardsCard(it, onOpenFeeTiers) }
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
private fun TradingRewardsCard(
    summary: TradingRewardsMath.Summary,
    onOpenFeeTiers: () -> Unit,
) {
    ElevatedCard(modifier = Modifier.fillMaxWidth().testTag(RewardsTestTags.TRADING)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Trading rewards", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                AssistChip(
                    onClick = {},
                    label = { Text(if (summary.isAuthoritative) "Live" else "Estimated") },
                )
            }
            Text(
                "Earn ${RewardsMath.formatPoints(summary.pointsPerDollar)} per $1 traded",
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                "Your 30-day volume: ${RewardsMath.formatCentsUsd(summary.volume30dCents)} → ~${RewardsMath.formatPoints(summary.pointsEarned30d)}",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (summary.isAuthoritative && summary.lifetimeTradingPoints > 0L) {
                Text(
                    "Lifetime trading points: ${RewardsMath.formatPoints(summary.lifetimeTradingPoints)}",
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            Text(
                if (summary.isAuthoritative) {
                    "Points accrue automatically as your trades fill."
                } else {
                    "Estimated from your trade history. Points accrue automatically as your trades fill."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = onOpenFeeTiers,
                modifier = Modifier.testTag(RewardsTestTags.TRADING_CTA),
            ) { Text("Trade & view fee tiers") }
        }
    }
}

@Composable
private fun ConvertToCashCard(
    state: RewardsUiState,
    onOpenCash: () -> Unit,
    onCashPointsChanged: (String) -> Unit,
    onCashPreset: (Long) -> Unit,
    onCashMax: () -> Unit,
    onConvertClick: (Long) -> Unit,
) {
    ElevatedCard(modifier = Modifier.fillMaxWidth().testTag(RewardsTestTags.CONVERT_CARD)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Convert points to cash", style = MaterialTheme.typography.titleMedium)
            Text(
                "Rate: ${RewardsCashMath.rateLabel()} · Min ${RewardsCashMath.formatPoints(RewardsCashMath.MIN_REDEEM_POINTS)} (${RewardsCashMath.formatCentsUsd(RewardsCashMath.minRedeemCents())})",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = state.cashPointsInput,
                onValueChange = onCashPointsChanged,
                singleLine = true,
                label = { Text("Points to convert") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth().testTag(RewardsTestTags.CONVERT_INPUT),
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = { onCashPreset(500L) }, label = { Text("$5") })
                AssistChip(onClick = { onCashPreset(1000L) }, label = { Text("$10") })
                AssistChip(onClick = onCashMax, label = { Text("Max") })
            }

            Text(
                "You'll receive ${RewardsCashMath.formatCentsUsd(state.cashCentsForInput)}",
                style = MaterialTheme.typography.titleMedium,
            )

            val hint = when (state.cashValidation) {
                RewardsCashMath.Validation.NOT_POSITIVE -> null
                RewardsCashMath.Validation.BELOW_MIN ->
                    "Minimum is ${RewardsCashMath.formatPoints(RewardsCashMath.MIN_REDEEM_POINTS)}."
                RewardsCashMath.Validation.INSUFFICIENT ->
                    "You only have ${RewardsCashMath.formatPoints(state.points)}."
                RewardsCashMath.Validation.VALID -> null
            }
            if (hint != null) {
                Text(hint, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
            }

            Button(
                enabled = state.canConvertCash,
                onClick = { onConvertClick(state.cashPoints) },
                modifier = Modifier.fillMaxWidth().testTag(RewardsTestTags.CONVERT_CTA),
            ) { Text(if (state.convertingCash) "Converting..." else "Convert to cash") }

            TextButton(
                onClick = onOpenCash,
                modifier = Modifier.testTag(RewardsTestTags.CASH_LINK),
            ) { Text("Open USD cash wallet") }
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
