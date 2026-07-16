@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.payouts

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ReceiptLong
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.payouts.WalletSummary

/** PAY-52 — stable testTags for the wallet home. */
object WalletTestTags {
    const val SCREEN = "wallet_screen"
    const val CONTENT = "wallet_content"
    const val AVAILABLE = "wallet_available"
    const val WITHDRAW = "wallet_withdraw"
    const val HISTORY = "wallet_history"
    const val HELD = "wallet_held"
    const val PENDING = "wallet_pending"
}

/**
 * PAY-52 — route-level wallet home. The money-OUT surface entry (More > Wallet hub): real available +
 * held + pending + lifetime-paid, a Withdraw CTA (routes through the PAY-C gate on the setup/withdraw
 * screen) and a link into the payout history/statements.
 */
@Composable
fun WalletRoute(
    onWithdraw: () -> Unit,
    onViewHistory: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: WalletViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    // Refresh on resume so the available/held figures reflect a just-made withdraw's real debit.
    LifecycleResumeEffect(Unit) {
        viewModel.refresh()
        onPauseOrDispose { }
    }
    WalletScreen(
        state = state,
        onWithdraw = onWithdraw,
        onViewHistory = onViewHistory,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::load,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun WalletScreen(
    state: WalletViewModel.UiState,
    onWithdraw: () -> Unit,
    onViewHistory: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(WalletTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.wallet_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("wallet_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoading && state.summary == null ->
                    LoadingState(message = stringResource(R.string.wallet_loading))

                state.summary == null ->
                    ErrorState(
                        message = state.error?.asString() ?: stringResource(R.string.wallet_error_generic),
                        onRetry = onRetry,
                    )

                else -> WalletContent(
                    summary = state.summary,
                    isRefreshing = state.isRefreshing,
                    onWithdraw = onWithdraw,
                    onViewHistory = onViewHistory,
                    onRefresh = onRefresh,
                )
            }
        }
    }
}

@Composable
private fun WalletContent(
    summary: WalletSummary,
    isRefreshing: Boolean,
    onWithdraw: () -> Unit,
    onViewHistory: () -> Unit,
    onRefresh: () -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
                .testTag(WalletTestTags.CONTENT),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Available balance + Withdraw CTA.
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = stringResource(R.string.wallet_available_label),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = formatPayoutMoney(summary.money(summary.availableCents)),
                        style = MaterialTheme.typography.displaySmall,
                        modifier = Modifier.testTag(WalletTestTags.AVAILABLE).semantics { heading() },
                    )
                    Text(
                        text = stringResource(
                            R.string.wallet_minimum_note,
                            formatPayoutMoney(summary.money(summary.minimumPayoutCents)),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Button(
                        onClick = onWithdraw,
                        modifier = Modifier.fillMaxWidth().testTag(WalletTestTags.WITHDRAW),
                    ) { Text(stringResource(R.string.wallet_withdraw_action)) }
                }
            }

            // Held (7-day hold) + pending, side by side.
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                StatCard(
                    modifier = Modifier.weight(1f).testTag(WalletTestTags.HELD),
                    label = stringResource(R.string.wallet_held_label),
                    amount = formatPayoutMoney(summary.money(summary.heldCents)),
                    caption = summary.heldReleaseAtEpochSeconds?.let { formatPayoutDate(it) }
                        ?.let { stringResource(R.string.wallet_held_until, it) }
                        ?: stringResource(R.string.wallet_held_none),
                )
                StatCard(
                    modifier = Modifier.weight(1f).testTag(WalletTestTags.PENDING),
                    label = stringResource(R.string.wallet_pending_label),
                    amount = formatPayoutMoney(summary.money(summary.pendingCents)),
                    caption = stringResource(R.string.wallet_pending_count, summary.pendingCount),
                )
            }

            // Lifetime totals.
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    TotalRow(
                        label = stringResource(R.string.wallet_lifetime_paid_label),
                        value = formatPayoutMoney(summary.money(summary.lifetimePaidCents)),
                    )
                    HorizontalDivider()
                    TotalRow(
                        label = stringResource(R.string.wallet_total_earned_label),
                        value = formatPayoutMoney(summary.money(summary.totalEarnedCents)),
                    )
                }
            }

            // Payout history / statements entry.
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(WalletTestTags.HISTORY)
                    .clickable(onClick = onViewHistory),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        Icons.Filled.ReceiptLong,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        text = stringResource(R.string.wallet_view_history),
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

@Composable
private fun StatCard(label: String, amount: String, caption: String, modifier: Modifier = Modifier) {
    Card(modifier = modifier) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(text = amount, style = MaterialTheme.typography.titleLarge)
            Text(
                text = caption,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun TotalRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(text = value, style = MaterialTheme.typography.titleMedium)
    }
}
