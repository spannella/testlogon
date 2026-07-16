@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ads.accounts.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** ADV3-4 (B4) - stable testTags for the advertiser-accounts list. */
object AdsAccountsTestTags {
    const val SCREEN = "ads_accounts_screen"
    const val LIST = "ads_accounts_list"
    const val EMPTY = "ads_accounts_empty"
    const val CREATE = "ads_accounts_create"
    fun row(accountId: String): String = "ads_account_row_$accountId"
}

/**
 * ADV3-4 (B4) - route-level advertiser-accounts list. This is the discovery surface that removes the
 * `listAccounts().firstOrNull()` single-account ceiling: each account row routes billing / campaigns /
 * analytics with a REAL accountId (not the "acc_sample" stub), so a 2+ account advertiser can act on any
 * account. Backed by the existing AdsAccountsViewModel (no new VM).
 */
@Composable
fun AdsAccountsRoute(
    onBack: () -> Unit,
    onOpenCampaigns: (accountId: String) -> Unit,
    onOpenBilling: (accountId: String) -> Unit,
    onOpenAnalytics: (accountId: String) -> Unit,
    onCreateAccount: () -> Unit,
    viewModel: AdsAccountsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    AdsAccountsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onSelect = viewModel::onAccountSelected,
        onOpenCampaigns = onOpenCampaigns,
        onOpenBilling = onOpenBilling,
        onOpenAnalytics = onOpenAnalytics,
        onCreateAccount = onCreateAccount,
    )
}

@Composable
fun AdsAccountsScreen(
    state: AdsAccountsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelect: (String) -> Unit,
    onOpenCampaigns: (String) -> Unit,
    onOpenBilling: (String) -> Unit,
    onOpenAnalytics: (String) -> Unit,
    onCreateAccount: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdsAccountsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Ad accounts") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is AdsAccountsUiState.Loading -> LoadingState()
                is AdsAccountsUiState.Empty -> EmptyState(
                    title = "No ad accounts yet",
                    body = "Create an advertiser account to start running campaigns.",
                    actionLabel = "Create ad account",
                    onAction = onCreateAccount,
                    modifier = Modifier.testTag(AdsAccountsTestTags.EMPTY),
                )
                is AdsAccountsUiState.Error -> ErrorState(message = state.error.message, onRetry = onRetry)
                is AdsAccountsUiState.Content -> AccountsContent(
                    state = state,
                    onRefresh = onRefresh,
                    onRetry = onRetry,
                    onSelect = onSelect,
                    onOpenCampaigns = onOpenCampaigns,
                    onOpenBilling = onOpenBilling,
                    onOpenAnalytics = onOpenAnalytics,
                    onCreateAccount = onCreateAccount,
                )
            }
        }
    }
}

@Composable
private fun AccountsContent(
    state: AdsAccountsUiState.Content,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelect: (String) -> Unit,
    onOpenCampaigns: (String) -> Unit,
    onOpenBilling: (String) -> Unit,
    onOpenAnalytics: (String) -> Unit,
    onCreateAccount: () -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize().testTag(AdsAccountsTestTags.LIST),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry) }
            items(state.accounts, key = { it.accountId ?: it.hashCode().toString() }) { account ->
                AccountRow(
                    account = account,
                    onSelect = onSelect,
                    onOpenCampaigns = onOpenCampaigns,
                    onOpenBilling = onOpenBilling,
                    onOpenAnalytics = onOpenAnalytics,
                )
            }
            item {
                TextButton(
                    onClick = onCreateAccount,
                    modifier = Modifier.fillMaxWidth().testTag(AdsAccountsTestTags.CREATE),
                ) { Text("Create another ad account") }
            }
        }
    }
}

@Composable
private fun AccountRow(
    account: AdAccountSummary,
    onSelect: (String) -> Unit,
    onOpenCampaigns: (String) -> Unit,
    onOpenBilling: (String) -> Unit,
    onOpenAnalytics: (String) -> Unit,
) {
    val id = account.accountId ?: return
    Card(modifier = Modifier.fillMaxWidth().testTag(AdsAccountsTestTags.row(id))) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = account.companyName ?: id,
                    style = MaterialTheme.typography.titleMedium,
                )
                account.status?.takeIf { it.isNotBlank() }?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Text(
                text = "Balance: " + formatCents(account.balanceCents) +
                    "  ·  Spent: " + formatCents(account.lifetimeSpendCents),
                style = MaterialTheme.typography.bodyMedium,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = { onSelect(id); onOpenCampaigns(id) },
                    modifier = Modifier.weight(1f),
                ) { Text("Campaigns") }
                OutlinedButton(
                    onClick = { onSelect(id); onOpenBilling(id) },
                    modifier = Modifier.weight(1f),
                ) { Text("Fund") }
                OutlinedButton(
                    onClick = { onSelect(id); onOpenAnalytics(id) },
                    modifier = Modifier.weight(1f),
                ) { Text("Stats") }
            }
        }
    }
}
