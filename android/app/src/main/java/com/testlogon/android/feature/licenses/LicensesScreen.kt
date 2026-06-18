@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.licenses

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material.icons.outlined.Copyright
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.licenses.IssuedLicense
import com.testlogon.android.data.licenses.LicenseRequest
import com.testlogon.android.data.licenses.RevenueSummary
import com.testlogon.android.data.licenses.RevenueTransaction
import com.testlogon.android.data.referrals.DEFAULT_CURRENCY_USD
import com.testlogon.android.feature.earnings.formatEarningsMoney

/** Stable testTags for the licensing hub. */
object LicensesTestTags {
    const val SCREEN = "licenses_screen"
    const val TABS = "licenses_tabs"
    const val LIST = "licenses_list"
    const val LOADING = "licenses_loading"
    const val EMPTY = "licenses_empty"
    const val ERROR = "licenses_error"
    const val OFFLINE = "licenses_offline"
    const val SESSION_EXPIRED = "licenses_session_expired"
    const val TAB_PREFIX = "licenses_tab_"
    const val ROW_PREFIX = "licenses_row_"
    const val REVENUE_SUMMARY = "licenses_revenue_summary"
}

/** Route-level licensing-hub entry (reachable from the More hub). Mirrors the web /licenses routes. */
@Composable
fun LicensesRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: LicensesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is LicensesEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    LaunchedEffect(state.phase) {
        if (state.phase == LicensesUiState.Phase.SessionExpired) onSessionExpired()
    }

    LicensesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onSelectTab = viewModel::onSelectTab,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun LicensesScreen(
    state: LicensesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelectTab: (LicensesTab) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(LicensesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.licenses_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("licenses_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            LicensesTabs(selected = state.tab, onSelectTab = onSelectTab)
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    LicensesUiState.Phase.Loading ->
                        LoadingState(modifier = Modifier.testTag(LicensesTestTags.LOADING))

                    LicensesUiState.Phase.Error ->
                        ErrorState(
                            message = state.errorMessage
                                ?: stringResource(R.string.licenses_error_generic),
                            onRetry = onRetry,
                            modifier = Modifier.testTag(LicensesTestTags.ERROR),
                        )

                    LicensesUiState.Phase.Offline ->
                        ErrorState(
                            message = state.errorMessage
                                ?: stringResource(R.string.licenses_error_generic),
                            onRetry = onRetry,
                            modifier = Modifier.testTag(LicensesTestTags.OFFLINE),
                        )

                    LicensesUiState.Phase.SessionExpired ->
                        EmptyState(
                            title = stringResource(R.string.licenses_session_expired_title),
                            body = stringResource(R.string.licenses_session_expired_body),
                            modifier = Modifier.testTag(LicensesTestTags.SESSION_EXPIRED),
                        )

                    LicensesUiState.Phase.Empty ->
                        PullToRefreshBox(
                            isRefreshing = state.isRefreshing,
                            onRefresh = onRefresh,
                            modifier = Modifier.fillMaxSize(),
                        ) {
                            EmptyState(
                                title = emptyTitle(state.tab),
                                body = emptyBody(state.tab),
                                imageVector = Icons.Outlined.Copyright,
                                modifier = Modifier.testTag(LicensesTestTags.EMPTY),
                            )
                        }

                    LicensesUiState.Phase.Content ->
                        PullToRefreshBox(
                            isRefreshing = state.isRefreshing,
                            onRefresh = onRefresh,
                            modifier = Modifier.fillMaxSize(),
                        ) {
                            LicensesContent(state = state, onRetry = onRetry)
                        }
                }
            }
        }
    }
}

@Composable
private fun LicensesTabs(selected: LicensesTab, onSelectTab: (LicensesTab) -> Unit) {
    val tabs = LicensesTab.entries
    SingleChoiceSegmentedButtonRow(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(LicensesTestTags.TABS),
    ) {
        tabs.forEachIndexed { index, tab ->
            SegmentedButton(
                selected = tab == selected,
                onClick = { onSelectTab(tab) },
                shape = SegmentedButtonDefaults.itemShape(index = index, count = tabs.size),
                modifier = Modifier.testTag(LicensesTestTags.TAB_PREFIX + tab.name.lowercase()),
            ) {
                Text(stringResource(tabLabel(tab)))
            }
        }
    }
}

@Composable
private fun LicensesContent(state: LicensesUiState, onRetry: () -> Unit) {
    LazyColumn(
        modifier = Modifier
            .testTag(LicensesTestTags.LIST)
            .fillMaxSize(),
        contentPadding = PaddingValues(vertical = 8.dp),
    ) {
        if (state.isStale) {
            item { OfflineBanner(onRetry = onRetry) }
        }
        when (state.tab) {
            LicensesTab.ISSUED -> {
                val items = state.issued?.items.orEmpty()
                items(items, key = { it.id }) { license ->
                    IssuedLicenseRow(license)
                    HorizontalDivider()
                }
            }

            LicensesTab.REQUESTS -> {
                val items = state.requests?.items.orEmpty()
                items(items, key = { it.id }) { request ->
                    LicenseRequestRow(request)
                    HorizontalDivider()
                }
            }

            LicensesTab.REVENUE -> {
                state.revenue?.summary?.let { summary ->
                    item { RevenueSummaryCard(summary) }
                }
                val txns = state.revenue?.transactions.orEmpty()
                items(txns, key = { it.id }) { txn ->
                    RevenueTransactionRow(txn)
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun IssuedLicenseRow(license: IssuedLicense) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(LicensesTestTags.ROW_PREFIX + license.id)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = license.contentId,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
            )
            AssistChip(onClick = {}, label = { Text(license.statusLabel()) })
        }
        val meta = listOf(license.modeLabel(), license.formattedCreated())
            .filter { it.isNotBlank() }
            .joinToString("   -   ")
        if (meta.isNotBlank()) {
            Text(
                text = meta,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun LicenseRequestRow(request: LicenseRequest) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(LicensesTestTags.ROW_PREFIX + request.id)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = request.ownerDisplayName.ifBlank { request.contentId },
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
            )
            AssistChip(onClick = {}, label = { Text(request.statusLabel()) })
        }
        request.terms?.let { terms ->
            Text(
                text = stringResource(
                    R.string.licenses_request_terms,
                    formatEarningsMoney(terms.fixedCostCents, DEFAULT_CURRENCY_USD),
                    terms.revenueSharePct,
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
        val meta = listOf(request.contentType, request.formattedCreated())
            .filter { it.isNotBlank() }
            .joinToString("   -   ")
        if (meta.isNotBlank()) {
            Text(
                text = meta,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (request.denialReason.isNotBlank()) {
            Text(
                text = stringResource(R.string.licenses_request_denied_reason, request.denialReason),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}

@Composable
private fun RevenueSummaryCard(summary: RevenueSummary) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(LicensesTestTags.REVENUE_SUMMARY),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = stringResource(R.string.licenses_revenue_total_label),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = formatEarningsMoney(summary.totalCents, summary.currency),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = stringResource(
                    R.string.licenses_revenue_transactions_count,
                    summary.totalTransactions,
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun RevenueTransactionRow(txn: RevenueTransaction) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(LicensesTestTags.ROW_PREFIX + txn.id)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = txn.sourceLabel().ifBlank { stringResource(R.string.licenses_revenue_source_fallback) },
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            val meta = listOf(txn.contentId, txn.formattedCreated())
                .filter { it.isNotBlank() }
                .joinToString("   -   ")
            if (meta.isNotBlank()) {
                Text(
                    text = meta,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Text(
            text = formatEarningsMoney(txn.splitAmountCents, txn.currency),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

private fun tabLabel(tab: LicensesTab): Int = when (tab) {
    LicensesTab.ISSUED -> R.string.licenses_tab_issued
    LicensesTab.REQUESTS -> R.string.licenses_tab_requests
    LicensesTab.REVENUE -> R.string.licenses_tab_revenue
}

@Composable
private fun emptyTitle(tab: LicensesTab): String = stringResource(
    when (tab) {
        LicensesTab.ISSUED -> R.string.licenses_issued_empty_title
        LicensesTab.REQUESTS -> R.string.licenses_requests_empty_title
        LicensesTab.REVENUE -> R.string.licenses_revenue_empty_title
    },
)

@Composable
private fun emptyBody(tab: LicensesTab): String = stringResource(
    when (tab) {
        LicensesTab.ISSUED -> R.string.licenses_issued_empty_body
        LicensesTab.REQUESTS -> R.string.licenses_requests_empty_body
        LicensesTab.REVENUE -> R.string.licenses_revenue_empty_body
    },
)
