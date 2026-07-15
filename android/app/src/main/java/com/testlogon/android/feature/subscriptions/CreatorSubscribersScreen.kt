@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.subscriptions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.subscriptions.CreatorSubscriberRow
import com.testlogon.android.data.subscriptions.SubscriptionAnalytics

/** SUB-E4-3 — stable test tags for the creator subscribers + MRR screen. */
object CreatorSubscribersTestTags {
    const val SCREEN = "creator_subs_screen"
    const val DASHBOARD = "creator_subs_dashboard"
    const val LIST = "creator_subs_list"
    const val EMPTY = "creator_subs_empty"
    const val ERROR = "creator_subs_error"
    const val LOAD_MORE = "creator_subs_load_more"
    const val CONFIRM_DIALOG = "creator_subs_confirm_dialog"
    fun row(id: String) = "creator_subs_row_$id"
    fun stopRenewal(id: String) = "creator_subs_stop_$id"
    fun refund(id: String) = "creator_subs_refund_$id"
    fun remove(id: String) = "creator_subs_remove_$id"
    fun filter(name: String) = "creator_subs_filter_$name"
}

/** SUB-E4-3 — creator "Subscribers" + MRR/analytics dashboard route (arg-less; owner-scoped in VM). */
@Composable
fun CreatorSubscribersRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CreatorSubscribersViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    val actionError = (state as? CreatorSubscribersUiState.Content)?.actionError
    LaunchedEffect(actionError) {
        val text = actionError?.resolve(context.resources) ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(text)
        viewModel.onActionErrorConsumed()
    }

    Scaffold(
        modifier = modifier.testTag(CreatorSubscribersTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.creator_subs_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when (val s = state) {
            is CreatorSubscribersUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding).fillMaxSize())

            is CreatorSubscribersUiState.Error ->
                ErrorState(
                    message = s.message.asString(),
                    onRetry = viewModel::onRetry,
                    modifier = Modifier.padding(padding).fillMaxSize().testTag(CreatorSubscribersTestTags.ERROR),
                )

            is CreatorSubscribersUiState.Content -> CreatorSubscribersContent(
                state = s,
                padding = padding,
                onFilterSelected = viewModel::onFilterSelected,
                onTierFilterSelected = viewModel::onTierFilterSelected,
                onLoadMore = viewModel::onLoadMore,
                onStopRenewal = viewModel::onStopRenewalClicked,
                onRemove = viewModel::onRemoveClicked,
                onRefund = viewModel::onRefundClicked,
            )
        }
    }

    val pending = (state as? CreatorSubscribersUiState.Content)?.pendingAction
    if (pending != null) {
        val name = pending.row.displayName
        val titleRes = when (pending.kind) {
            SubscriberActionKind.REMOVE -> R.string.creator_subs_confirm_remove_title
            SubscriberActionKind.REFUND -> R.string.creator_subs_confirm_refund_title
            SubscriberActionKind.STOP_RENEWAL -> R.string.creator_subs_confirm_stop_title
        }
        val bodyRes = when (pending.kind) {
            SubscriberActionKind.REMOVE -> R.string.creator_subs_confirm_remove_body
            SubscriberActionKind.REFUND -> R.string.creator_subs_confirm_refund_body
            SubscriberActionKind.STOP_RENEWAL -> R.string.creator_subs_confirm_stop_body
        }
        AlertDialog(
            onDismissRequest = viewModel::onActionDismissed,
            modifier = Modifier.testTag(CreatorSubscribersTestTags.CONFIRM_DIALOG),
            title = { Text(stringResource(titleRes)) },
            text = { Text(stringResource(bodyRes, name)) },
            confirmButton = {
                TextButton(onClick = viewModel::onActionConfirmed) {
                    Text(stringResource(R.string.creator_subs_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = viewModel::onActionDismissed) {
                    Text(stringResource(R.string.creator_subs_dismiss))
                }
            },
        )
    }
}

@Composable
private fun CreatorSubscribersContent(
    state: CreatorSubscribersUiState.Content,
    padding: PaddingValues,
    onFilterSelected: (SubscriberFilter) -> Unit,
    onTierFilterSelected: (String?) -> Unit,
    onLoadMore: () -> Unit,
    onStopRenewal: (CreatorSubscriberRow) -> Unit,
    onRemove: (CreatorSubscriberRow) -> Unit,
    onRefund: (CreatorSubscriberRow) -> Unit,
) {
    val tiers = state.analytics?.byTier.orEmpty()
    LazyColumn(
        modifier = Modifier.padding(padding).fillMaxSize().testTag(CreatorSubscribersTestTags.LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "dashboard") {
            AnalyticsDashboard(state.analytics)
        }
        if (tiers.isNotEmpty()) {
            item(key = "by_tier") {
                TierBreakdownSection(tiers = tiers, currency = state.analytics?.currency?.uppercase() ?: "USD")
            }
            item(key = "tier_filters") {
                TierFilterRow(tiers = tiers, selected = state.planFilter, onTierFilterSelected = onTierFilterSelected)
            }
        }
        item(key = "filters") {
            FilterChipRow(selected = state.filter, onFilterSelected = onFilterSelected)
        }

        if (state.loadingList) {
            item(key = "list_loading") {
                Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            }
        } else if (state.subscribers.isEmpty()) {
            item(key = "empty") {
                EmptyState(
                    title = stringResource(R.string.creator_subs_empty_title),
                    body = stringResource(R.string.creator_subs_empty_body),
                    modifier = Modifier.fillMaxWidth().testTag(CreatorSubscribersTestTags.EMPTY),
                )
            }
        } else {
            items(items = state.subscribers, key = { it.subscriptionId }) { row ->
                SubscriberRowCard(
                    row = row,
                    busy = state.actioningId == row.subscriptionId,
                    disabled = state.actioningId != null && state.actioningId != row.subscriptionId,
                    onStopRenewal = { onStopRenewal(row) },
                    onRemove = { onRemove(row) },
                    onRefund = { onRefund(row) },
                )
            }
            if (state.nextCursor != null) {
                item(key = "load_more") {
                    Box(Modifier.fillMaxWidth().padding(top = 4.dp), contentAlignment = Alignment.Center) {
                        if (state.loadingMore) {
                            CircularProgressIndicator()
                        } else {
                            OutlinedButton(
                                onClick = onLoadMore,
                                modifier = Modifier.testTag(CreatorSubscribersTestTags.LOAD_MORE),
                            ) { Text(stringResource(R.string.creator_subs_load_more)) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AnalyticsDashboard(analytics: SubscriptionAnalytics?) {
    Column(
        modifier = Modifier.testTag(CreatorSubscribersTestTags.DASHBOARD),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            stringResource(R.string.creator_subs_dashboard_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        if (analytics == null) {
            Text(
                stringResource(R.string.creator_subs_analytics_unavailable),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            return@Column
        }
        val currency = analytics.currency?.uppercase() ?: "USD"
        val free = stringResource(R.string.creator_subs_zero_money)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            StatTile(stringResource(R.string.creator_subs_stat_active), analytics.activeSubscribers.toString())
            StatTile(
                stringResource(R.string.creator_subs_stat_mrr),
                formatTierPrice(analytics.mrrCents, currency, free),
            )
            StatTile(stringResource(R.string.creator_subs_stat_trialing), analytics.trialing.toString())
            StatTile(stringResource(R.string.creator_subs_stat_past_due), analytics.pastDue.toString())
            StatTile(stringResource(R.string.creator_subs_stat_new), analytics.newSubs30d.toString())
            StatTile(stringResource(R.string.creator_subs_stat_churned), analytics.churned30d.toString())
            StatTile(
                stringResource(R.string.creator_subs_stat_arpu),
                formatTierPrice(analytics.arpuCents, currency, free),
            )
            StatTile(
                stringResource(R.string.creator_subs_stat_churn_rate),
                "${(analytics.churnRate * 100).toInt()}%",
            )
            if (analytics.pastDueMrrCents > 0) {
                StatTile(
                    stringResource(R.string.creator_subs_stat_past_due_mrr),
                    formatTierPrice(analytics.pastDueMrrCents, currency, free),
                )
            }
        }
        // SUBX-43 (C9): explicit window labels (lifetime revenue vs 30-day churn window).
        Text(
            stringResource(
                R.string.creator_subs_net_revenue,
                formatTierPrice(analytics.netRevenueToDateCents, currency, free),
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (analytics.refundedToDateCents > 0) {
            Text(
                stringResource(
                    R.string.creator_subs_refunded_to_date,
                    formatTierPrice(analytics.refundedToDateCents, currency, free),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(
            stringResource(R.string.creator_subs_window_note, analytics.periodDays),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** SUBX-43 (C8) — per-tier revenue/subscriber breakdown, reconciling to the creator-wide totals. */
@Composable
private fun TierBreakdownSection(
    tiers: List<com.testlogon.android.data.subscriptions.TierRevenue>,
    currency: String,
) {
    val free = stringResource(R.string.creator_subs_zero_money)
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            stringResource(R.string.creator_subs_by_tier_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        tiers.forEach { tier ->
            Card(
                modifier = Modifier.fillMaxWidth().testTag("creator_subs_tier_${tier.planId ?: "none"}"),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        tier.planName ?: stringResource(R.string.creator_subs_tier_unknown),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        stringResource(R.string.creator_subs_tier_active, tier.activeSubscribers) +
                            "  •  " +
                            stringResource(
                                R.string.creator_subs_tier_mrr,
                                formatTierPrice(tier.mrrCents, currency, free),
                            ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        stringResource(
                            R.string.creator_subs_tier_net,
                            formatTierPrice(tier.netRevenueToDateCents, currency, free),
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

/** SUBX-43 (C6) — per-tier filter chips (All + one per tier) for the subscriber list. */
@Composable
private fun TierFilterRow(
    tiers: List<com.testlogon.android.data.subscriptions.TierRevenue>,
    selected: String?,
    onTierFilterSelected: (String?) -> Unit,
) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(
            selected = selected == null,
            onClick = { onTierFilterSelected(null) },
            label = { Text(stringResource(R.string.creator_subs_tier_filter_all)) },
        )
        tiers.filter { it.planId != null }.forEach { tier ->
            FilterChip(
                selected = selected == tier.planId,
                onClick = { onTierFilterSelected(tier.planId) },
                label = {
                    Text(
                        tier.planName ?: stringResource(R.string.creator_subs_tier_unknown),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                modifier = Modifier.testTag("creator_subs_tier_filter_${tier.planId}"),
            )
        }
    }
}

@Composable
private fun StatTile(label: String, value: String) {
    Card(
        modifier = Modifier.width(108.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                value,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
            )
        }
    }
}

@Composable
private fun FilterChipRow(selected: SubscriberFilter, onFilterSelected: (SubscriberFilter) -> Unit) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SubscriberFilter.values().forEach { filter ->
            FilterChip(
                selected = selected == filter,
                onClick = { onFilterSelected(filter) },
                label = { Text(stringResource(filterLabelRes(filter))) },
                modifier = Modifier.testTag(CreatorSubscribersTestTags.filter(filter.name)),
            )
        }
    }
}

@Composable
private fun SubscriberRowCard(
    row: CreatorSubscriberRow,
    busy: Boolean,
    disabled: Boolean,
    onStopRenewal: () -> Unit,
    onRemove: () -> Unit,
    onRefund: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(CreatorSubscribersTestTags.row(row.subscriptionId))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    row.displayName,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                StatusBadge(row.rawStatus)
            }
            Text(
                row.planName ?: stringResource(R.string.creator_subs_tier_unknown),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                if (row.isTrial) MiniBadge(stringResource(R.string.creator_subs_trial_badge))
                if (row.isGift) MiniBadge(stringResource(R.string.creator_subs_gift_badge))
            }
            val since = formatEpochDate(row.sinceEpochSeconds) ?: stringResource(R.string.creator_subs_no_date)
            Text(
                stringResource(R.string.creator_subs_since, since),
                style = MaterialTheme.typography.bodySmall,
            )
            val nextRaw = row.nextBillingDateEpochSeconds ?: row.currentPeriodEndEpochSeconds
            val next = formatEpochDate(nextRaw) ?: stringResource(R.string.creator_subs_no_date)
            Text(
                stringResource(R.string.creator_subs_next_billing, next),
                style = MaterialTheme.typography.bodySmall,
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (busy) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                } else {
                    OutlinedButton(
                        onClick = onStopRenewal,
                        enabled = !disabled,
                        modifier = Modifier.testTag(CreatorSubscribersTestTags.stopRenewal(row.subscriptionId)),
                    ) { Text(stringResource(R.string.creator_subs_action_stop_renewal)) }
                    OutlinedButton(
                        onClick = onRefund,
                        enabled = !disabled,
                        modifier = Modifier.testTag(CreatorSubscribersTestTags.refund(row.subscriptionId)),
                    ) { Text(stringResource(R.string.creator_subs_action_refund)) }
                    OutlinedButton(
                        onClick = onRemove,
                        enabled = !disabled,
                        modifier = Modifier.testTag(CreatorSubscribersTestTags.remove(row.subscriptionId)),
                    ) { Text(stringResource(R.string.creator_subs_action_remove)) }
                }
            }
        }
    }
}

@Composable
private fun StatusBadge(rawStatus: String) {
    val scheme = MaterialTheme.colorScheme
    val (labelRes, container, content) = when (rawStatus.lowercase()) {
        "active" -> Triple(R.string.manage_sub_status_active, scheme.primaryContainer, scheme.onPrimaryContainer)
        "trialing", "trial" -> Triple(R.string.manage_sub_status_trialing, scheme.tertiaryContainer, scheme.onTertiaryContainer)
        "past_due" -> Triple(R.string.manage_sub_status_past_due, scheme.errorContainer, scheme.onErrorContainer)
        "grace" -> Triple(R.string.creator_subs_status_grace, scheme.errorContainer, scheme.onErrorContainer)
        "canceling", "cancelling" -> Triple(R.string.creator_subs_status_canceling, scheme.surfaceVariant, scheme.onSurfaceVariant)
        "canceled", "cancelled" -> Triple(R.string.manage_sub_status_canceled, scheme.surfaceVariant, scheme.onSurfaceVariant)
        "expired" -> Triple(R.string.manage_sub_status_expired, scheme.surfaceVariant, scheme.onSurfaceVariant)
        else -> Triple(R.string.manage_sub_status_unknown, scheme.surfaceVariant, scheme.onSurfaceVariant)
    }
    Badge(text = stringResource(labelRes), container = container, content = content)
}

@Composable
private fun MiniBadge(text: String) {
    Badge(
        text = text,
        container = MaterialTheme.colorScheme.secondaryContainer,
        content = MaterialTheme.colorScheme.onSecondaryContainer,
    )
}

@Composable
private fun Badge(text: String, container: Color, content: Color) {
    Surface(color = container, contentColor = content, shape = RoundedCornerShape(8.dp)) {
        Text(
            text,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
        )
    }
}

private fun filterLabelRes(filter: SubscriberFilter): Int = when (filter) {
    SubscriberFilter.ALL -> R.string.creator_subs_filter_all
    SubscriberFilter.ACTIVE -> R.string.creator_subs_filter_active
    SubscriberFilter.TRIALING -> R.string.creator_subs_filter_trialing
    SubscriberFilter.PAST_DUE -> R.string.creator_subs_filter_past_due
    SubscriberFilter.CANCELED -> R.string.creator_subs_filter_canceled
}
