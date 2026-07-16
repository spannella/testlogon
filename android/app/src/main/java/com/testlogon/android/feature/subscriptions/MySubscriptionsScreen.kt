@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.subscriptions

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.subscriptions.SubscriptionState

/** SUBX-20 — stable test tags for the "My subscriptions" list screen. */
object MySubscriptionsTestTags {
    const val SCREEN = "my_subs_screen"
    const val LIST = "my_subs_list"
    const val EMPTY = "my_subs_empty"
    const val ERROR = "my_subs_error"
    fun row(id: String) = "my_subs_row_$id"
}

/**
 * SUBX-20 — the subscriber's "My subscriptions" list. Renders EVERY subscription the viewer holds
 * (active / trialing / past_due / canceled / expired) over the existing [MySubscriptionsViewModel],
 * and routes each row into the manage screen for THAT specific subscription (subscriptionId +
 * creatorId), so a multi-creator subscriber can view and manage all of them (fixes the old
 * single-sub, wrong-creator dead-end). PAST_DUE rows are flagged so the subscriber can jump straight
 * into dunning recovery.
 */
@Composable
fun MySubscriptionsRoute(
    onOpenManage: (subscriptionId: String, creatorId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MySubscriptionsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MySubscriptionsScreen(
        state = state,
        onOpenManage = onOpenManage,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun MySubscriptionsScreen(
    state: MySubscriptionsUiState,
    onOpenManage: (subscriptionId: String, creatorId: String) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(MySubscriptionsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.my_subs_title)) },
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
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoading -> LoadingState()
                state.error != null -> ErrorState(
                    message = state.error,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(MySubscriptionsTestTags.ERROR),
                )
                state.isEmpty -> EmptyState(
                    title = stringResource(R.string.my_subs_empty_title),
                    body = stringResource(R.string.my_subs_empty_body),
                    modifier = Modifier.testTag(MySubscriptionsTestTags.EMPTY),
                )
                else -> LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .testTag(MySubscriptionsTestTags.LIST),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(state.subscriptions, key = { it.subscriptionId }) { row ->
                        SubscriptionRow(row = row, onOpenManage = onOpenManage)
                    }
                }
            }
        }
    }
}

@Composable
private fun SubscriptionRow(
    row: MySubscriptionRow,
    onOpenManage: (subscriptionId: String, creatorId: String) -> Unit,
) {
    val freeLabel = stringResource(R.string.subs_tiers_free)
    val priceText = formatTierPrice(row.priceCents ?: 0L, row.currency ?: "USD", freeLabel)
    val intervalEnd = formatEpochDate(row.currentPeriodEndEpochSeconds)
    val statusLabel = stringResource(myStatusRes(row.status))
    Card(
        Modifier
            .fillMaxWidth()
            .clickable { onOpenManage(row.subscriptionId, row.creatorId) }
            .testTag(MySubscriptionsTestTags.row(row.subscriptionId)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(row.planId, style = MaterialTheme.typography.titleMedium)
                Text(priceText, style = MaterialTheme.typography.bodyMedium)
                if (intervalEnd != null) {
                    val label = if (row.cancelAtPeriodEnd) R.string.my_subs_ends_on else R.string.my_subs_renews_on
                    Text(
                        stringResource(label, intervalEnd),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (row.status == SubscriptionState.PAST_DUE) {
                    Surface(
                        color = MaterialTheme.colorScheme.errorContainer,
                        contentColor = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            stringResource(R.string.my_subs_past_due_banner),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        )
                    }
                }
                AssistChip(
                    onClick = { onOpenManage(row.subscriptionId, row.creatorId) },
                    label = { Text(statusLabel) },
                    trailingIcon = {
                        Icon(
                            Icons.AutoMirrored.Filled.KeyboardArrowRight,
                            contentDescription = null,
                        )
                    },
                )
            }
        }
    }
}

private fun myStatusRes(status: SubscriptionState): Int = when (status) {
    SubscriptionState.ACTIVE -> R.string.manage_sub_status_active
    SubscriptionState.TRIALING -> R.string.manage_sub_status_trialing
    SubscriptionState.PAST_DUE -> R.string.manage_sub_status_past_due
    SubscriptionState.CANCELED -> R.string.manage_sub_status_canceled
    SubscriptionState.EXPIRED -> R.string.manage_sub_status_expired
    SubscriptionState.UNKNOWN -> R.string.manage_sub_status_unknown
}
