@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.payouts

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.payouts.Payout

/** AND-260 — stable testTags for the payout history screen. */
object PayoutHistoryTestTags {
    const val SCREEN = "payout_history_screen"
    const val LIST = "payout_history_list"
    const val EMPTY = "payout_history_empty"
    const val ERROR = "payout_history_error"
    const val ROW = "payout_row"
    const val APPEND_FOOTER = "payout_history_append_footer"
    const val APPEND_RETRY = "payout_history_append_retry"
}

/** AND-260 — route-level payout history entry, reachable from earnings / billing / the More hub. */
@Composable
fun PayoutHistoryRoute(
    onPayoutClick: (payoutId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PayoutHistoryViewModel = hiltViewModel(),
) {
    val payouts = viewModel.payouts.collectAsLazyPagingItems()
    PayoutHistoryScreen(
        payouts = payouts,
        onPayoutClick = onPayoutClick,
        onRefresh = { viewModel.refresh() },
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun PayoutHistoryScreen(
    payouts: LazyPagingItems<Payout>,
    onPayoutClick: (String) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(PayoutHistoryTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.payout_history_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("payout_history_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        val refreshState = payouts.loadState.refresh
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                refreshState is LoadState.Loading && payouts.itemCount == 0 ->
                    LoadingState(message = stringResource(R.string.payout_history_loading))

                refreshState is LoadState.Error && payouts.itemCount == 0 -> {
                    val message = (refreshState.error as? PayoutsLoadException)?.message
                        ?: stringResource(R.string.payout_history_error_generic)
                    ErrorState(
                        message = message,
                        onRetry = payouts::retry,
                        modifier = Modifier.testTag(PayoutHistoryTestTags.ERROR),
                    )
                }

                refreshState is LoadState.NotLoading && payouts.itemCount == 0 ->
                    EmptyState(
                        title = stringResource(R.string.payout_history_empty),
                        modifier = Modifier.testTag(PayoutHistoryTestTags.EMPTY),
                    )

                else -> PayoutsList(payouts = payouts, onRefresh = onRefresh, onPayoutClick = onPayoutClick)
            }
        }
    }
}

@Composable
private fun PayoutsList(
    payouts: LazyPagingItems<Payout>,
    onRefresh: () -> Unit,
    onPayoutClick: (String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = payouts.loadState.refresh is LoadState.Loading && payouts.itemCount > 0,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(modifier = Modifier.fillMaxSize().testTag(PayoutHistoryTestTags.LIST)) {
            items(
                count = payouts.itemCount,
                key = { index -> payouts.peek(index)?.payoutId ?: index },
            ) { index ->
                val payout = payouts[index]
                if (payout != null) {
                    PayoutRow(payout = payout, onClick = { onPayoutClick(payout.payoutId) })
                }
            }

            when (payouts.loadState.append) {
                is LoadState.Loading -> item {
                    Box(
                        Modifier.fillMaxWidth().padding(16.dp).testTag(PayoutHistoryTestTags.APPEND_FOOTER),
                        contentAlignment = Alignment.Center,
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    }
                }
                is LoadState.Error -> item {
                    Row(
                        Modifier.fillMaxWidth().padding(16.dp).testTag(PayoutHistoryTestTags.APPEND_FOOTER),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            stringResource(R.string.payout_history_append_error),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        TextButton(
                            onClick = payouts::retry,
                            modifier = Modifier.testTag(PayoutHistoryTestTags.APPEND_RETRY),
                        ) { Text(stringResource(R.string.action_retry)) }
                    }
                }
                else -> Unit
            }
        }
    }
}

@Composable
private fun PayoutRow(payout: Payout, onClick: () -> Unit) {
    val dateText = formatPayoutDate(payout.displayEpochSeconds)
        ?: stringResource(R.string.payout_date_unknown)
    val amountText = formatPayoutMoney(payout.amount)
    val methodText = stringResource(payoutMethodLabelRes(payout.method))
    val statusText = stringResource(payoutStatusLabelRes(payout.status))
    val cd = buildString {
        append(amountText)
        append(", "); append(methodText)
        append(", "); append(dateText)
        append(", "); append(stringResource(R.string.payout_status_cd, statusText))
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(PayoutHistoryTestTags.ROW)
            .clearAndSetSemantics { contentDescription = cd },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = amountText,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "$dateText · $methodText",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        PayoutStatusChip(status = payout.status)
    }
}
