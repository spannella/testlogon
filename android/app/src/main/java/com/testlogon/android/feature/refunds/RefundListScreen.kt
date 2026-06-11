@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.refunds

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.refunds.RefundRequest

/** AND-244 — stable testTags for the refund-requests list screen. */
object RefundListTestTags {
    const val SCREEN = "refunds_screen"
    const val LIST = "refunds_list"
    const val EMPTY = "refunds_empty"
    const val ERROR = "refunds_error"
    const val ROW = "refund_row"
    const val STALE = "refunds_stale"
}

/** AND-244 — route-level refund-requests list, reachable from billing / the More hub. */
@Composable
fun RefundListRoute(
    onRefundClick: (refundId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: RefundListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    RefundListScreen(
        state = state,
        onRefundClick = onRefundClick,
        onRefresh = viewModel::refresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun RefundListScreen(
    state: RefundListUiState,
    onRefundClick: (String) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(RefundListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.refunds_title)) },
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
                state.isLoading && state.refunds.isEmpty() ->
                    LoadingState(message = stringResource(R.string.refunds_loading))

                state.error != null && state.refunds.isEmpty() ->
                    ErrorState(
                        message = state.error.asString(),
                        onRetry = onRefresh,
                        modifier = Modifier.testTag(RefundListTestTags.ERROR),
                    )

                state.refunds.isEmpty() ->
                    EmptyState(
                        title = stringResource(R.string.refunds_empty),
                        modifier = Modifier.testTag(RefundListTestTags.EMPTY),
                    )

                else -> RefundList(state = state, onRefresh = onRefresh, onRefundClick = onRefundClick)
            }
        }
    }
}

@Composable
private fun RefundList(
    state: RefundListUiState,
    onRefresh: () -> Unit,
    onRefundClick: (String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        Column(Modifier.fillMaxSize()) {
            if (state.isStale) {
                OfflineBanner(
                    message = stringResource(R.string.refunds_stale_banner),
                    onRetry = onRefresh,
                    modifier = Modifier.testTag(RefundListTestTags.STALE),
                )
            }
            LazyColumn(modifier = Modifier.fillMaxSize().testTag(RefundListTestTags.LIST)) {
                items(items = state.refunds, key = { it.id }) { refund ->
                    RefundRow(refund = refund, onClick = { onRefundClick(refund.id) })
                }
            }
        }
    }
}

@Composable
private fun RefundRow(refund: RefundRequest, onClick: () -> Unit) {
    val dateText = formatRefundDate(refund.createdAtEpochSeconds)
        ?: stringResource(R.string.refunds_date_unknown)
    val amountText = formatRefundMoney(refund.amount)
    val statusText = stringResource(refundStatusLabelRes(refund.status))
    val cd = "$amountText, $statusText, $dateText"
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(RefundListTestTags.ROW)
            .clearAndSetSemantics { contentDescription = cd },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(text = amountText, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = "$dateText · ${refund.reason}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        AssistChip(
            onClick = onClick,
            label = { Text(statusText) },
            modifier = Modifier.padding(start = 8.dp),
        )
    }
}
