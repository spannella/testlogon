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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
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
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.payouts.PayoutBatch

/** AND-261 — stable testTags for the bulk-payout batch list screen. */
object BulkPayoutsListTestTags {
    const val SCREEN = "bulk_payouts_list_screen"
    const val LIST = "bulk_payouts_list"
    const val EMPTY = "bulk_payouts_empty"
    const val ERROR = "bulk_payouts_error"
    const val ROW = "bulk_batch_row"
    const val STALE = "bulk_payouts_stale"
}

/** AND-261 — route-level bulk batch list entry (reached from the More hub / payouts area). */
@Composable
fun BulkPayoutsListRoute(
    onBatchClick: (batchId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: BulkPayoutsListViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    BulkPayoutsListScreen(
        state = state,
        onBatchClick = onBatchClick,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun BulkPayoutsListScreen(
    state: BulkListUiState,
    onBatchClick: (String) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(BulkPayoutsListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.bulk_payouts_title)) },
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
            when (state) {
                is BulkListUiState.Loading ->
                    LoadingState(message = stringResource(R.string.bulk_payouts_loading))

                is BulkListUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.bulk_payouts_empty),
                        modifier = Modifier.testTag(BulkPayoutsListTestTags.EMPTY),
                    )

                is BulkListUiState.Error ->
                    ErrorState(
                        message = state.message.asString(),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(BulkPayoutsListTestTags.ERROR),
                    )

                is BulkListUiState.Content ->
                    Column(Modifier.fillMaxSize()) {
                        StaleBanner(
                            stale = state.stale,
                            refreshing = false,
                            onRetry = onRetry,
                            modifier = Modifier.testTag(BulkPayoutsListTestTags.STALE),
                        )
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().testTag(BulkPayoutsListTestTags.LIST),
                        ) {
                            items(items = state.batches, key = { it.id }) { batch ->
                                BatchRow(batch = batch, onClick = { onBatchClick(batch.id) })
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun BatchRow(batch: PayoutBatch, onClick: () -> Unit) {
    val amountText = formatPayoutMoney(batch.total)
    val dateText = formatPayoutDate(batch.createdAtEpochSeconds)
        ?: stringResource(R.string.payout_date_unknown)
    val countText = stringResource(R.string.bulk_batch_item_count, batch.itemCount)
    val statusText = stringResource(payoutBatchStatusLabelRes(batch.status))
    val cd = buildString {
        append(batch.id); append(", "); append(batch.kind)
        append(", "); append(amountText)
        append(", "); append(countText)
        append(", "); append(stringResource(R.string.payout_status_cd, statusText))
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(BulkPayoutsListTestTags.ROW)
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
                text = "${batch.kind} · $countText · $dateText",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        PayoutBatchStatusChip(status = batch.status)
    }
}
