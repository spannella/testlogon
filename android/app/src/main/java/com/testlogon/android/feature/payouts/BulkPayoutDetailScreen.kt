@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.payouts

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
import androidx.compose.material3.HorizontalDivider
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
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.payouts.PayoutBatch
import com.testlogon.android.data.payouts.PayoutBatchItem

/** AND-261 — stable testTags for the bulk-payout batch detail screen. */
object BulkPayoutDetailTestTags {
    const val SCREEN = "bulk_payout_detail_screen"
    const val LIST = "bulk_payout_detail_list"
    const val ERROR = "bulk_payout_detail_error"
    const val HEADER = "bulk_payout_detail_header"
    const val ITEM_ROW = "bulk_batch_item_row"
}

/** AND-261 — route-level bulk batch detail entry (cache-free; single GET with embedded items). */
@Composable
fun BulkPayoutDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: BulkPayoutDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    BulkPayoutDetailScreen(
        state = state,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun BulkPayoutDetailScreen(
    state: BulkBatchDetailUiState,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(BulkPayoutDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.bulk_payout_detail_title)) },
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
                is BulkBatchDetailUiState.Loading ->
                    LoadingState(message = stringResource(R.string.bulk_payouts_loading))

                is BulkBatchDetailUiState.Error ->
                    ErrorState(
                        message = state.message.asString(),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(BulkPayoutDetailTestTags.ERROR),
                    )

                is BulkBatchDetailUiState.Content ->
                    LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(BulkPayoutDetailTestTags.LIST),
                    ) {
                        item { BatchHeader(state.batch) }
                        item { HorizontalDivider() }
                        items(items = state.batch.items, key = { it.refId }) { item ->
                            BatchItemRow(item)
                        }
                    }
            }
        }
    }
}

@Composable
private fun BatchHeader(batch: PayoutBatch) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
            .testTag(BulkPayoutDetailTestTags.HEADER),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = formatPayoutMoney(batch.total),
            style = MaterialTheme.typography.headlineSmall,
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(text = batch.kind, style = MaterialTheme.typography.bodyMedium)
            PayoutBatchStatusChip(status = batch.status, modifier = Modifier.padding(start = 8.dp))
        }
        Text(
            text = stringResource(R.string.bulk_batch_item_count, batch.itemCount),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = stringResource(R.string.bulk_batch_rollup, batch.successCount, batch.failureCount),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        formatPayoutDate(batch.createdAtEpochSeconds)?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun BatchItemRow(item: PayoutBatchItem) {
    val amountText = formatPayoutMoney(item.amount)
    val statusText = stringResource(payoutStatusLabelRes(item.status))
    val cd = buildString {
        append(item.recipient.ifBlank { item.refId })
        append(", "); append(amountText)
        append(", "); append(stringResource(R.string.payout_status_cd, statusText))
        if (item.reason.isNotBlank()) {
            append(", "); append(item.reason)
        }
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(BulkPayoutDetailTestTags.ITEM_ROW)
            .clearAndSetSemantics { contentDescription = cd },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = item.recipient.ifBlank { item.refId },
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = amountText,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (item.reason.isNotBlank()) {
                Text(
                    text = item.reason,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        PayoutStatusChip(status = item.status)
    }
}
