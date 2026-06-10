@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.purchases

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.purchases.OrderStatus
import com.testlogon.android.data.purchases.PurchaseListItem

/** AND-219 — stable test tags for the purchase-history screen. */
object PurchaseHistoryTestTags {
    const val SCREEN = "purchase_history_screen"
    const val FIELD = "purchase_history_search_field"
    const val CLEAR = "purchase_history_search_clear"
    const val LIST = "purchase_history_list"
    const val ROW = "purchase_history_row"
    const val EMPTY_HISTORY = "purchase_history_empty"
    const val EMPTY_SEARCH = "purchase_history_empty_search"
    const val ERROR = "purchase_history_error"
}

/** Maps an [OrderStatus] to its localized label string resource. */
fun orderStatusLabelRes(status: OrderStatus): Int = when (status) {
    OrderStatus.Pending -> R.string.purchase_status_pending
    OrderStatus.Completed -> R.string.purchase_status_completed
    OrderStatus.Cancelled -> R.string.purchase_status_cancelled
    OrderStatus.Reverted -> R.string.purchase_status_reverted
    OrderStatus.CancelRequested -> R.string.purchase_status_cancel_requested
    OrderStatus.CancelDenied -> R.string.purchase_status_cancel_denied
    is OrderStatus.Unknown -> R.string.purchase_status_unknown
}

/**
 * AND-219 — purchase-history route. Collects the query + the debounced paged history/search results and
 * renders [PurchaseHistoryScreen]. Tapping a row opens the order detail with the txn id.
 */
@Composable
fun PurchaseHistoryRoute(
    onPurchaseClick: (txnId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PurchaseHistoryViewModel = hiltViewModel(),
) {
    val query by viewModel.query.collectAsStateWithLifecycle()
    val items = viewModel.items.collectAsLazyPagingItems()
    PurchaseHistoryScreen(
        query = query,
        items = items,
        onQueryChange = viewModel::onQueryChange,
        onClear = viewModel::onClear,
        onPurchaseClick = onPurchaseClick,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun PurchaseHistoryScreen(
    query: String,
    items: LazyPagingItems<PurchaseListItem>,
    onQueryChange: (String) -> Unit,
    onClear: () -> Unit,
    onPurchaseClick: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val refresh = items.loadState.refresh
    val phase = purchaseHistoryUiState(
        query = query,
        refreshLoading = refresh is LoadState.Loading,
        refreshError = refresh is LoadState.Error,
        errorMessage = (refresh as? LoadState.Error)?.let {
            (it.error as? PurchasesLoadException)?.message
        },
        retryable = true,
        itemCount = items.itemCount,
    )
    Scaffold(
        modifier = modifier.testTag(PurchaseHistoryTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.purchase_history_title)) },
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
        Column(Modifier.fillMaxSize().padding(padding)) {
            SearchField(query = query, onQueryChange = onQueryChange, onClear = onClear)
            Box(Modifier.fillMaxSize()) {
                when (phase) {
                    is PurchaseHistoryUiState.Loading -> LoadingState()

                    is PurchaseHistoryUiState.EmptyHistory ->
                        EmptyState(
                            title = stringResource(R.string.purchase_history_empty),
                            modifier = Modifier.testTag(PurchaseHistoryTestTags.EMPTY_HISTORY),
                        )

                    is PurchaseHistoryUiState.EmptySearch ->
                        EmptyState(
                            title = stringResource(R.string.purchase_history_empty_search, phase.query),
                            actionLabel = stringResource(R.string.purchase_history_clear_search),
                            onAction = onClear,
                            modifier = Modifier.testTag(PurchaseHistoryTestTags.EMPTY_SEARCH),
                        )

                    is PurchaseHistoryUiState.Error ->
                        ErrorState(
                            message = phase.message.ifBlank {
                                stringResource(R.string.purchase_history_error)
                            },
                            onRetry = items::retry,
                            modifier = Modifier.testTag(PurchaseHistoryTestTags.ERROR),
                        )

                    is PurchaseHistoryUiState.Content ->
                        HistoryList(items = items, onPurchaseClick = onPurchaseClick)
                }
            }
        }
    }
}

@Composable
private fun SearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    onClear: () -> Unit,
) {
    val fieldLabel = stringResource(R.string.purchase_history_search_label)
    OutlinedTextField(
        value = query,
        onValueChange = onQueryChange,
        singleLine = true,
        label = { Text(fieldLabel) },
        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(
                    onClick = onClear,
                    modifier = Modifier.testTag(PurchaseHistoryTestTags.CLEAR),
                ) {
                    Icon(
                        Icons.Filled.Clear,
                        contentDescription = stringResource(R.string.purchase_history_clear_search),
                    )
                }
            }
        },
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(imeAction = ImeAction.Search),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .testTag(PurchaseHistoryTestTags.FIELD)
            .semantics { contentDescription = fieldLabel },
    )
}

@Composable
private fun HistoryList(
    items: LazyPagingItems<PurchaseListItem>,
    onPurchaseClick: (String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(PurchaseHistoryTestTags.LIST),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.id ?: index }) { index ->
            val item = items[index]
            if (item != null) {
                PurchaseRow(item = item, onClick = { onPurchaseClick(item.id) })
            }
        }
    }
}

/** One history row: title + status chip + locale-formatted amount + date. Merged for TalkBack. */
@Composable
private fun PurchaseRow(
    item: PurchaseListItem,
    onClick: () -> Unit,
) {
    val statusLabel = stringResource(orderStatusLabelRes(item.status))
    val amount = formatMoney(item.money)
    val date = formatEpochSeconds(item.createdAtEpochSec)
    val rowCd = stringResource(R.string.purchase_row_cd, item.title, amount, date, statusLabel)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(PurchaseHistoryTestTags.ROW)
            .clickable(onClick = onClick)
            .semantics { contentDescription = rowCd },
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.fillMaxWidth(0.7f)) {
            Text(
                text = item.title,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = date,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            AssistChip(onClick = {}, label = { Text(statusLabel) })
        }
        Text(
            text = amount,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
        )
    }
}
