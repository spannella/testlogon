@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.sellerstore

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.sellerstore.SellerOrder
import com.testlogon.android.data.sellerstore.SellerOrderDetail
import com.testlogon.android.feature.catalog.formatPrice

/** ECOM (seller store) — stable test tags for orders-received. */
object SellerOrdersTestTags {
    const val SCREEN = "seller_orders_screen"
    const val STATUS_CHIP = "seller_orders_status_chip"
    const val ROW = "seller_orders_row"
    const val EMPTY = "seller_orders_empty"
    const val ERROR = "seller_orders_error"
    const val DETAIL = "seller_orders_detail"
    const val TRANSITION = "seller_orders_transition"
    const val CANCEL = "seller_orders_cancel"
}

@Composable
fun SellerOrdersRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SellerOrdersViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is SellerOrdersEvent.Message -> snackbarHostState.showSnackbar(event.text)
            }
        }
    }

    SellerOrdersScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onSetStatus = viewModel::setStatus,
        onOpenOrder = viewModel::openOrder,
        onCloseDetail = viewModel::closeDetail,
        onTransition = viewModel::transition,
        onCancel = viewModel::cancel,
        onRetry = viewModel::refresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun SellerOrdersScreen(
    state: SellerOrdersUiState,
    snackbarHostState: SnackbarHostState,
    onSetStatus: (String) -> Unit,
    onOpenOrder: (String) -> Unit,
    onCloseDetail: () -> Unit,
    onTransition: (String) -> Unit,
    onCancel: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SellerOrdersTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.seller_orders_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            StatusBar(selected = state.status, onSelect = onSetStatus)
            HorizontalDivider()
            Box(Modifier.fillMaxSize()) {
                when {
                    state.loading -> LoadingState()
                    state.error != null ->
                        ErrorState(message = state.error, onRetry = onRetry, modifier = Modifier.testTag(SellerOrdersTestTags.ERROR))
                    state.orders.isEmpty() ->
                        EmptyState(
                            title = stringResource(R.string.seller_orders_empty_title),
                            body = stringResource(R.string.seller_orders_empty_body),
                            modifier = Modifier.testTag(SellerOrdersTestTags.EMPTY),
                        )
                    else -> LazyColumn(
                        Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(state.orders, key = { it.orderId }) { order ->
                            OrderRow(order = order, onClick = { onOpenOrder(order.orderId) })
                        }
                    }
                }
            }
        }
    }

    if (state.detail != null || state.detailLoading) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(onDismissRequest = onCloseDetail, sheetState = sheetState) {
            Box(Modifier.fillMaxWidth().testTag(SellerOrdersTestTags.DETAIL)) {
                if (state.detail == null) {
                    LoadingState(fullScreen = false)
                } else {
                    OrderDetail(
                        detail = state.detail,
                        actionBusy = state.actionBusy,
                        onTransition = onTransition,
                        onCancel = onCancel,
                    )
                }
            }
        }
    }
}

@Composable
private fun StatusBar(selected: String, onSelect: (String) -> Unit) {
    Row(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        SellerOrdersUiState.STATUSES.forEach { status ->
            FilterChip(
                selected = status == selected,
                onClick = { onSelect(status) },
                label = { Text(status) },
                modifier = Modifier.testTag(SellerOrdersTestTags.STATUS_CHIP),
            )
        }
    }
}

@Composable
private fun OrderRow(order: SellerOrder, onClick: () -> Unit) {
    ElevatedCard(Modifier.fillMaxWidth().testTag(SellerOrdersTestTags.ROW).clickable(onClick = onClick)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = "#" + order.orderId.take(12),
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            order.buyerId?.let {
                Text(stringResource(R.string.seller_orders_buyer, it), style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(
                text = formatPrice(order.amountCents, order.currency) + "  ·  " +
                    stringResource(R.string.seller_orders_items, order.lineItemCount) + "  ·  " + order.status,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

@Composable
private fun OrderDetail(
    detail: SellerOrderDetail,
    actionBusy: Boolean,
    onTransition: (String) -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("#" + detail.orderId, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(
            text = stringResource(R.string.seller_orders_status, detail.status) + "  ·  " + formatPrice(detail.amountCents, detail.currency),
            style = MaterialTheme.typography.bodyMedium,
        )
        HorizontalDivider()
        detail.lineItems.forEach { line ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    text = (line.name ?: line.itemId) + "  ×" + line.quantity,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(end = 8.dp),
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(formatPrice(line.unitPriceCents * line.quantity, line.currency), style = MaterialTheme.typography.bodyMedium)
            }
        }
        HorizontalDivider()
        if (detail.allowedTransitions.isEmpty()) {
            Text(stringResource(R.string.seller_orders_no_actions), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            Text(stringResource(R.string.seller_orders_fulfil), style = MaterialTheme.typography.titleSmall)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                detail.allowedTransitions.forEach { target ->
                    AssistChip(
                        onClick = { if (!actionBusy) onTransition(target) },
                        label = { Text(target) },
                        modifier = Modifier.testTag(SellerOrdersTestTags.TRANSITION),
                    )
                }
            }
        }
        OutlinedButton(
            onClick = { if (!actionBusy) onCancel() },
            modifier = Modifier.fillMaxWidth().testTag(SellerOrdersTestTags.CANCEL),
        ) { Text(stringResource(R.string.seller_orders_cancel)) }
    }
}
