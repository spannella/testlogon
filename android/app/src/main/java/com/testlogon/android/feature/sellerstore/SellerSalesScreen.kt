@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.sellerstore

import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.LocalShipping
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
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
import com.testlogon.android.data.sellerstore.SellerSale
import com.testlogon.android.data.sellerstore.SellerSaleAddress
import com.testlogon.android.data.sellerstore.SellerSaleDetail
import com.testlogon.android.feature.catalog.formatPrice

/** ECOM-SELLER - stable test tags for the seller sales / orders-received screen. */
object SellerSalesTestTags {
    const val SCREEN = "seller_sales_screen"
    const val ROW = "seller_sales_row"
    const val EMPTY = "seller_sales_empty"
    const val ERROR = "seller_sales_error"
    const val DETAIL = "seller_sales_detail"
    const val ADDRESS = "seller_sales_address"
    const val TRANSITION = "seller_sales_transition"
    const val MARK_SHIPPED = "seller_sales_mark_shipped"
    const val TRACKING = "seller_sales_tracking"
    const val CARRIER = "seller_sales_carrier"
}

@Composable
fun SellerSalesRoute(
    onBack: () -> Unit,
    initialSaleId: String? = null,
    modifier: Modifier = Modifier,
    viewModel: SellerSalesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    // shop_item_sold alert deep-link: auto-open the sale detail once.
    LaunchedEffect(initialSaleId) {
        if (!initialSaleId.isNullOrBlank()) viewModel.openSale(initialSaleId)
    }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is SellerSalesEvent.Message -> snackbarHostState.showSnackbar(event.text)
            }
        }
    }

    SellerSalesScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onOpenSale = viewModel::openSale,
        onCloseDetail = viewModel::closeDetail,
        onTransition = viewModel::transition,
        onRetry = viewModel::refresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun SellerSalesScreen(
    state: SellerSalesUiState,
    snackbarHostState: SnackbarHostState,
    onOpenSale: (String) -> Unit,
    onCloseDetail: () -> Unit,
    onTransition: (String, String?, String?) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SellerSalesTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.seller_sales_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.loading -> LoadingState()
                state.error != null ->
                    ErrorState(message = state.error, onRetry = onRetry, modifier = Modifier.testTag(SellerSalesTestTags.ERROR))
                state.sales.isEmpty() ->
                    EmptyState(
                        title = stringResource(R.string.seller_sales_empty_title),
                        body = stringResource(R.string.seller_sales_empty_body),
                        modifier = Modifier.testTag(SellerSalesTestTags.EMPTY),
                    )
                else -> LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(state.sales, key = { it.shipGroupId }) { sale ->
                        SaleRow(sale = sale, onClick = { onOpenSale(sale.shipGroupId) })
                    }
                }
            }
        }
    }

    if (state.detail != null || state.detailLoading) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(onDismissRequest = onCloseDetail, sheetState = sheetState) {
            Box(Modifier.fillMaxWidth().testTag(SellerSalesTestTags.DETAIL)) {
                if (state.detail == null) {
                    LoadingState(fullScreen = false)
                } else {
                    SaleDetail(
                        detail = state.detail,
                        actionBusy = state.actionBusy,
                        onTransition = onTransition,
                    )
                }
            }
        }
    }
}

@Composable
private fun SaleRow(sale: SellerSale, onClick: () -> Unit) {
    ElevatedCard(Modifier.fillMaxWidth().testTag(SellerSalesTestTags.ROW).clickable(onClick = onClick)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            sale.buyerName?.takeIf { it.isNotBlank() }?.let {
                Text(stringResource(R.string.seller_sales_buyer, it), style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(
                text = formatPrice(sale.subtotalCents, sale.currency) + "  ·  " +
                    stringResource(R.string.seller_sales_items, sale.itemCount) + "  ·  " + sale.status,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
            )
            Text(
                text = "#" + sale.shipGroupId.take(16),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun SaleDetail(
    detail: SellerSaleDetail,
    actionBusy: Boolean,
    onTransition: (String, String?, String?) -> Unit,
) {
    var tracking by rememberSaveable(detail.shipGroupId) { mutableStateOf("") }
    var carrier by rememberSaveable(detail.shipGroupId) { mutableStateOf("") }

    Column(
        Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(
            text = stringResource(R.string.seller_sales_status, detail.status),
            style = MaterialTheme.typography.titleMedium,
        )

        // Buyer + shipping address (G2)
        HorizontalDivider()
        Text(stringResource(R.string.seller_sales_ship_to), style = MaterialTheme.typography.titleSmall)
        Column(Modifier.testTag(SellerSalesTestTags.ADDRESS), verticalArrangement = Arrangement.spacedBy(1.dp)) {
            val recipient = detail.shipTo.name?.takeIf { it.isNotBlank() } ?: detail.buyerName
            recipient?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }
            if (detail.shipTo.hasAny) {
                addressLines(detail.shipTo).forEach { line ->
                    Text(line, style = MaterialTheme.typography.bodyMedium)
                }
            } else {
                Text(stringResource(R.string.seller_sales_no_address), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            detail.buyerEmail?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        // Line items (G4: real names) + subtotal
        HorizontalDivider()
        Text(stringResource(R.string.seller_sales_line_items), style = MaterialTheme.typography.titleSmall)
        detail.lineItems.forEach { line ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    text = (line.name?.takeIf { it.isNotBlank() } ?: line.sku ?: line.itemId) + "  ×" + line.quantity,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(end = 8.dp),
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(formatPrice(line.lineTotalCents, line.currency), style = MaterialTheme.typography.bodyMedium)
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(stringResource(R.string.seller_sales_subtotal), style = MaterialTheme.typography.titleSmall)
            Text(formatPrice(detail.subtotalCents, detail.currency), style = MaterialTheme.typography.titleSmall)
        }

        detail.trackingNumber?.takeIf { it.isNotBlank() }?.let {
            Text(stringResource(R.string.seller_sales_tracked, it, detail.carrier ?: ""), style = MaterialTheme.typography.bodySmall)
        }

        // Fulfilment (G3): scoped to THIS ship group
        HorizontalDivider()
        val canShip = SellerSalesViewModel.SHIPPED in detail.allowedTransitions
        if (detail.allowedTransitions.isEmpty()) {
            Text(stringResource(R.string.seller_sales_no_actions), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            Text(stringResource(R.string.seller_sales_fulfil), style = MaterialTheme.typography.titleSmall)
            if (canShip) {
                OutlinedTextField(
                    value = tracking,
                    onValueChange = { tracking = it },
                    label = { Text(stringResource(R.string.seller_sales_tracking)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SellerSalesTestTags.TRACKING),
                )
                OutlinedTextField(
                    value = carrier,
                    onValueChange = { carrier = it },
                    label = { Text(stringResource(R.string.seller_sales_carrier)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SellerSalesTestTags.CARRIER),
                )
                Button(
                    onClick = { if (!actionBusy) onTransition(SellerSalesViewModel.SHIPPED, tracking, carrier) },
                    enabled = !actionBusy,
                    modifier = Modifier.fillMaxWidth().testTag(SellerSalesTestTags.MARK_SHIPPED),
                ) {
                    Icon(Icons.Outlined.LocalShipping, contentDescription = null)
                    Text("  " + stringResource(R.string.seller_sales_mark_shipped))
                }
            }
            val others = detail.allowedTransitions.filter { it != SellerSalesViewModel.SHIPPED }
            if (others.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    others.forEach { target ->
                        AssistChip(
                            onClick = { if (!actionBusy) onTransition(target, null, null) },
                            label = { Text(target) },
                            modifier = Modifier.testTag(SellerSalesTestTags.TRANSITION),
                        )
                    }
                }
            }
        }
    }
}

/** Builds the human address lines from the buyer ship-to (name is rendered separately). */
private fun addressLines(a: SellerSaleAddress): List<String> {
    val lines = mutableListOf<String>()
    a.line1?.takeIf { it.isNotBlank() }?.let { lines.add(it) }
    a.line2?.takeIf { it.isNotBlank() }?.let { lines.add(it) }
    val cityState = listOfNotNull(
        a.city?.takeIf { it.isNotBlank() },
        listOfNotNull(a.state?.takeIf { it.isNotBlank() }, a.postalCode?.takeIf { it.isNotBlank() }).joinToString(" ").takeIf { it.isNotBlank() },
    ).joinToString(", ")
    if (cityState.isNotBlank()) lines.add(cityState)
    a.country?.takeIf { it.isNotBlank() }?.let { lines.add(it) }
    return lines
}
