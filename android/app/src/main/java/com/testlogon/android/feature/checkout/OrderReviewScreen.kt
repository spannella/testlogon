@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.checkout

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
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
import com.testlogon.android.data.checkout.CheckoutLineItem
import com.testlogon.android.data.checkout.CheckoutSession
import com.testlogon.android.feature.catalog.formatPrice

/** AND-213 — stable test tags for the order-review screen. */
object OrderReviewTestTags {
    const val SCREEN = "order_review_screen"
    const val LIST = "order_review_list"
    const val TOTAL = "order_review_total"
    const val PLACE_ORDER = "order_review_place_order"
    const val ADDRESS_ROW = "order_review_address_row"
    const val EMPTY = "order_review_empty"
    const val ERROR = "order_review_error"

    fun line(sku: String) = "order_review_line_$sku"
}

/**
 * AND-213 — order-review route. Creates the checkout session, renders it, and routes the (stubbed)
 * payment outcome to a snackbar. Payment is intentionally unavailable (AND-031 not wired).
 */
@Composable
fun OrderReviewRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    // ECOMX-40 (B3): open the shipping-address step.
    onSelectAddress: () -> Unit = {},
    // ECOMX-40 (B3): the address_id handed back from the address step (nav SavedStateHandle).
    selectedAddressId: String? = null,
    // FIX (ecom residual #1): fired when the reliable purchase completes; routes to order confirmation.
    onOrderComplete: (txnId: String?, orderId: String) -> Unit = { _, _ -> },
    viewModel: CheckoutSessionViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val placing by viewModel.placing.collectAsStateWithLifecycle()
    val addressId by viewModel.selectedAddressId.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val paymentsUnavailable = stringResource(R.string.checkout_payments_unavailable)
    val addressRequired = stringResource(R.string.checkout_address_required)

    // ECOMX-40 (B3): fold the address step's result back into the VM state.
    LaunchedEffect(selectedAddressId) {
        if (selectedAddressId != null) viewModel.onAddressSelected(selectedAddressId)
    }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is CheckoutEvent.PaymentsUnavailable -> snackbarHostState.showSnackbar(paymentsUnavailable)
                is CheckoutEvent.PaymentFailed -> snackbarHostState.showSnackbar(event.message)
                is CheckoutEvent.AddressRequired -> snackbarHostState.showSnackbar(addressRequired)
                is CheckoutEvent.PurchaseComplete -> onOrderComplete(event.txnId, event.orderId)
            }
        }
    }

    OrderReviewScreen(
        state = state,
        placing = placing,
        selectedAddressId = addressId,
        snackbarHostState = snackbarHostState,
        onPlaceOrder = viewModel::placeOrder,
        onSelectAddress = onSelectAddress,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun OrderReviewScreen(
    state: OrderReviewUiState,
    placing: Boolean,
    snackbarHostState: SnackbarHostState,
    onPlaceOrder: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    // ECOMX-40 (B3): the currently selected shipping address (null until picked).
    selectedAddressId: String? = null,
    onSelectAddress: () -> Unit = {},
) {
    Scaffold(
        modifier = modifier.testTag(OrderReviewTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.checkout_title)) },
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
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            if (state is OrderReviewUiState.Ready) {
                PlaceOrderBar(
                    session = state.session,
                    placing = placing,
                    hasAddress = !selectedAddressId.isNullOrBlank(),
                    onPlaceOrder = onPlaceOrder,
                )
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is OrderReviewUiState.Loading -> LoadingState()

                is OrderReviewUiState.EmptyCart ->
                    EmptyState(
                        title = stringResource(R.string.checkout_empty_title),
                        body = stringResource(R.string.checkout_empty_body),
                        actionLabel = stringResource(R.string.action_back),
                        onAction = onBack,
                        modifier = Modifier.testTag(OrderReviewTestTags.EMPTY),
                    )

                is OrderReviewUiState.Error ->
                    ErrorState(
                        message = state.message,
                        onRetry = onRetry,
                        modifier = Modifier.testTag(OrderReviewTestTags.ERROR),
                    )

                is OrderReviewUiState.Ready ->
                    OrderReviewContent(
                        session = state.session,
                        selectedAddressId = selectedAddressId,
                        onSelectAddress = onSelectAddress,
                    )
            }
        }
    }
}

@Composable
private fun OrderReviewContent(
    session: CheckoutSession,
    selectedAddressId: String?,
    onSelectAddress: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(OrderReviewTestTags.LIST),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        // ECOMX-40 (B3): the reachable shipping-address step. Required before Place order.
        item(key = "__address_row") {
            ShippingAddressRow(hasAddress = !selectedAddressId.isNullOrBlank(), onSelectAddress = onSelectAddress)
            HorizontalDivider()
        }
        items(session.lineItems, key = { it.sku }) { line ->
            OrderReviewLine(line, session.currency)
            HorizontalDivider()
        }
    }
}

/** ECOMX-40 (B3) — the tappable "Shipping address" row that opens the address step. */
@Composable
private fun ShippingAddressRow(hasAddress: Boolean, onSelectAddress: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().testTag(OrderReviewTestTags.ADDRESS_ROW)
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
            Text(
                text = stringResource(R.string.checkout_shipping_address_label),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                text = if (hasAddress) stringResource(R.string.checkout_address_selected)
                else stringResource(R.string.checkout_address_none),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        androidx.compose.material3.TextButton(onClick = onSelectAddress) {
            Text(
                if (hasAddress) stringResource(R.string.checkout_address_change)
                else stringResource(R.string.checkout_address_add),
            )
        }
    }
}

@Composable
private fun OrderReviewLine(line: CheckoutLineItem, currency: String) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 4.dp).testTag(OrderReviewTestTags.line(line.sku)),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
            Text(
                text = line.name,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = stringResource(R.string.checkout_line_qty, line.quantity) +
                    "  ·  " + formatPrice(line.unitPriceCents, currency) + " each",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(
            text = formatPrice(line.lineTotalCents, currency),
            style = MaterialTheme.typography.titleSmall,
        )
    }
}

@Composable
private fun PlaceOrderBar(
    session: CheckoutSession,
    placing: Boolean,
    hasAddress: Boolean,
    onPlaceOrder: () -> Unit,
) {
    Surface(tonalElevation = 3.dp) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.checkout_total_label), style = MaterialTheme.typography.titleMedium)
                Text(
                    text = formatPrice(session.totalCents, session.currency),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.testTag(OrderReviewTestTags.TOTAL),
                )
            }
            // ECOMX-40 (B3): merchandise subtotal shown; shipping + sales tax are computed at
            // charge time from the shipping address and reflected on the confirmation/receipt.
            Text(
                text = stringResource(R.string.checkout_shipping_tax_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            // ECOMX-41 (B4): ONE checkout CTA (the dual "Choose payment method" button is removed).
            // Disabled until a shipping address is chosen (ECOMX-40 B3).
            Button(
                onClick = onPlaceOrder,
                enabled = !placing && hasAddress,
                modifier = Modifier.fillMaxWidth().testTag(OrderReviewTestTags.PLACE_ORDER),
            ) {
                if (placing) {
                    CircularProgressIndicator(
                        strokeWidth = 2.dp,
                        modifier = Modifier.size(18.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.width(8.dp))
                }
                Text(stringResource(R.string.checkout_place_order))
            }
        }
    }
}
