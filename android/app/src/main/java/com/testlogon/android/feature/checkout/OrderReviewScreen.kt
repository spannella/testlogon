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
    viewModel: CheckoutSessionViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val placing by viewModel.placing.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val paymentsUnavailable = stringResource(R.string.checkout_payments_unavailable)

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is CheckoutEvent.PaymentsUnavailable -> snackbarHostState.showSnackbar(paymentsUnavailable)
                is CheckoutEvent.PaymentFailed -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    OrderReviewScreen(
        state = state,
        placing = placing,
        snackbarHostState = snackbarHostState,
        onPlaceOrder = viewModel::placeOrder,
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
                PlaceOrderBar(session = state.session, placing = placing, onPlaceOrder = onPlaceOrder)
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

                is OrderReviewUiState.Ready -> OrderReviewContent(session = state.session)
            }
        }
    }
}

@Composable
private fun OrderReviewContent(session: CheckoutSession) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(OrderReviewTestTags.LIST),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(session.lineItems, key = { it.sku }) { line ->
            OrderReviewLine(line)
            HorizontalDivider()
        }
    }
}

@Composable
private fun OrderReviewLine(line: CheckoutLineItem) {
    Row(
        Modifier.fillMaxWidth().testTag(OrderReviewTestTags.line(line.sku)),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = line.name,
            style = MaterialTheme.typography.bodyLarge,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(end = 12.dp),
        )
        Text(
            text = stringResource(R.string.checkout_line_qty, line.quantity),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun PlaceOrderBar(session: CheckoutSession, placing: Boolean, onPlaceOrder: () -> Unit) {
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
            Button(
                onClick = onPlaceOrder,
                enabled = !placing,
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
