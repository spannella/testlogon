@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.purchases

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.purchases.PurchaseDetail
import com.testlogon.android.feature.tracking.TrackingSection

/** AND-220 — stable test tags for the order-detail screen. */
object OrderDetailTestTags {
    const val SCREEN = "order_detail_screen"
    const val HEADER = "order_detail_header"
    const val ITEMS = "order_detail_items"
    const val ITEM_ROW = "order_detail_item_row"
    const val SUMMARY = "order_detail_summary"
    const val BILLING_ACTIONS = "order_detail_billing_actions"
    const val REQUEST_REFUND = "order_detail_request_refund"
    const val OPEN_DISPUTE = "order_detail_open_dispute"
    // ECOMX-42 (B6) / ECOMX-43 (B5).
    const val CONFIRM_DELIVERY = "order_detail_confirm_delivery"
    const val CONFIRM_DELIVERY_BTN = "order_detail_confirm_delivery_btn"
    const val DIGITAL_ITEMS = "order_detail_digital_items"
    const val DIGITAL_OPEN = "order_detail_digital_open"
}

/**
 * AND-220 — order (transaction) detail route. Renders the header/summary, the resolved cart line items,
 * and EMBEDS the AND-215 [TrackingSection] (no duplication of carrier parsing / status display). The
 * "Track package" link is launched via an https-only ACTION_VIEW guard (intent-redirection hardening).
 */
@Composable
fun OrderDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: OrderDetailViewModel = hiltViewModel(),
    // AND-244/AND-245: billing-adjacent entry points. Default to no-op so existing callers compile;
    // the nav graph wires them to the refund-submit / file-dispute routes (keyed by the txn id).
    onRequestRefund: (transactionEntryId: String) -> Unit = {},
    onOpenDispute: (transactionEntryId: String) -> Unit = {},
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val snackbarHostState = androidx.compose.runtime.remember { androidx.compose.material3.SnackbarHostState() }
    val confirmedLabel = stringResource(R.string.order_confirm_received_done)

    androidx.compose.runtime.LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is OrderDetailEvent.DeliveryConfirmed -> snackbarHostState.showSnackbar(confirmedLabel)
                is OrderDetailEvent.ActionFailed -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    Scaffold(
        modifier = modifier.testTag(OrderDetailTestTags.SCREEN),
        snackbarHost = { androidx.compose.material3.SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.order_detail_title)) },
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
            when (val s = state) {
                is OrderDetailUiState.Loading -> LoadingState()
                is OrderDetailUiState.Error ->
                    ErrorState(
                        message = s.message,
                        onRetry = viewModel::retry,
                    )
                is OrderDetailUiState.Content ->
                    OrderDetailContent(
                        order = s.order,
                        items = s.items,
                        entitlements = s.entitlements,
                        confirming = s.confirming,
                        onConfirmReceived = viewModel::confirmReceived,
                        onRequestRefund = { onRequestRefund(s.order.id) },
                        onOpenDispute = { onOpenDispute(s.order.id) },
                        tracking = {
                            // Embed the AND-215 section; its CTA launches the carrier URL (https-only).
                            TrackingSection(
                                state = s.tracking,
                                onRetry = viewModel::retry,
                                onOpenCarrier = { url -> openCarrierUrl(context, url) },
                                onCopy = { number -> copyToClipboard(context, number) },
                            )
                        },
                    )
            }
        }
    }
}

@Composable
private fun OrderDetailContent(
    order: PurchaseDetail,
    items: List<CartItem>,
    entitlements: List<com.testlogon.android.data.entitlements.LibraryEntitlement>,
    confirming: Boolean,
    onConfirmReceived: () -> Unit,
    onRequestRefund: () -> Unit,
    onOpenDispute: () -> Unit,
    tracking: @Composable () -> Unit,
) {
    val context = LocalContext.current
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item { OrderHeader(order) }
        if (items.isNotEmpty()) {
            item { OrderItemsCard(items, order.money.currency) }
        }
        item { tracking() }
        // ECOMX-42 (B6): confirm-delivery affordance once the order has shipped.
        if (order.canConfirmDelivery) {
            item { ConfirmDeliveryCard(confirming = confirming, onConfirmReceived = onConfirmReceived) }
        }
        // ECOMX-43 (B5): digital-goods access/download for this order.
        if (entitlements.isNotEmpty()) {
            item { DigitalItemsCard(entitlements = entitlements, context = context) }
        }
        // AND-244/AND-245: billing-adjacent actions against this transaction.
        item { OrderBillingActions(onRequestRefund = onRequestRefund, onOpenDispute = onOpenDispute) }
    }
}

/** ECOMX-42 (B6) — "Confirm delivery" card; visible once the order has shipped, hidden once completed. */
@Composable
private fun ConfirmDeliveryCard(confirming: Boolean, onConfirmReceived: () -> Unit) {
    Card(Modifier.fillMaxWidth().testTag(OrderDetailTestTags.CONFIRM_DELIVERY)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            androidx.compose.material3.Button(
                onClick = onConfirmReceived,
                enabled = !confirming,
                modifier = Modifier.fillMaxWidth().testTag(OrderDetailTestTags.CONFIRM_DELIVERY_BTN),
            ) {
                if (confirming) {
                    androidx.compose.material3.CircularProgressIndicator(
                        strokeWidth = 2.dp,
                        modifier = Modifier.size(18.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    androidx.compose.foundation.layout.Spacer(Modifier.width(8.dp))
                }
                Text(stringResource(R.string.order_confirm_received))
            }
        }
    }
}

/** ECOMX-43 (B5) — digital items granted by this order; each opens/downloads via the entitlement. */
@Composable
private fun DigitalItemsCard(
    entitlements: List<com.testlogon.android.data.entitlements.LibraryEntitlement>,
    context: Context,
) {
    Card(Modifier.fillMaxWidth().testTag(OrderDetailTestTags.DIGITAL_ITEMS)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.order_digital_access_title), style = MaterialTheme.typography.titleMedium)
            entitlements.forEach { ent ->
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                ) {
                    Text(
                        text = ent.label,
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.weight(1f),
                    )
                    androidx.compose.material3.TextButton(
                        onClick = {
                            // Open the buyer's library entry for this granted product. The entitlement
                            // gates access; the deep link resolves to the in-app viewer for its type.
                            openLibraryItem(context, ent.entitlementId)
                        },
                        enabled = ent.isAccessible,
                        modifier = Modifier.testTag(OrderDetailTestTags.DIGITAL_OPEN),
                    ) { Text(stringResource(R.string.order_digital_open)) }
                }
            }
        }
    }
}

/** AND-244/AND-245 — "Request a refund" / "Open a dispute" actions, reachable from the order detail. */
@Composable
private fun OrderBillingActions(onRequestRefund: () -> Unit, onOpenDispute: () -> Unit) {
    Card(Modifier.fillMaxWidth().testTag(OrderDetailTestTags.BILLING_ACTIONS)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.order_detail_billing_help), style = MaterialTheme.typography.titleMedium)
            androidx.compose.material3.TextButton(
                onClick = onRequestRefund,
                modifier = Modifier.testTag(OrderDetailTestTags.REQUEST_REFUND),
            ) { Text(stringResource(R.string.order_detail_request_refund)) }
            androidx.compose.material3.TextButton(
                onClick = onOpenDispute,
                modifier = Modifier.testTag(OrderDetailTestTags.OPEN_DISPUTE),
            ) { Text(stringResource(R.string.order_detail_open_dispute)) }
        }
    }
}

@Composable
private fun OrderHeader(order: PurchaseDetail) {
    val statusLabel = stringResource(orderStatusLabelRes(order.status))
    // ECOMX-42 (B2): show the REAL physical fulfilment state (Processing/Shipped/Delivered) when the
    // order header carries it — distinct from the money status chip.
    val fulfillmentLabel = order.fulfillmentStatus?.takeIf { it.isNotBlank() }
        ?.replace('_', ' ')?.replaceFirstChar { it.uppercase() }
    Card(Modifier.fillMaxWidth().testTag(OrderDetailTestTags.HEADER)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(order.title, style = MaterialTheme.typography.titleLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, label = { Text(statusLabel) })
                if (fulfillmentLabel != null) {
                    AssistChip(
                        onClick = {},
                        label = { Text(fulfillmentLabel) },
                        modifier = Modifier.testTag("order_detail_fulfillment_chip"),
                    )
                }
            }
            Text(
                text = stringResource(R.string.order_detail_placed, formatEpochSeconds(order.createdAtEpochSec)),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                text = formatMoney(order.money),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.testTag(OrderDetailTestTags.SUMMARY),
            )
            order.merchantId?.let {
                Text(
                    text = stringResource(R.string.order_detail_merchant, it),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            order.externalRef?.let {
                Text(
                    text = stringResource(R.string.order_detail_reference, it),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun OrderItemsCard(items: List<CartItem>, currency: String) {
    Card(Modifier.fillMaxWidth().testTag(OrderDetailTestTags.ITEMS)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.order_detail_items_title), style = MaterialTheme.typography.titleMedium)
            items.forEachIndexed { index, item ->
                if (index > 0) HorizontalDivider()
                OrderItemRow(item, currency)
            }
        }
    }
}

@Composable
private fun OrderItemRow(item: CartItem, currency: String) {
    Row(
        Modifier.fillMaxWidth().testTag(OrderDetailTestTags.ITEM_ROW),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(Modifier.fillMaxWidth(0.7f)) {
            Text(item.name, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = stringResource(
                    R.string.order_detail_item_qty_price,
                    item.quantity,
                    formatCents(item.unitPriceCents, currency),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(formatCents(item.lineTotalCents, currency), style = MaterialTheme.typography.bodyMedium)
    }
}

/** Cart line items are integer cents (distinct from the transaction's major-unit amount). */
private fun formatCents(cents: Long, currency: String): String {
    return try {
        val fmt = java.text.NumberFormat.getCurrencyInstance()
        fmt.currency = java.util.Currency.getInstance(currency)
        fmt.format(cents / 100.0)
    } catch (_: IllegalArgumentException) {
        "%.2f %s".format(cents / 100.0, currency)
    }
}

/** Launches [url] in an external browser only when it is an https URL (intent-redirection hardening). */
internal fun openCarrierUrl(context: Context, url: String) {
    if (!url.startsWith("https://", ignoreCase = true)) return
    val intent = Intent(Intent.ACTION_VIEW, url.toUri()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        // No browser available; the CTA is best-effort.
    }
}

private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText("tracking_number", text))
}

/**
 * ECOMX-43 (B5) — open the buyer's library entry for a granted entitlement. Launches the app's
 * `library` deep link (handled by the in-app viewer for the product type). Best-effort: if nothing
 * handles it the CTA is a no-op (the entitlement itself already gates + records access).
 */
internal fun openLibraryItem(context: Context, entitlementId: String) {
    val uri = "testlogon://library/${android.net.Uri.encode(entitlementId)}".toUri()
    val intent = Intent(Intent.ACTION_VIEW, uri)
        .setPackage(context.packageName)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        // No in-app handler yet; access is still granted server-side (the entitlement stands).
    }
}
