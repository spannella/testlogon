@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.viewer.shop

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.ShoppingCart
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.data.livecommerce.PinnedProduct
import com.testlogon.android.feature.broadcast.host.livecommerce.formatMoney

/** LIVECOM L5 — stable testTags for the viewer shop-this-stream overlay. */
object ShopThisStreamTestTags {
    const val PANEL = "shop_this_stream_panel"
    const val TOGGLE = "shop_this_stream_toggle"
    const val ROW = "shop_this_stream_row"
    const val BUY = "shop_this_stream_buy"
    const val CONFIRM = "shop_this_stream_confirm_buy"
}

/**
 * LIVECOM L5 — the viewer "Shop this stream" overlay/drawer beneath the live player. Lists the products
 * the host pinned (name / price / image + an affiliate hint) and lets the viewer buy IN-STREAM: tapping a
 * product opens a compact confirm sheet, and confirming completes the purchase attributed to the broadcast
 * session + host WITHOUT leaving the stream (no nav away). A snackbar-less inline notice reports the result.
 *
 * Resolves its own [ShopThisStreamViewModel] from the viewer route's NavBackStackEntry ("sessionId" arg),
 * so it drops into the ViewerScreen next to the existing products shelf / tips / chat panels.
 */
@Composable
fun ShopThisStreamPanel(
    modifier: Modifier = Modifier,
    vm: ShopThisStreamViewModel = hiltViewModel(),
    onShowMessage: (String) -> Unit = {},
) {
    val s by vm.uiState.collectAsStateWithLifecycle()

    // Mirror any result to an optional external sink (e.g. a host snackbar) without blocking the inline notice.
    LaunchedEffect(s.purchaseMessage, s.error) {
        (s.purchaseMessage ?: s.error)?.let { if (s.pendingBuy == null) onShowMessage(it) }
    }

    Card(modifier = modifier.testTag(ShopThisStreamTestTags.PANEL)) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 40.dp)
                    .testTag(ShopThisStreamTestTags.TOGGLE),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(Icons.Filled.ShoppingCart, contentDescription = null)
                Text(
                    text = "Shop this stream (${s.products.size})",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = vm::onToggleExpanded) {
                    Icon(
                        if (s.expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                        contentDescription = if (s.expanded) "Collapse" else "Expand",
                    )
                }
            }

            if (s.expanded) {
                when {
                    s.loading -> CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    s.products.isEmpty() -> Text("No products featured yet.", style = MaterialTheme.typography.bodyMedium)
                    else -> s.products.forEach { p ->
                        ProductRow(
                            product = p,
                            buying = s.buyingProductId == p.productId,
                            onBuy = { vm.onSelect(p) },
                        )
                    }
                }
            }

            // Inline in-stream purchase result / error (the viewer never leaves the stream).
            s.purchaseMessage?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
            }
            (s.error.takeIf { s.pendingBuy == null })?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
        }
    }

    s.pendingBuy?.let { product ->
        AlertDialog(
            modifier = Modifier.testTag(ShopThisStreamTestTags.CONFIRM),
            onDismissRequest = vm::onDismissBuy,
            title = { Text("Buy in-stream") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(product.name, style = MaterialTheme.typography.titleSmall)
                    Text(formatMoney(product.priceCents, product.currency))
                    if (product.isAffiliate) {
                        Text(
                            "Affiliate — the host earns %.1f%%".format(product.commissionPercent),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Text(
                        "You'll stay in the stream after purchase.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    s.error?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = vm::confirmBuy,
                    enabled = s.buyingProductId == null,
                    modifier = Modifier.testTag(ShopThisStreamTestTags.BUY),
                ) {
                    if (s.buyingProductId != null) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp))
                    } else {
                        Text("Buy ${formatMoney(product.priceCents, product.currency)}")
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = vm::onDismissBuy, enabled = s.buyingProductId == null) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun ProductRow(product: PinnedProduct, buying: Boolean, onBuy: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().testTag(ShopThisStreamTestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (product.imageUrl != null) {
            AsyncImage(model = product.imageUrl, contentDescription = null, modifier = Modifier.size(48.dp))
        } else {
            Box(modifier = Modifier.size(48.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(product.name, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodyMedium)
            Text(formatMoney(product.priceCents, product.currency), style = MaterialTheme.typography.bodySmall)
            if (product.isAffiliate) {
                AssistChip(onClick = {}, label = { Text("Affiliate") })
            }
        }
        if (buying) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp))
        } else {
            Button(onClick = onBuy, modifier = Modifier.heightIn(min = 40.dp)) { Text("Buy") }
        }
    }
}
