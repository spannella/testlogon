@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.host.livecommerce

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.livecommerce.PinnedProduct
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/** LIVECOM L5 — stable testTags for the host feature-product control. */
object LiveCommerceHostTestTags {
    const val CARD = "host_live_commerce_card"
    const val SEARCH = "host_live_commerce_search"
    const val SEARCH_GO = "host_live_commerce_search_go"
    const val PIN = "host_live_commerce_pin"
    const val UNPIN = "host_live_commerce_unpin"
    const val PINNED_ROW = "host_live_commerce_pinned_row"
}

/**
 * LIVECOM L5 — the "Feature / Pin product" control surfaced on the PRIMARY live host screen. Reuses the
 * host route's NavBackStackEntry (same "sessionId" arg), so the [LiveCommerceHostViewModel] resolves with
 * no extra nav wiring (same pattern as the host ad-break section). The host searches ANY product to pin
 * as an affiliate, or picks from their own catalog items (shown when the search box is empty); the pinned
 * "shop this stream" set renders with an unpin affordance and an affiliate badge + commission hint.
 */
@Composable
fun LiveCommerceHostSection(vm: LiveCommerceHostViewModel = hiltViewModel()) {
    val s by vm.uiState.collectAsStateWithLifecycle()
    Card(modifier = Modifier.fillMaxWidth().testTag(LiveCommerceHostTestTags.CARD)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = "Shop this stream — feature products",
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = "Pin your own products or any seller's product as an affiliate. Viewers buy in-stream.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // ── Pinned "shop this stream" set ──────────────────────────────────
            if (s.loading) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp))
            } else if (s.pinned.isEmpty()) {
                Text("No products pinned yet.", style = MaterialTheme.typography.bodyMedium)
            } else {
                s.pinned.forEach { p ->
                    PinnedRow(
                        product = p,
                        busy = s.busyProductId == p.productId,
                        onUnpin = { vm.unpin(p.productId) },
                    )
                }
            }

            HorizontalDivider()

            // ── Add / pin a product ────────────────────────────────────────────
            OutlinedTextField(
                value = s.query,
                onValueChange = vm::onQueryChange,
                label = { Text("Search any product to affiliate") },
                singleLine = true,
                trailingIcon = {
                    TextButton(onClick = vm::search, modifier = Modifier.testTag(LiveCommerceHostTestTags.SEARCH_GO)) {
                        Text("Search")
                    }
                },
                modifier = Modifier.fillMaxWidth().testTag(LiveCommerceHostTestTags.SEARCH),
            )

            Text(
                text = if (s.query.isBlank()) "Your products" else "Search results",
                style = MaterialTheme.typography.labelLarge,
            )
            if (s.searching) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp))
            } else if (s.candidates.isEmpty()) {
                Text(
                    text = if (s.query.isBlank()) "You have no catalog products yet." else "No matches.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            } else {
                s.candidates.forEach { item ->
                    CandidateRow(
                        item = item,
                        alreadyPinned = item.itemId in s.pinnedIds,
                        busy = s.busyProductId == item.itemId,
                        onPin = { vm.pin(item) },
                    )
                }
            }

            s.error?.let { msg ->
                Text(
                    text = msg,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun PinnedRow(product: PinnedProduct, busy: Boolean, onUnpin: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().testTag(LiveCommerceHostTestTags.PINNED_ROW),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Thumb(product.imageUrl)
        Column(modifier = Modifier.weight(1f)) {
            Text(product.name, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodyMedium)
            Text(formatMoney(product.priceCents, product.currency), style = MaterialTheme.typography.bodySmall)
            if (product.isAffiliate) {
                AssistChip(
                    onClick = {},
                    label = { Text("Affiliate • %.1f%%".format(product.commissionPercent)) },
                )
            }
        }
        if (busy) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp))
        } else {
            IconButton(onClick = onUnpin, modifier = Modifier.testTag(LiveCommerceHostTestTags.UNPIN)) {
                Icon(Icons.Filled.Close, contentDescription = "Unpin ${product.name}")
            }
        }
    }
}

@Composable
private fun CandidateRow(item: CatalogItem, alreadyPinned: Boolean, busy: Boolean, onPin: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Thumb(item.thumbnailUrl)
        Column(modifier = Modifier.weight(1f)) {
            Text(item.name, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodyMedium)
            Text(formatMoney(item.priceCents, item.currency), style = MaterialTheme.typography.bodySmall)
        }
        if (busy) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp))
        } else if (alreadyPinned) {
            Text("Pinned", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        } else {
            OutlinedButton(
                onClick = onPin,
                modifier = Modifier.heightIn(min = 40.dp).testTag(LiveCommerceHostTestTags.PIN),
            ) { Text("Pin") }
        }
    }
}

@Composable
private fun Thumb(url: String?) {
    Box(
        modifier = Modifier
            .size(44.dp)
            .padding(0.dp),
        contentAlignment = Alignment.Center,
    ) {
        if (url != null) {
            AsyncImage(model = url, contentDescription = null, modifier = Modifier.size(44.dp))
        } else {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .padding(0.dp),
            )
        }
    }
}

/** Formats integer minor units with the item currency (falls back to a plain amount on a bad code). */
internal fun formatMoney(cents: Long, currency: String): String = try {
    NumberFormat.getCurrencyInstance(Locale.getDefault()).apply {
        this.currency = Currency.getInstance(currency)
    }.format(cents / 100.0)
} catch (_: Exception) {
    "%.2f %s".format(cents / 100.0, currency)
}
