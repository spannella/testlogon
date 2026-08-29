@file:OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.messaging.EcomCardModel

/** FE-150 / FE-151 test tags. */
object EcomCardTestTags {
    const val PRODUCT_CARD = "thread_product_card"
    const val PRODUCT_BUY = "thread_product_card_buy"
    const val PRODUCT_STOCK = "thread_product_card_stock"
    const val ORDER_CARD = "thread_order_share_card"
    const val ORDER_STATUS = "thread_order_share_status"
}

/**
 * FE-150 — Product card: image, title, formatted price, an in-stock/out-of-stock badge, and a Buy
 * button that opens the product-detail (checkout) screen pre-filled for the product. Price format +
 * fields all come from the pure [EcomCardModel]; this only renders. [onBuy] receives (categoryId, itemId).
 */
@Composable
fun ProductCard(
    card: EcomCardModel.ProductCard,
    onBuy: (categoryId: String, itemId: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val cd = "Product ${card.title}, ${EcomCardModel.formatPrice(card.priceCents, card.currency)}" +
        (if (card.inStock) ", in stock" else ", out of stock")
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = modifier
            .widthIn(max = 260.dp)
            .testTag(EcomCardTestTags.PRODUCT_CARD)
            .semantics { contentDescription = cd },
    ) {
        Column(Modifier.padding(12.dp)) {
            card.imageUrl?.let { url ->
                AsyncImage(
                    model = url,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(1.6f)
                        .clip(RoundedCornerShape(8.dp)),
                )
            }
            Text(
                card.title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.padding(top = if (card.imageUrl != null) 8.dp else 0.dp),
            )
            Row(Modifier.fillMaxWidth().padding(top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    EcomCardModel.formatPrice(card.priceCents, card.currency),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f),
                )
                StockBadge(card.inStock)
            }
            Button(
                onClick = { onBuy(card.categoryId, card.itemId) },
                enabled = card.inStock,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp)
                    .testTag(EcomCardTestTags.PRODUCT_BUY),
            ) { Text(if (card.inStock) "Buy" else "Out of stock") }
        }
    }
}

@Composable
private fun StockBadge(inStock: Boolean) {
    val (bg, fg, label) = if (inStock) {
        Triple(MarketColors.Up.copy(alpha = 0.18f), MarketColors.Up, "In stock")
    } else {
        Triple(MarketColors.Down.copy(alpha = 0.18f), MarketColors.Down, "Out of stock")
    }
    Text(
        label,
        style = MaterialTheme.typography.labelSmall,
        color = fg,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier
            .testTag(EcomCardTestTags.PRODUCT_STOCK)
            .clip(RoundedCornerShape(50))
            .background(bg)
            .padding(horizontal = 8.dp, vertical = 2.dp),
    )
}

/**
 * FE-151 — Order/purchase-share card: a mode label (Receipt / Gift / Recommendation), the item
 * summary, the order status, and the total when present. In receipt mode the card carries NO buyer
 * name/address (guaranteed by the [EcomCardModel] choke point) so this composable simply never has
 * PII to show. Attribution (buyer name) renders only for gift/recommendation.
 */
@Composable
fun OrderShareCard(
    card: EcomCardModel.OrderCard,
    modifier: Modifier = Modifier,
) {
    val modeLabel = when (card.mode) {
        EcomCardModel.OrderMode.RECEIPT -> "Receipt"
        EcomCardModel.OrderMode.GIFT -> "Gift"
        EcomCardModel.OrderMode.RECOMMENDATION -> "Recommendation"
    }
    val total = card.totalCents?.let { EcomCardModel.formatPrice(it, card.currency ?: "USD") }
    val cd = "Shared order, $modeLabel, ${card.summary}, ${card.status}"

    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = modifier
            .widthIn(max = 260.dp)
            .testTag(EcomCardTestTags.ORDER_CARD)
            .semantics { contentDescription = cd },
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    modeLabel,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    card.status,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier
                        .testTag(EcomCardTestTags.ORDER_STATUS)
                        .clip(RoundedCornerShape(50))
                        .background(MaterialTheme.colorScheme.tertiaryContainer)
                        .padding(horizontal = 8.dp, vertical = 2.dp),
                )
            }
            Text(
                card.summary,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.padding(top = 6.dp),
            )
            total?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
            // Attribution shows ONLY for gift/recommendation; receipt mode has no buyer name at all.
            card.buyerName?.let {
                Text(
                    "Shared by $it",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
        }
    }
}
