package com.testlogon.android.feature.catalog

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.testlogon.android.data.shopads.SponsoredProduct

/**
 * ADV x ECOM (B2) — test tags for the shop Sponsored product card.
 */
object SponsoredProductTestTags {
    const val CARD = "sponsored_product_card"
    const val LABEL = "sponsored_product_label"
    fun card(unitId: String) = "sponsored_product_card_$unitId"
}

/**
 * ADV x ECOM (B2) — a SPONSORED product card for the shop search/browse results. Distinct "Sponsored"
 * label, NO like / wishlist / tip affordance (a sponsored product is standalone platform-100% and is
 * NOT tippable). The whole card is one tap-through to the real product page; the caller fires the
 * click beacon + stashes the ad_click_id (CPA) and navigates. The impression beacon fires when the
 * card first composes (see [onFirstShown]).
 */
@Composable
fun SponsoredProductCard(
    product: SponsoredProduct,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .testTag(SponsoredProductTestTags.CARD)
            .testTag(SponsoredProductTestTags.card(product.unitId))
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
        ),
    ) {
        Column(Modifier.padding(12.dp)) {
            // Fixed disclosure chip (the server sponsor_label carries the creative title, not a
            // disclosure); the shopper must always see a clear "Sponsored" mark.
            SponsoredLabel("Sponsored")
            Row(
                Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    Modifier
                        .size(72.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(MaterialTheme.colorScheme.surfaceVariant),
                ) {
                    val image = product.imageUrl
                    if (image != null) {
                        SubcomposeAsyncImage(
                            model = ImageRequest.Builder(LocalContext.current).data(image).crossfade(true).build(),
                            contentDescription = product.name,
                            loading = { Box(Modifier.fillMaxSize()) },
                            modifier = Modifier.fillMaxSize(),
                        )
                    }
                }
                Column(Modifier.weight(1f)) {
                    Text(
                        text = product.name,
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (product.priceCents > 0) {
                        Text(
                            text = formatPrice(product.priceCents, product.currency),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                        )
                    }
                    Text(
                        text = product.ctaText,
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 2.dp),
                    )
                }
            }
        }
    }
}

/** The distinct "Sponsored" disclosure chip. */
@Composable
private fun SponsoredLabel(label: String) {
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
        shape = RoundedCornerShape(4.dp),
        modifier = Modifier.testTag(SponsoredProductTestTags.LABEL),
    ) {
        Text(
            text = label.ifBlank { "Sponsored" },
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
        )
    }
}
