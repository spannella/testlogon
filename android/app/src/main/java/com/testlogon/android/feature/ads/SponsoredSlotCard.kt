package com.testlogon.android.feature.ads

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
import androidx.compose.runtime.LaunchedEffect
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

/** FE-161 — test tags for the reusable sponsored slot card. */
object SponsoredSlotTestTags {
    const val CARD = "sponsored_slot_card"
    const val LABEL = "sponsored_slot_label"
    fun card(unitId: String) = "sponsored_slot_card_$unitId"
}

/**
 * FE-161 (EPIC G) — a REUSABLE sponsored slot card for interleaved list surfaces (market / token
 * discovery). Renders the served creative (AsyncImage) + headline / CTA + an always-present, clear
 * "Sponsored" disclosure chip alongside the server [SponsoredProduct.sponsorLabel]. Fires an
 * IMPRESSION exactly once when first composed (keyed on the unit id) via [onImpression], and a CLICK
 * on tap via [onClick] (the caller opens the cta_url through the shared ad-click path). Both beacons
 * ride the one /ui/ads/track money-path through AdTrackRepository. Degrade-safe: a missing image just
 * renders a placeholder box; a blank sponsor label still shows the fixed "Sponsored" chip.
 */
@Composable
fun SponsoredSlotCard(
    product: SponsoredProduct,
    onImpression: () -> Unit,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // Impression fires once when the slot first enters composition (i.e. becomes visible in the list).
    LaunchedEffect(product.unitId) { onImpression() }
    Card(
        modifier = modifier
            .fillMaxWidth()
            .testTag(SponsoredSlotTestTags.CARD)
            .testTag(SponsoredSlotTestTags.card(product.unitId))
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
        ),
    ) {
        Column(Modifier.padding(12.dp)) {
            SponsoredDisclosure(product.sponsorLabel)
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
                    val headline = product.tracking.headline?.takeIf { it.isNotBlank() } ?: product.name
                    Text(
                        text = headline,
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = product.ctaText,
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }
        }
    }
}

/**
 * The always-present "Sponsored" disclosure. The fixed chip is the legally-required mark; when the
 * server carries a distinct [sponsorLabel] (e.g. the advertiser name) that is NOT just the word
 * "Sponsored", it is shown alongside so the viewer sees who paid.
 */
@Composable
private fun SponsoredDisclosure(sponsorLabel: String) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Surface(
            color = MaterialTheme.colorScheme.tertiaryContainer,
            contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
            shape = RoundedCornerShape(4.dp),
            modifier = Modifier.testTag(SponsoredSlotTestTags.LABEL),
        ) {
            Text(
                text = "Sponsored",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            )
        }
        val extra = sponsorLabel.trim()
        if (extra.isNotBlank() && !extra.equals("Sponsored", ignoreCase = true)) {
            Text(
                text = extra,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}
