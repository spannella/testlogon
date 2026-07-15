package com.testlogon.android.feature.feed

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.ui.input.TlButton

/** Stable test tags for the subscriber-only lock card (SUB-E3-2). */
object SubscriberLockTestTags {
    const val CARD = "subscriber_lock_card"
    const val CTA = "subscriber_lock_cta"
    const val LABEL = "subscriber_lock_label"
    const val TEASER = "subscriber_lock_teaser"
}

/**
 * SUB-E3-2 - locked-content affordance shown IN PLACE OF a subscriber-only post/body that the server
 * withheld from a non-subscriber (Paywall.SubscriberLocked). Mirrors the tip/price [PaywallCard]
 * styling (blurred teaser + lock + label + CTA) but the CTA is "Subscribe to unlock", opening the
 * creator subscribe flow (SubscriptionTiersDest) rather than a per-post purchase. The card exposes NO
 * protected text (the domain post is already redacted at the mapper); it re-locks automatically when
 * the subscription lapses because the server re-marks the post locked.
 */
@Composable
fun SubscriberLockCard(
    creatorName: String,
    onSubscribeClick: () -> Unit,
    modifier: Modifier = Modifier,
    style: PaywallStyle = PaywallStyle.Feed,
    // SUBX-31: when the post requires a specific tier LEVEL, name that tier and
    // upsell to it (rather than a generic "subscribe"). 0/null = binary any-sub.
    requiredTierName: String? = null,
    requiredTierLevel: Int = 0,
) {
    val tier = requiredTierName?.takeIf { it.isNotBlank() }
    val label = if (tier != null) "$tier tier required" else "Subscribers only"
    val sub = if (tier != null) {
        "This post is for $creatorName's $tier tier. Subscribe at that tier to unlock it."
    } else {
        "Subscribe to $creatorName to unlock this content."
    }
    val cd = if (tier != null) {
        "Locked post. Requires the $tier tier. Subscribe to $creatorName at the $tier tier to unlock."
    } else {
        "Locked post. Subscribers only. Subscribe to $creatorName to unlock."
    }
    val padding = if (style == PaywallStyle.Detail) 24.dp else 16.dp

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
            .padding(padding)
            .testTag(SubscriberLockTestTags.CARD)
            .clearAndSetSemantics { contentDescription = cd },
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        LockedTeaser()
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Filled.Lock,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
            Text(
                text = label,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(start = 8.dp).testTag(SubscriberLockTestTags.LABEL),
            )
        }
        Text(
            text = sub,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        TlButton(
            text = if (tier != null) "Subscribe to $tier" else "Subscribe to unlock",
            onClick = onSubscribeClick,
            modifier = Modifier.testTag(SubscriberLockTestTags.CTA),
        )
    }
}

/** A blurred/teaser placeholder standing in for the withheld subscriber-only media. Decorative only. */
@Composable
private fun LockedTeaser() {
    val scheme = MaterialTheme.colorScheme
    val gradient = Brush.linearGradient(
        colors = listOf(
            scheme.primary.copy(alpha = 0.22f),
            scheme.tertiary.copy(alpha = 0.16f),
            scheme.surfaceVariant.copy(alpha = 0.65f),
        ),
    )
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(140.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(gradient)
            .testTag(SubscriberLockTestTags.TEASER),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            Icons.Filled.Lock,
            contentDescription = null,
            tint = scheme.onSurfaceVariant.copy(alpha = 0.85f),
            modifier = Modifier.size(44.dp),
        )
        Pill(text = "Subscribers only", modifier = Modifier.align(Alignment.TopStart).padding(8.dp))  // teaser overlay (tier named on the card below)
    }
}

/** A small rounded pill used for the Subscribers-only overlay on the teaser. */
@Composable
private fun Pill(text: String, modifier: Modifier = Modifier) {
    Surface(
        color = MaterialTheme.colorScheme.scrim.copy(alpha = 0.6f),
        shape = RoundedCornerShape(50),
        modifier = modifier,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Filled.Star,
                contentDescription = null,
                tint = Color.White,
                modifier = Modifier.padding(start = 8.dp).size(12.dp),
            )
            Text(
                text = text,
                style = MaterialTheme.typography.labelSmall,
                color = Color.White,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(start = 4.dp, end = 10.dp, top = 4.dp, bottom = 4.dp),
            )
        }
    }
}
