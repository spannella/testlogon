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
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.data.feed.LockType
import com.testlogon.android.data.feed.Paywall

/** Stable test tags for the paywall card (AND-101). */
object PaywallTestTags {
    const val CARD = "paywall_card"
    const val CTA = "paywall_cta"
    const val LABEL = "paywall_label"
    // #19 — the blurred/teaser media placeholder + the prominent price pill.
    const val TEASER = "paywall_teaser"
    const val PRICE_PILL = "paywall_price_pill"
}

enum class PaywallStyle { Feed, Detail }

/**
 * AND-101 / #19 — locked-content affordance shown IN PLACE OF protected body/media. A tip-/price-locked
 * post is now visually UNMISTAKABLE: a tall blurred-teaser placeholder (diagonal gradient + a large
 * centered lock + a "Locked" pill and price pill) stands in for the gated media, above the lock label
 * and the unlock/tip CTA — matching the locked-message styling. M2 is display-only: the CTA invokes
 * [onUnlockClick] (deferred purchase, TODO(AND-E24)). The card carries a single merged
 * contentDescription and exposes NO protected text (the domain post is already redacted at the mapper).
 */
@Composable
fun PaywallCard(
    locked: Paywall.Locked,
    onUnlockClick: () -> Unit,
    modifier: Modifier = Modifier,
    style: PaywallStyle = PaywallStyle.Feed,
    // AND-177 — unlock flow state driving the CTA (spinner / disabled / sold-out / payments-unavailable).
    unlockState: UnlockState = UnlockState.Idle,
) {
    val priceText = PriceFormatter.format(locked.priceCents)
    val label = labelFor(locked)
    val ctaText = if (priceText != null) "Unlock for $priceText" else "Unlock"
    val inProgress = unlockState is UnlockState.InProgress
    val soldOut = locked.unlockLimitReached || unlockState is UnlockState.SoldOut
    val ctaEnabled = !inProgress && !soldOut && !locked.lockExpired
    val statusMessage: String? = when (unlockState) {
        is UnlockState.PaymentsUnavailable -> stringResource(R.string.paywall_payments_unavailable)
        is UnlockState.Failed -> unlockState.message
        else -> null
    }
    val cd = buildString {
        append("Locked post. ").append(label).append(". ")
        if (priceText != null) append(priceText).append(". ")
        append(ctaText).append(".")
    }
    val padding = if (style == PaywallStyle.Detail) 24.dp else 16.dp

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
            .padding(padding)
            .testTag(PaywallTestTags.CARD)
            .clearAndSetSemantics { contentDescription = cd },
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // #19 — blurred/teaser media stand-in so a locked post is obviously gated (not a normal post).
        LockedTeaser(label = label, priceText = priceText, expired = locked.lockExpired)

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
                modifier = Modifier.padding(start = 8.dp).testTag(PaywallTestTags.LABEL),
            )
        }
        if (locked.lockExpired) {
            Text(
                text = "This offer has expired.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else if (soldOut) {
            Text(
                text = stringResource(R.string.paywall_sold_out),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (statusMessage != null) {
            Text(
                text = statusMessage,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        TlButton(
            text = if (inProgress) stringResource(R.string.paywall_unlocking) else ctaText,
            onClick = onUnlockClick,
            enabled = ctaEnabled,
            loading = inProgress,
            modifier = Modifier.testTag(PaywallTestTags.CTA),
        )
    }
}

/**
 * #19 — a blurred/teaser placeholder shown where the gated media would be. A diagonal gradient (the
 * "blur" stand-in, since the real media is redacted server-side and never reaches the client) with a
 * large centered lock and overlaid "Locked"/price pills, so a tip-locked post reads as locked at a
 * glance. Decorative only (the card's merged contentDescription describes the lock to a11y).
 */
@Composable
private fun LockedTeaser(label: String, priceText: String?, expired: Boolean) {
    val scheme = MaterialTheme.colorScheme
    val gradient = Brush.linearGradient(
        colors = listOf(
            scheme.primary.copy(alpha = 0.22f),
            scheme.secondary.copy(alpha = 0.16f),
            scheme.surfaceVariant.copy(alpha = 0.65f),
        ),
    )
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(140.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(gradient)
            .testTag(PaywallTestTags.TEASER),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            Icons.Filled.Lock,
            contentDescription = null,
            tint = scheme.onSurfaceVariant.copy(alpha = 0.85f),
            modifier = Modifier.size(44.dp),
        )
        // Top-start "Locked" pill.
        Pill(
            text = if (expired) "Expired" else "Locked",
            modifier = Modifier.align(Alignment.TopStart).padding(8.dp),
        )
        // Top-end price pill (when a price is known).
        if (priceText != null) {
            Pill(
                text = priceText,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(8.dp)
                    .testTag(PaywallTestTags.PRICE_PILL),
            )
        }
        // Bottom caption restating the lock kind.
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = scheme.onSurfaceVariant,
            modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 10.dp),
        )
    }
}

/** A small rounded pill used for the Locked / price overlays on the teaser. */
@Composable
private fun Pill(text: String, modifier: Modifier = Modifier) {
    Surface(
        color = MaterialTheme.colorScheme.scrim.copy(alpha = 0.6f),
        shape = RoundedCornerShape(50),
        modifier = modifier,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Filled.Lock,
                contentDescription = null,
                tint = androidx.compose.ui.graphics.Color.White,
                modifier = Modifier.padding(start = 8.dp).size(12.dp),
            )
            Text(
                text = text,
                style = MaterialTheme.typography.labelSmall,
                color = androidx.compose.ui.graphics.Color.White,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(start = 4.dp, end = 10.dp, top = 4.dp, bottom = 4.dp),
            )
        }
    }
}

private fun labelFor(locked: Paywall.Locked): String = when (locked.lockType) {
    LockType.TIP_LOTTERY -> "Tip to unlock"
    LockType.FIXED_PRICE, LockType.UNKNOWN -> "Paid content"
}
