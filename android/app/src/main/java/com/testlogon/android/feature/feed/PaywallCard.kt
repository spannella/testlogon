package com.testlogon.android.feature.feed

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
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
}

enum class PaywallStyle { Feed, Detail }

/**
 * AND-101 — locked-content affordance shown IN PLACE OF protected body/media. Shows a lock icon, a
 * short label, the formatted price (when present), and an "Unlock" CTA. M2 is display-only: the CTA
 * invokes [onUnlockClick] which is a non-purchasing stub (TODO(AND-E24)). The card carries a single
 * merged contentDescription and exposes NO protected text (the domain post is already redacted).
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
        append("Locked post. ").append(label).append(". ").append(ctaText).append(".")
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

private fun labelFor(locked: Paywall.Locked): String = when (locked.lockType) {
    LockType.TIP_LOTTERY -> "Tip to unlock"
    LockType.FIXED_PRICE, LockType.UNKNOWN -> "Paid content"
}
