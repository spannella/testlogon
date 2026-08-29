@file:OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.messaging.CryptoTransferModel
import java.util.Locale

/** FE-111 test tags. */
object CryptoTransferTestTags {
    const val CARD = "thread_crypto_transfer_card"
    const val STATUS = "thread_crypto_transfer_status"
}

/**
 * FE-111 — Crypto-transfer card: asset + amount (+ fiat estimate), from→to attribution, a status
 * badge (pending/completed/failed), and sent-vs-received directional styling. The direction, fiat
 * math, and status label all come from the pure [CryptoTransferModel]; this only renders.
 *
 * [viewerSub] is the current user's sub, used to decide SENT vs RECEIVED framing.
 */
@Composable
fun CryptoTransferCard(
    card: CryptoTransferModel.CryptoTransfer,
    viewerSub: String?,
    modifier: Modifier = Modifier,
) {
    val direction = CryptoTransferModel.transferDirection(card, viewerSub)
    val sent = direction == CryptoTransferModel.Direction.SENT
    val accent = if (sent) MarketColors.Down else MarketColors.Up  // out = red-ish, in = green-ish
    val fiatCents = CryptoTransferModel.fiatEquivalentCents(card.asset, card.amount)
    val headline = (if (sent) "-" else "+") + "${card.amount} ${card.asset}"
    val counterparty = if (sent) card.toName.ifBlank { "recipient" } else card.fromName.ifBlank { "sender" }
    val relation = if (sent) "To $counterparty" else "From $counterparty"
    val cd = (if (sent) "Sent" else "Received") + " ${card.amount} ${card.asset}, ${CryptoTransferModel.statusLabel(card.status)}"

    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = modifier
            .testTag(CryptoTransferTestTags.CARD)
            .semantics { contentDescription = cd },
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (sent) "Sent crypto" else "Received crypto",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f),
                )
                StatusBadge(card.status)
            }
            Text(
                headline,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = accent,
                modifier = Modifier.padding(top = 4.dp),
            )
            fiatCents?.let {
                Text(
                    "~ " + fmtUsd(it),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
            Text(
                relation,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.padding(top = 6.dp),
            )
            card.memo?.takeIf { it.isNotBlank() }?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
        }
    }
}

@Composable
private fun StatusBadge(status: CryptoTransferModel.Status) {
    val (bg, fg) = when (status) {
        CryptoTransferModel.Status.PENDING -> MaterialTheme.colorScheme.tertiaryContainer to MaterialTheme.colorScheme.onTertiaryContainer
        CryptoTransferModel.Status.COMPLETE -> MarketColors.Up.copy(alpha = 0.18f) to MarketColors.Up
        CryptoTransferModel.Status.FAILED -> MarketColors.Down.copy(alpha = 0.18f) to MarketColors.Down
    }
    Text(
        CryptoTransferModel.statusLabel(status),
        style = MaterialTheme.typography.labelSmall,
        color = fg,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier
            .testTag(CryptoTransferTestTags.STATUS)
            .clip(RoundedCornerShape(50))
            .background(bg)
            .padding(horizontal = 8.dp, vertical = 2.dp),
    )
}

/** Format integer USD cents as "$1,250.00". */
private fun fmtUsd(cents: Long): String =
    "$" + String.format(Locale.US, "%,.2f", cents / 100.0)
