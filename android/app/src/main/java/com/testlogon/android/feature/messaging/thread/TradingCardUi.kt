@file:OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.messaging.TradingCardModel
import java.util.Locale

/** FE-101 test tags. */
object TradingCardTestTags {
    const val MARKET_CARD = "thread_market_card"
    const val MARKET_TRADE = "thread_market_card_trade"
    const val POSITION_CARD = "thread_position_card"
}

/**
 * FE-101 — live market data resolved at render time for a shared market card (price/change/spark are
 * NOT carried on the wire; the ViewModel refreshes them into [ThreadUiState.marketCards]). All fields
 * null while loading, so the card shows the ticker immediately and fills price/change/spark when ready.
 */
data class MarketCardLive(
    val lastPriceDisplay: Double? = null,
    val changePct: Double? = null,
    val spark: List<Float> = emptyList(),
    val priceLabel: String? = null,
)

/**
 * FE-101 — Market card: ticker + live price + change % + a mini sparkline + a Trade button that opens
 * the order-ticket (Symbol detail) screen for the symbol. Mirrors the Markets-list row treatment.
 */
@Composable
fun MarketCard(
    card: TradingCardModel.MarketCard,
    live: MarketCardLive,
    onTrade: (symbolId: Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    val up = (live.changePct ?: 0.0) >= 0.0
    val cd = "Market ${card.symbol}" + (live.changePct?.let { ", ${pct(it)}" } ?: "")
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = modifier
            .widthIn(max = 300.dp)
            .testTag(TradingCardTestTags.MARKET_CARD)
            .semantics { contentDescription = cd },
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("Market", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(card.symbol, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                MiniSparkline(points = live.spark, up = up, modifier = Modifier.width(72.dp).height(28.dp))
            }
            Row(Modifier.fillMaxWidth().padding(top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    live.priceLabel ?: live.lastPriceDisplay?.let { fmtPrice(it) } ?: "—",
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    live.changePct?.let { pct(it) } ?: "--",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (live.changePct == null) MaterialTheme.colorScheme.onSurfaceVariant else if (up) MarketColors.Up else MarketColors.Down,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Button(
                onClick = { onTrade(card.symbolId) },
                modifier = Modifier.fillMaxWidth().padding(top = 10.dp).testTag(TradingCardTestTags.MARKET_TRADE),
            ) { Text("Trade") }
        }
    }
}

/**
 * FE-102 — Position card: renders ONLY the fields the sender's disclosure permitted (the withheld
 * ones arrive null and are simply not shown), plus "shared by <owner>" attribution and directional
 * color. The disclosure logic itself lives in the pure TradingCardModel; this only renders.
 */
@Composable
fun PositionCard(
    card: TradingCardModel.PositionCard,
    onTrade: (symbolId: Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    val long = card.isLong
    val directional = when (long) { true -> MarketColors.Up; false -> MarketColors.Down; else -> MaterialTheme.colorScheme.onSurfaceVariant }
    val sideLabel = when (long) { true -> "LONG"; false -> "SHORT"; else -> null }
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = modifier
            .widthIn(max = 300.dp)
            .testTag(TradingCardTestTags.POSITION_CARD)
            .semantics { contentDescription = "Position ${card.symbol}" },
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("Position", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(card.symbol, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                sideLabel?.let {
                    Text(it, style = MaterialTheme.typography.labelLarge, color = directional, fontWeight = FontWeight.Bold)
                }
            }
            // The headline P&L figure: the percentage the disclosure exposes (uPnL% or ROI%).
            val headlinePct = card.pnlPct ?: card.roiPct
            headlinePct?.let {
                Text(
                    (if (card.pnlPct != null) "P&L " else "ROI ") + pct(it),
                    style = MaterialTheme.typography.headlineSmall,
                    color = if (it >= 0) MarketColors.Up else MarketColors.Down,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
            // FULL-disclosure detail rows (each present only when the field was permitted/sent).
            card.qty?.let { DetailRow("Size", it.toString()) }
            card.entryPrice?.let { DetailRow("Entry", it.toString()) }
            card.markPrice?.let { DetailRow("Mark", it.toString()) }
            card.liquidationPrice?.let { DetailRow("Liq.", it.toString()) }
            card.unrealizedPnl?.let { DetailRow("uPnL", it.toString(), if (it >= 0) MarketColors.Up else MarketColors.Down) }
            Text(
                "Shared by ${card.owner.ifBlank { "a trader" }}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 8.dp),
            )
            Button(
                onClick = { onTrade(card.symbolId) },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            ) { Text("View market") }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String, valueColor: Color? = null) {
    Row(Modifier.fillMaxWidth().padding(top = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodySmall, color = valueColor ?: MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Medium)
    }
}

/** A compact filled-area sparkline (mirrors the Markets-list Sparkline; self-contained Canvas). */
@Composable
private fun MiniSparkline(points: List<Float>, up: Boolean, modifier: Modifier = Modifier) {
    val color = if (up) MarketColors.Up else MarketColors.Down
    Canvas(modifier = modifier) {
        val n = points.size
        if (n < 2) {
            val y = size.height / 2f
            drawLine(MarketColors.Border, Offset(0f, y), Offset(size.width, y), strokeWidth = 1.5f)
            return@Canvas
        }
        val min = points.min()
        val max = points.max()
        val range = (max - min).let { if (it == 0f) 1f else it }
        val dx = size.width / (n - 1)
        fun px(i: Int) = dx * i
        fun py(v: Float) = size.height * (1f - (v - min) / range)
        val line = Path().apply {
            moveTo(px(0), py(points[0]))
            for (i in 1 until n) lineTo(px(i), py(points[i]))
        }
        val fill = Path().apply {
            addPath(line)
            lineTo(px(n - 1), size.height)
            lineTo(px(0), size.height)
            close()
        }
        drawPath(fill, Brush.verticalGradient(listOf(color.copy(alpha = 0.22f), Color.Transparent)))
        drawPath(line, color = color, style = Stroke(width = 2f, cap = StrokeCap.Round))
    }
}

private fun pct(v: Double): String = String.format(Locale.US, "%+.2f%%", v)
private fun fmtPrice(v: Double): String = String.format(Locale.US, "%,.2f", v)
