package com.testlogon.android.feature.markets.book

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.exchange.OrderBook
import com.testlogon.android.data.exchange.OrderBookLevel

private val UpColor = Color(0xFF16A34A)
private val DownColor = Color(0xFFDC2626)
private const val MAX_ROWS = 20

/**
 * L2 depth order-book viewer, dependency-free. Renders:
 *  - a cumulative depth chart (bids left/green, asks right/red) as a stepped area,
 *  - a ladder: asks (red, ascending) above a centred spread/mid row above bids (green, descending),
 *    each row showing price | size | cumulative size with a depth bar whose width tracks cumulative
 *    size (asks grow up from the spread, bids grow down).
 *
 * Reads whatever the current [book] holds (REST snapshot up to depth 50 or the live depth-10 frame).
 * Prices/qty are raw integers scaled by [priceScaler] (>=1) for display.
 */
@Composable
fun OrderBookL2(
    book: OrderBook?,
    priceScaler: Long,
    modifier: Modifier = Modifier,
) {
    if (book == null || (book.asks.isEmpty() && book.bids.isEmpty())) {
        Text("No order book.", style = MaterialTheme.typography.bodySmall)
        return
    }
    val scaler = priceScaler.coerceAtLeast(1L)

    // asks ascending from the spread; take nearest MAX_ROWS then reverse so the spread is centred.
    val asks = book.asks.take(MAX_ROWS)
    val bids = book.bids.take(MAX_ROWS)

    // Cumulative sizes (from the spread outward).
    val askCum = cumulative(asks)
    val bidCum = cumulative(bids)
    val maxCum = maxOf(askCum.lastOrNull() ?: 1L, bidCum.lastOrNull() ?: 1L).coerceAtLeast(1L)

    Column(modifier = modifier.fillMaxWidth().testTag("order_book_l2")) {
        DepthChart(asks = asks, bids = bids, askCum = askCum, bidCum = bidCum, maxCum = maxCum)

        // header
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp, horizontal = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            LabelCell("Price")
            LabelCell("Size")
            LabelCell("Total")
        }

        // asks: nearest-to-spread at the BOTTOM, so reverse for top-down render
        asks.indices.reversed().forEach { i ->
            L2Row(
                price = asks[i].price,
                size = asks[i].qty,
                cum = askCum[i],
                maxCum = maxCum,
                color = DownColor,
                scaler = scaler,
            )
        }

        SpreadRow(book = book, scaler = scaler)

        bids.indices.forEach { i ->
            L2Row(
                price = bids[i].price,
                size = bids[i].qty,
                cum = bidCum[i],
                maxCum = maxCum,
                color = UpColor,
                scaler = scaler,
            )
        }
    }
}

@Composable
private fun DepthChart(
    asks: List<OrderBookLevel>,
    bids: List<OrderBookLevel>,
    askCum: List<Long>,
    bidCum: List<Long>,
    maxCum: Long,
    modifier: Modifier = Modifier,
) {
    Canvas(
        modifier = modifier
            .fillMaxWidth()
            .height(90.dp)
            .padding(vertical = 4.dp)
            .testTag("depth_chart"),
    ) {
        val midX = size.width / 2f
        val h = size.height

        fun yOf(cum: Long): Float = h * (1f - (cum.toFloat() / maxCum.toFloat()))

        // bids: from mid going LEFT
        if (bids.isNotEmpty()) {
            val path = Path().apply {
                moveTo(midX, h)
                var x = midX
                bidCum.forEachIndexed { i, c ->
                    val nx = midX - (midX * ((i + 1).toFloat() / bids.size))
                    val y = yOf(c)
                    lineTo(x, y)
                    lineTo(nx, y)
                    x = nx
                }
                lineTo(x, h)
                close()
            }
            drawPath(path, UpColor.copy(alpha = 0.35f))
        }

        // asks: from mid going RIGHT
        if (asks.isNotEmpty()) {
            val path = Path().apply {
                moveTo(midX, h)
                var x = midX
                askCum.forEachIndexed { i, c ->
                    val nx = midX + (midX * ((i + 1).toFloat() / asks.size))
                    val y = yOf(c)
                    lineTo(x, y)
                    lineTo(nx, y)
                    x = nx
                }
                lineTo(x, h)
                close()
            }
            drawPath(path, DownColor.copy(alpha = 0.35f))
        }

        // centre divider
        drawLine(Color(0x33888888), Offset(midX, 0f), Offset(midX, h), strokeWidth = 1f)
    }
}

@Composable
private fun L2Row(
    price: Long,
    size: Long,
    cum: Long,
    maxCum: Long,
    color: Color,
    scaler: Long,
) {
    val fraction = (cum.toFloat() / maxCum.toFloat()).coerceIn(0f, 1f)
    Box(modifier = Modifier.fillMaxWidth().height(22.dp)) {
        Box(
            modifier = Modifier
                .fillMaxWidth(fraction)
                .height(22.dp)
                .align(Alignment.CenterEnd)
                .background(color.copy(alpha = 0.14f)),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            ValueCell(fmt(price.toDouble() / scaler), color = color)
            ValueCell(size.toString(), color = null)
            ValueCell(cum.toString(), color = null, muted = true)
        }
    }
}

@Composable
private fun SpreadRow(book: OrderBook, scaler: Long) {
    val spread = book.spread
    val mid = book.mid
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
            .padding(vertical = 6.dp, horizontal = 8.dp)
            .testTag("book_spread"),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = mid?.let { "Mid " + fmt(it / scaler) } ?: "Mid -",
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            fontFamily = FontFamily.Monospace,
        )
        Text(
            text = "Spread " + (spread?.let { fmt(it.toDouble() / scaler) } ?: "-"),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontFamily = FontFamily.Monospace,
        )
    }
}

@Composable
private fun LabelCell(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        fontFamily = FontFamily.Monospace,
    )
}

@Composable
private fun ValueCell(text: String, color: Color?, muted: Boolean = false) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = color ?: if (muted) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
        fontFamily = FontFamily.Monospace,
    )
}

/** Running cumulative sum of the level quantities (index i = sum of levels 0..i). */
private fun cumulative(levels: List<OrderBookLevel>): List<Long> {
    var run = 0L
    return levels.map { run += it.qty; run }
}

private fun fmt(v: Double): String {
    val whole = v == v.toLong().toDouble()
    return if (whole) String.format(java.util.Locale.US, "%,d", v.toLong())
    else String.format(java.util.Locale.US, "%,.2f", v)
}
