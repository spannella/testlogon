package com.testlogon.android.feature.markets.book

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.testlogon.android.data.exchange.OrderBook
import com.testlogon.android.data.exchange.OrderBookLevel
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.markets.ui.MarketColors

private val UpColor = MarketColors.Up
private val DownColor = MarketColors.Down
private const val MAX_ROWS = 12

/** Order-book layout. LADDER = asks-top / spread / bids-bottom; COLUMNS = bids-left / asks-right. */
enum class BookStyle(val label: String) { LADDER("Ladder"), COLUMNS("Columns") }

/**
 * L2 depth order-book viewer, dependency-free, dark exchange palette. Two layouts via [style]:
 *  - LADDER: asks (red) on top, a centred mid/spread bar, then bids (green) below, each row with a
 *    right-anchored cumulative-depth bar plus a compact depth curve above the ladder.
 *  - COLUMNS: bids (green) on the left and asks (red) on the right, best-of-book adjacent to a centre
 *    divider, each row's depth bar growing outward from the centre, with the spread bar spanning top.
 * Prices/qty are raw integers scaled by [priceScaler]; [lastUp] tints the mid by last-trade direction.
 */
@Composable
fun OrderBookL2(
    book: OrderBook?,
    priceScaler: Long,
    modifier: Modifier = Modifier,
    style: BookStyle = BookStyle.LADDER,
    lastUp: Boolean? = null,
    onPriceClick: (price: Long, side: OrderSide) -> Unit = { _, _ -> },
) {
    if (book == null || (book.asks.isEmpty() && book.bids.isEmpty())) {
        Text("No order book.", color = MarketColors.TextFaint, fontSize = 12.sp, modifier = modifier)
        return
    }
    val scaler = priceScaler.coerceAtLeast(1L)
    val asks = book.asks.take(MAX_ROWS)
    val bids = book.bids.take(MAX_ROWS)
    val askCum = cumulative(asks)
    val bidCum = cumulative(bids)
    val maxCum = maxOf(askCum.lastOrNull() ?: 1L, bidCum.lastOrNull() ?: 1L).coerceAtLeast(1L)

    when (style) {
        BookStyle.LADDER -> Column(modifier = modifier.fillMaxWidth().testTag("order_book_l2")) {
            DepthChart(asks = asks, bids = bids, askCum = askCum, bidCum = bidCum, maxCum = maxCum)

            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp, horizontal = 4.dp)) {
                LabelCell("Price", TextAlign.Start, 1.2f)
                LabelCell("Size", TextAlign.End, 1f)
                LabelCell("Total", TextAlign.End, 1f)
            }

            // asks: nearest-to-spread at the BOTTOM, so reverse for top-down render
            asks.indices.reversed().forEach { i ->
                L2Row(price = asks[i].price, size = asks[i].qty, cum = askCum[i], maxCum = maxCum, color = DownColor, fill = MarketColors.DownFill, scaler = scaler, onClick = { onPriceClick(asks[i].price, OrderSide.BUY) })
            }

            SpreadRow(book = book, scaler = scaler, lastUp = lastUp)

            bids.indices.forEach { i ->
                L2Row(price = bids[i].price, size = bids[i].qty, cum = bidCum[i], maxCum = maxCum, color = UpColor, fill = MarketColors.UpFill, scaler = scaler, onClick = { onPriceClick(bids[i].price, OrderSide.SELL) })
            }
        }

        BookStyle.COLUMNS -> Column(modifier = modifier.fillMaxWidth().testTag("order_book_columns")) {
            SpreadRow(book = book, scaler = scaler, lastUp = lastUp)
            Row(modifier = Modifier.fillMaxWidth().height(intrinsicRows(asks.size, bids.size))) {
                // Bids on the left: price sits toward the centre, depth grows leftward from the divider.
                Column(modifier = Modifier.weight(1f)) {
                    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp, horizontal = 6.dp)) {
                        LabelCell("Size", TextAlign.Start, 1f)
                        LabelCell("Bid", TextAlign.End, 1f)
                    }
                    bids.indices.forEach { i ->
                        BookColRow(price = bids[i].price, size = bids[i].qty, cum = bidCum[i], maxCum = maxCum, color = UpColor, fill = MarketColors.UpFill, scaler = scaler, bidSide = true, onClick = { onPriceClick(bids[i].price, OrderSide.SELL) })
                    }
                }
                Box(modifier = Modifier.width(1.dp).fillMaxHeight().background(MarketColors.Border))
                // Asks on the right: price toward the centre, depth grows rightward from the divider.
                Column(modifier = Modifier.weight(1f)) {
                    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp, horizontal = 6.dp)) {
                        LabelCell("Ask", TextAlign.Start, 1f)
                        LabelCell("Size", TextAlign.End, 1f)
                    }
                    asks.indices.forEach { i ->
                        BookColRow(price = asks[i].price, size = asks[i].qty, cum = askCum[i], maxCum = maxCum, color = DownColor, fill = MarketColors.DownFill, scaler = scaler, bidSide = false, onClick = { onPriceClick(asks[i].price, OrderSide.BUY) })
                    }
                }
            }
        }
    }
}

/** Approx height so the centre divider spans the taller column (header + N rows). */
private fun intrinsicRows(asks: Int, bids: Int) = (34 + 21 * maxOf(asks, bids)).dp

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
            .height(64.dp)
            .padding(vertical = 4.dp)
            .testTag("depth_chart"),
    ) {
        val midX = size.width / 2f
        val h = size.height
        fun yOf(cum: Long): Float = h * (1f - (cum.toFloat() / maxCum.toFloat()))

        if (bids.isNotEmpty()) {
            val path = Path().apply {
                moveTo(midX, h)
                var x = midX
                bidCum.forEachIndexed { i, c ->
                    val nx = midX - (midX * ((i + 1).toFloat() / bids.size))
                    val y = yOf(c)
                    lineTo(x, y); lineTo(nx, y); x = nx
                }
                lineTo(x, h); close()
            }
            drawPath(path, Brush.verticalGradient(listOf(UpColor.copy(alpha = 0.40f), UpColor.copy(alpha = 0.06f))))
        }
        if (asks.isNotEmpty()) {
            val path = Path().apply {
                moveTo(midX, h)
                var x = midX
                askCum.forEachIndexed { i, c ->
                    val nx = midX + (midX * ((i + 1).toFloat() / asks.size))
                    val y = yOf(c)
                    lineTo(x, y); lineTo(nx, y); x = nx
                }
                lineTo(x, h); close()
            }
            drawPath(path, Brush.verticalGradient(listOf(DownColor.copy(alpha = 0.40f), DownColor.copy(alpha = 0.06f))))
        }
        drawLine(MarketColors.Border, Offset(midX, 0f), Offset(midX, h), strokeWidth = 1f)
    }
}

@Composable
private fun L2Row(
    price: Long,
    size: Long,
    cum: Long,
    maxCum: Long,
    color: Color,
    fill: Color,
    scaler: Long,
    onClick: () -> Unit = {},
) {
    val fraction = (cum.toFloat() / maxCum.toFloat()).coerceIn(0f, 1f)
    Box(modifier = Modifier.fillMaxWidth().height(21.dp).clickable(onClick = onClick)) {
        Box(
            modifier = Modifier
                .fillMaxWidth(fraction)
                .height(21.dp)
                .align(Alignment.CenterEnd)
                .background(fill),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            NumCell(fmt(price.toDouble() / scaler), color = color, align = TextAlign.Start, weight = 1.2f, bold = true)
            NumCell(size.toString(), color = MarketColors.TextPrimary, align = TextAlign.End, weight = 1f)
            NumCell(cum.toString(), color = MarketColors.TextSecondary, align = TextAlign.End, weight = 1f)
        }
    }
}

/** One row of the COLUMNS layout. [bidSide] mirrors the depth bar + cell order about the centre. */
@Composable
private fun BookColRow(
    price: Long,
    size: Long,
    cum: Long,
    maxCum: Long,
    color: Color,
    fill: Color,
    scaler: Long,
    bidSide: Boolean,
    onClick: () -> Unit = {},
) {
    val fraction = (cum.toFloat() / maxCum.toFloat()).coerceIn(0f, 1f)
    Box(modifier = Modifier.fillMaxWidth().height(21.dp).clickable(onClick = onClick)) {
        Box(
            modifier = Modifier
                .fillMaxWidth(fraction)
                .height(21.dp)
                .align(if (bidSide) Alignment.CenterEnd else Alignment.CenterStart)
                .background(fill),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (bidSide) {
                NumCell(size.toString(), color = MarketColors.TextSecondary, align = TextAlign.Start, weight = 1f)
                NumCell(fmt(price.toDouble() / scaler), color = color, align = TextAlign.End, weight = 1f, bold = true)
            } else {
                NumCell(fmt(price.toDouble() / scaler), color = color, align = TextAlign.Start, weight = 1f, bold = true)
                NumCell(size.toString(), color = MarketColors.TextSecondary, align = TextAlign.End, weight = 1f)
            }
        }
    }
}

@Composable
private fun SpreadRow(book: OrderBook, scaler: Long, lastUp: Boolean?) {
    val spread = book.spread
    val mid = book.mid
    val midColor = when (lastUp) {
        true -> MarketColors.Up
        false -> MarketColors.Down
        null -> MarketColors.TextPrimary
    }
    val spreadPct = if (spread != null && mid != null && mid != 0.0) spread / scaler / mid * 100.0 else null
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MarketColors.SurfaceAlt)
            .padding(vertical = 7.dp, horizontal = 6.dp)
            .testTag("book_spread"),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = mid?.let { fmt(it / scaler) } ?: "--",
            color = midColor,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace,
            fontSize = 15.sp,
        )
        Text(
            text = "Spread " + (spread?.let { fmt(it.toDouble() / scaler) } ?: "-") +
                (spreadPct?.let { "  (" + String.format("%.2f", it) + "%)" } ?: ""),
            color = MarketColors.TextSecondary,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
        )
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.LabelCell(text: String, align: TextAlign, weight: Float) {
    Text(
        text = text,
        color = MarketColors.TextSecondary,
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        textAlign = align,
        modifier = Modifier.weight(weight),
    )
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.NumCell(
    text: String,
    color: Color,
    align: TextAlign,
    weight: Float,
    bold: Boolean = false,
) {
    Text(
        text = text,
        color = color,
        fontFamily = FontFamily.Monospace,
        fontWeight = if (bold) FontWeight.SemiBold else FontWeight.Normal,
        fontSize = 12.sp,
        textAlign = align,
        modifier = Modifier.weight(weight),
    )
}

private fun cumulative(levels: List<OrderBookLevel>): List<Long> {
    var run = 0L
    return levels.map { run += it.qty; run }
}

private fun fmt(v: Double): String {
    val whole = v == v.toLong().toDouble()
    return if (whole) String.format(java.util.Locale.US, "%,d", v.toLong())
    else String.format(java.util.Locale.US, "%,.2f", v)
}
