package com.testlogon.android.feature.markets.chart

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.testlogon.android.data.exchange.OrderBook
import com.testlogon.android.feature.markets.ui.MarketColors
import java.util.Locale

private const val MAX_LEVELS = 40

/**
 * Full market-depth chart drawn on a Compose [Canvas], dependency-free (no charting library). Renders
 * the two cumulative-depth curves from an [OrderBook] as mirrored step areas about the mid price:
 * bids in green filling from the mid leftward (best bid nearest the centre), asks in red filling
 * rightward. The mid/spread is marked with a vertical divider + a header readout. A touch crosshair
 * (drag or tap) reports the price under the finger and the cumulative size available to that price.
 *
 * All pure axis/curve math lives in [DepthMath] (unit-tested); this composable only maps the model
 * into pixels and paints it. Prices are raw integer ticks scaled by [priceScaler] for display.
 */
@Composable
fun DepthChart(
    book: OrderBook?,
    priceScaler: Long,
    modifier: Modifier = Modifier,
) {
    val model = remember(book) { DepthMath.model(book, maxLevels = MAX_LEVELS) }
    val scaler = priceScaler.coerceAtLeast(1L)

    if (model.isEmpty) {
        Text(
            "No depth available.",
            color = MarketColors.TextFaint,
            fontSize = 12.sp,
            modifier = modifier.padding(horizontal = 12.dp, vertical = 24.dp).testTag("depth_chart_empty"),
        )
        return
    }

    // Crosshair as a horizontal fraction across the price axis (null = hidden). Kept as a fraction so
    // it stays valid across canvas-size changes; resolved to a price/cum readout via DepthMath.
    var crossFrac by remember { mutableStateOf<Float?>(null) }
    val density = LocalDensity.current

    Box(modifier = modifier.fillMaxWidth().testTag("depth_chart_full")) {
        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height(220.dp)
                .pointerInput(model) {
                    detectDragGestures(
                        onDragStart = { crossFrac = (it.x / size.width).coerceIn(0f, 1f) },
                        onDragEnd = { crossFrac = null },
                        onDragCancel = { crossFrac = null },
                        onDrag = { change, _ -> crossFrac = (change.position.x / size.width).coerceIn(0f, 1f) },
                    )
                }
                .pointerInput(model) {
                    detectTapGestures(
                        onPress = {
                            crossFrac = (it.x / size.width).coerceIn(0f, 1f)
                            tryAwaitRelease()
                            crossFrac = null
                        },
                    )
                },
        ) {
            drawDepth(model = model)
            crossFrac?.let { f -> drawCrosshair(model = model, fracX = f, densityScale = density.density) }
        }

        DepthHeader(model = model, scaler = scaler, crossFrac = crossFrac)
    }
}

/** Draw the mirrored cumulative-depth step areas + the mid divider. */
private fun DrawScope.drawDepth(model: DepthMath.DepthModel) {
    val w = size.width
    val h = size.height
    val priceSpan = (model.maxPrice - model.minPrice).toDouble().coerceAtLeast(1.0)
    fun xOf(price: Long): Float = (((price - model.minPrice).toDouble() / priceSpan) * w).toFloat().coerceIn(0f, w)
    fun yOf(cum: Long): Float = (h * (1f - (cum.toFloat() / model.maxCum.toFloat()))).coerceIn(0f, h)

    // Bids: best bid is nearest the mid; walk outward to lower prices (leftward). Build a step area
    // anchored to the baseline so the fill reads as classic accumulated depth.
    if (model.bids.isNotEmpty()) {
        val pts = model.bids // best-first (descending price)
        val fill = Path()
        val line = Path()
        val startX = xOf(pts.first().price)
        fill.moveTo(startX, h)
        var firstLine = true
        var prevX = startX
        pts.forEach { p ->
            val x = xOf(p.price)
            val y = yOf(p.cumQty)
            // step: horizontal to this price at the previous height, then vertical to the new cum
            fill.lineTo(prevX, y)
            fill.lineTo(x, y)
            if (firstLine) { line.moveTo(prevX, y); firstLine = false } else line.lineTo(prevX, y)
            line.lineTo(x, y)
            prevX = x
        }
        fill.lineTo(prevX, h)
        fill.close()
        drawPath(fill, Brush.verticalGradient(listOf(MarketColors.Up.copy(alpha = 0.38f), MarketColors.Up.copy(alpha = 0.05f))))
        drawPath(line, MarketColors.Up, style = Stroke(width = 2f))
    }

    // Asks: best ask nearest the mid; walk outward to higher prices (rightward).
    if (model.asks.isNotEmpty()) {
        val pts = model.asks // best-first (ascending price)
        val fill = Path()
        val line = Path()
        val startX = xOf(pts.first().price)
        fill.moveTo(startX, h)
        var firstLine = true
        var prevX = startX
        pts.forEach { p ->
            val x = xOf(p.price)
            val y = yOf(p.cumQty)
            fill.lineTo(prevX, y)
            fill.lineTo(x, y)
            if (firstLine) { line.moveTo(prevX, y); firstLine = false } else line.lineTo(prevX, y)
            line.lineTo(x, y)
            prevX = x
        }
        fill.lineTo(prevX, h)
        fill.close()
        drawPath(fill, Brush.verticalGradient(listOf(MarketColors.Down.copy(alpha = 0.38f), MarketColors.Down.copy(alpha = 0.05f))))
        drawPath(line, MarketColors.Down, style = Stroke(width = 2f))
    }

    // Mid divider.
    val midPrice = model.mid ?: ((model.minPrice + model.maxPrice) / 2.0)
    val midX = (((midPrice - model.minPrice) / priceSpan) * w).toFloat().coerceIn(0f, w)
    drawLine(
        color = MarketColors.TextFaint,
        start = Offset(midX, 0f),
        end = Offset(midX, h),
        strokeWidth = 1.5f,
        pathEffect = PathEffect.dashPathEffect(floatArrayOf(6f, 6f)),
    )
}

/** Draw the crosshair vertical line + a small dot at the depth curve under the finger. */
private fun DrawScope.drawCrosshair(
    model: DepthMath.DepthModel,
    fracX: Float,
    densityScale: Float,
) {
    val cross = DepthMath.crosshairAt(model, fracX) ?: return
    val w = size.width
    val h = size.height
    val x = (fracX.coerceIn(0f, 1f) * w)
    val color = if (cross.isBid) MarketColors.Up else MarketColors.Down
    drawLine(color = color.copy(alpha = 0.7f), start = Offset(x, 0f), end = Offset(x, h), strokeWidth = 1f)
    val y = (h * (1f - (cross.cumQty.toFloat() / model.maxCum.toFloat()))).coerceIn(0f, h)
    drawCircle(color = color, radius = 4f * densityScale, center = Offset(x, y))
}

/**
 * Overlaid header: mid/spread on the left and a live crosshair readout (price + cumulative size) on
 * the right when the user is touching the chart. Drawn as Compose text (crisp) rather than on canvas.
 */
@Composable
private fun DepthHeader(model: DepthMath.DepthModel, scaler: Long, crossFrac: Float?) {
    val cross = crossFrac?.let { DepthMath.crosshairAt(model, it) }
    androidx.compose.foundation.layout.Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalArrangement = androidx.compose.foundation.layout.Arrangement.SpaceBetween,
    ) {
        val mid = model.mid
        val spread = model.spread
        Text(
            text = "Mid " + (mid?.let { fmtPrice(it / scaler) } ?: "--") +
                (spread?.let { "  Spread " + fmtPrice(it.toDouble() / scaler) } ?: ""),
            color = MarketColors.TextSecondary,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
        )
        if (cross != null) {
            val c = if (cross.isBid) MarketColors.Up else MarketColors.Down
            Text(
                text = fmtPrice(cross.price.toDouble() / scaler) + "  x " + cross.cumQty.toString(),
                color = c,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
            )
        }
    }
}

private fun fmtPrice(v: Double): String {
    val whole = v == v.toLong().toDouble()
    return if (whole) String.format(Locale.US, "%,d", v.toLong())
    else String.format(Locale.US, "%,.2f", v)
}
