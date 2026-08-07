package com.testlogon.android.feature.markets.chart

import android.graphics.Paint
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.exchange.Candle
import com.testlogon.android.feature.markets.ui.MarketColors
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.roundToInt

private val UpColor = MarketColors.Up
private val DownColor = MarketColors.Down
private val GridColor = MarketColors.SurfaceAlt
private val AxisTextColor = MarketColors.TextSecondary
private val CrosshairColor = MarketColors.TextSecondary
private val AccentColor = MarketColors.Accent

/** Supported chart timeframes. [seconds] is the candle interval requested from the backend. */
enum class Timeframe(val label: String, val seconds: Int) {
    M1("1m", 60),
    M5("5m", 300),
    M15("15m", 900),
    H1("1h", 3_600),
    D1("1d", 86_400),
}

private const val MIN_VISIBLE = 12
private const val MAX_VISIBLE = 200
private const val DEFAULT_VISIBLE = 60

/**
 * TradingView-style interactive candlestick chart, dependency-free (pure Compose [Canvas] + the
 * platform [android.graphics.Canvas] for axis text). Dark exchange palette. Supports horizontal pan,
 * pinch-zoom, a draggable crosshair with an O/H/L/C tooltip card, a right price axis, a bottom time
 * axis, a volume sub-pane, and a dashed accent last-price line with a price tag.
 *
 * When [showTimeframes] is false the built-in chip row is hidden (the host supplies its own control).
 */
@Composable
fun CandlestickChart(
    candles: List<Candle>,
    priceScaler: Long,
    modifier: Modifier = Modifier,
    selected: Timeframe = Timeframe.M1,
    showTimeframes: Boolean = true,
    onTimeframeSelected: (Timeframe) -> Unit = {},
) {
    Column(modifier = modifier) {
        if (showTimeframes) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Timeframe.entries.forEach { tf ->
                    FilterChip(
                        selected = tf == selected,
                        onClick = { onTimeframeSelected(tf) },
                        label = { Text(tf.label) },
                        modifier = Modifier.testTag("tf_chip_${tf.label}"),
                    )
                }
            }
        }
        CandlestickCanvas(
            candles = candles,
            priceScaler = priceScaler.coerceAtLeast(1L),
            modifier = Modifier.fillMaxWidth().height(260.dp).testTag("candle_chart"),
        )
    }
}

@Composable
private fun CandlestickCanvas(
    candles: List<Candle>,
    priceScaler: Long,
    modifier: Modifier,
) {
    if (candles.isEmpty()) {
        Box(modifier = modifier, contentAlignment = Alignment.Center) {
            Text("No candles.", color = MarketColors.TextFaint)
        }
        return
    }

    val density = LocalDensity.current
    val axisTextPx = with(density) { 10.dp.toPx() }
    val rightAxisWidthPx = with(density) { 58.dp.toPx() }
    val bottomAxisHeightPx = with(density) { 16.dp.toPx() }

    var visibleCount by remember { mutableStateOf(DEFAULT_VISIBLE.coerceAtMost(candles.size)) }
    var scrollOffset by remember { mutableFloatStateOf(0f) }
    var crosshairIdx by remember { mutableStateOf(-1) }
    var crosshairX by remember { mutableFloatStateOf(-1f) }
    var crosshairY by remember { mutableFloatStateOf(-1f) }

    Box(modifier = modifier) {
        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height(260.dp)
                .pointerInput(candles.size) {
                    detectTransformGestures { _, pan, zoom, _ ->
                        if (abs(zoom - 1f) > 0.001f) {
                            val next = (visibleCount / zoom).roundToInt()
                            visibleCount = next.coerceIn(MIN_VISIBLE, MAX_VISIBLE.coerceAtMost(candles.size))
                        }
                        val slotPx = (size.width - rightAxisWidthPx) / visibleCount.coerceAtLeast(1)
                        if (slotPx > 0f) {
                            scrollOffset = (scrollOffset - pan.x / slotPx)
                                .coerceIn(0f, (candles.size - visibleCount).coerceAtLeast(0).toFloat())
                        }
                    }
                }
                .pointerInput(candles.size, visibleCount) {
                    detectDragGestures(
                        onDragStart = { off -> crosshairX = off.x; crosshairY = off.y },
                        onDragEnd = { crosshairIdx = -1; crosshairX = -1f; crosshairY = -1f },
                        onDragCancel = { crosshairIdx = -1; crosshairX = -1f; crosshairY = -1f },
                    ) { change, _ ->
                        crosshairX = change.position.x
                        crosshairY = change.position.y
                    }
                },
        ) {
            val plotWidth = size.width - rightAxisWidthPx
            val totalHeight = size.height - bottomAxisHeightPx
            val priceHeight = totalHeight * 0.74f
            val volTop = priceHeight + totalHeight * 0.03f
            val volHeight = totalHeight - volTop

            val startIdx = (candles.size - visibleCount - scrollOffset.roundToInt())
                .coerceIn(0, (candles.size - 1).coerceAtLeast(0))
            val endIdx = (startIdx + visibleCount).coerceAtMost(candles.size)
            val window = candles.subList(startIdx, endIdx)
            if (window.isEmpty()) return@Canvas

            val minLow = window.minOf { it.low }
            val maxHigh = window.maxOf { it.high }
            val range = (maxHigh - minLow).coerceAtLeast(1L)
            val maxVol = window.maxOf { it.volume }.coerceAtLeast(1L)

            val n = window.size
            val slot = plotWidth / n
            val bodyWidth = (slot * 0.62f).coerceAtLeast(1f)

            fun yOfPrice(price: Long): Float =
                priceHeight * (1f - ((price - minLow).toFloat() / range.toFloat()))

            val gridPaint = Paint().apply {
                color = AxisTextColor.value.toInt()
                textSize = axisTextPx
                isAntiAlias = true
                textAlign = Paint.Align.LEFT
            }
            val ticks = 5
            for (t in 0..ticks) {
                val frac = t.toFloat() / ticks
                val y = priceHeight * frac
                drawLine(GridColor, Offset(0f, y), Offset(plotWidth, y), strokeWidth = 1f)
                val price = maxHigh - (range * frac).toLong()
                drawContext.canvas.nativeCanvas.drawText(
                    formatAxisPrice(price.toDouble() / priceScaler),
                    plotWidth + 6f,
                    (y + axisTextPx / 2f).coerceIn(axisTextPx, priceHeight),
                    gridPaint,
                )
            }

            val timeFmt = SimpleDateFormat("HH:mm", Locale.US)
            val vTicks = 4
            for (t in 0..vTicks) {
                val frac = t.toFloat() / vTicks
                val x = plotWidth * frac
                drawLine(GridColor, Offset(x, 0f), Offset(x, priceHeight), strokeWidth = 1f)
                val wi = ((n - 1) * frac).roundToInt().coerceIn(0, n - 1)
                val label = timeFmt.format(Date(window[wi].tsStartNs / 1_000_000L))
                gridPaint.textAlign = when (t) {
                    0 -> Paint.Align.LEFT
                    vTicks -> Paint.Align.RIGHT
                    else -> Paint.Align.CENTER
                }
                drawContext.canvas.nativeCanvas.drawText(label, x.coerceIn(0f, plotWidth), size.height - 2f, gridPaint)
            }
            gridPaint.textAlign = Paint.Align.LEFT

            window.forEachIndexed { i, c ->
                val cx = slot * i + slot / 2f
                val up = c.close >= c.open
                val color = if (up) UpColor else DownColor
                drawLine(color, Offset(cx, yOfPrice(c.high)), Offset(cx, yOfPrice(c.low)), strokeWidth = 1.5f)
                val yOpen = yOfPrice(c.open)
                val yClose = yOfPrice(c.close)
                val top = minOf(yOpen, yClose)
                val bodyH = abs(yClose - yOpen).coerceAtLeast(1.5f)
                drawRect(color, Offset(cx - bodyWidth / 2f, top), Size(bodyWidth, bodyH))
                val vFrac = c.volume.toFloat() / maxVol.toFloat()
                val vBarH = volHeight * vFrac
                drawRect(
                    color.copy(alpha = 0.45f),
                    Offset(cx - bodyWidth / 2f, volTop + (volHeight - vBarH)),
                    Size(bodyWidth, vBarH),
                )
            }

            // ---- last-price dashed accent line + tag ----
            val last = window.last()
            val yLast = yOfPrice(last.close)
            val dash = PathEffect.dashPathEffect(floatArrayOf(10f, 8f), 0f)
            drawLine(AccentColor, Offset(0f, yLast), Offset(plotWidth, yLast), strokeWidth = 1.5f, pathEffect = dash)
            drawRect(AccentColor, Offset(plotWidth, (yLast - axisTextPx).coerceIn(0f, priceHeight)), Size(rightAxisWidthPx, axisTextPx * 2f))
            val tagPaint = Paint().apply {
                color = android.graphics.Color.BLACK
                textSize = axisTextPx
                isAntiAlias = true
                isFakeBoldText = true
                textAlign = Paint.Align.LEFT
            }
            drawContext.canvas.nativeCanvas.drawText(
                formatAxisPrice(last.close.toDouble() / priceScaler),
                plotWidth + 6f,
                (yLast + axisTextPx / 2f).coerceIn(axisTextPx, priceHeight),
                tagPaint,
            )

            // ---- crosshair + tooltip card ----
            if (crosshairX in 0f..plotWidth && crosshairY in 0f..totalHeight) {
                val hoverIdx = (crosshairX / slot).toInt().coerceIn(0, n - 1)
                crosshairIdx = startIdx + hoverIdx
                val snapX = slot * hoverIdx + slot / 2f
                val chDash = PathEffect.dashPathEffect(floatArrayOf(6f, 6f), 0f)
                drawLine(CrosshairColor, Offset(snapX, 0f), Offset(snapX, totalHeight), strokeWidth = 1f, pathEffect = chDash)
                drawLine(CrosshairColor, Offset(0f, crosshairY), Offset(plotWidth, crosshairY), strokeWidth = 1f, pathEffect = chDash)
                drawCrosshairTooltip(window[hoverIdx], priceScaler, axisTextPx, snapX, plotWidth)
            } else {
                crosshairIdx = -1
            }
        }
    }
}

private fun DrawScope.drawCrosshairTooltip(
    c: Candle,
    priceScaler: Long,
    textPx: Float,
    snapX: Float,
    plotWidth: Float,
) {
    val timeFmt = SimpleDateFormat("MMM d HH:mm", Locale.US)
    val up = c.close >= c.open
    val bodyColor = if (up) MarketColors.Up else MarketColors.Down
    val lines = listOf(
        "O " + formatAxisPrice(c.open.toDouble() / priceScaler),
        "H " + formatAxisPrice(c.high.toDouble() / priceScaler),
        "L " + formatAxisPrice(c.low.toDouble() / priceScaler),
        "C " + formatAxisPrice(c.close.toDouble() / priceScaler),
        "Vol " + c.volume.toString(),
    )
    val pad = 10f
    val lineH = textPx * 1.5f
    val boxW = 132f
    val boxH = lineH * (lines.size + 1) + pad
    val boxX = (snapX + 12f).coerceIn(0f, max(0f, plotWidth - boxW))
    val boxY = 8f
    // shadow
    drawRect(Color(0x66000000), Offset(boxX + 2f, boxY + 3f), Size(boxW, boxH))
    // card
    drawRect(MarketColors.SurfaceAlt, Offset(boxX, boxY), Size(boxW, boxH))
    // border
    drawRect(MarketColors.Border, Offset(boxX, boxY), Size(boxW, 1f))
    drawRect(MarketColors.Border, Offset(boxX, boxY + boxH - 1f), Size(boxW, 1f))
    drawRect(MarketColors.Border, Offset(boxX, boxY), Size(1f, boxH))
    drawRect(MarketColors.Border, Offset(boxX + boxW - 1f, boxY), Size(1f, boxH))

    val headPaint = Paint().apply {
        color = MarketColors.TextSecondary.value.toInt()
        textSize = textPx * 0.95f
        isAntiAlias = true
        textAlign = Paint.Align.LEFT
    }
    drawContext.canvas.nativeCanvas.drawText(
        timeFmt.format(Date(c.tsStartNs / 1_000_000L)),
        boxX + pad, boxY + lineH, headPaint,
    )
    val valPaint = Paint().apply {
        color = bodyColor.value.toInt()
        textSize = textPx
        isAntiAlias = true
        textAlign = Paint.Align.LEFT
    }
    lines.forEachIndexed { i, line ->
        drawContext.canvas.nativeCanvas.drawText(line, boxX + pad, boxY + lineH * (i + 2), valPaint)
    }
}

private fun formatAxisPrice(v: Double): String {
    val whole = v == v.toLong().toDouble()
    return if (whole) String.format(Locale.US, "%,d", v.toLong())
    else String.format(Locale.US, "%,.2f", v)
}
