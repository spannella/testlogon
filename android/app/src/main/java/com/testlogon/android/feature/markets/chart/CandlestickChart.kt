package com.testlogon.android.feature.markets.chart

import android.graphics.Paint
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
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
import androidx.compose.ui.unit.sp
import com.testlogon.android.data.exchange.Candle
import com.testlogon.android.feature.markets.ui.MarketColors
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.roundToInt
import kotlin.math.sqrt

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

/** How the price series is drawn. */
enum class ChartType(val label: String) {
    CANDLES("Candles"),
    LINE("Line"),
    AREA("Area"),
}

/** Optional bottom oscillator sub-pane. Mutually exclusive. */
enum class Oscillator(val label: String) {
    NONE("Off"),
    RSI("RSI"),
    MACD("MACD"),
}

private val RsiColor = Color(0xFFB388FF)    // violet
private val MacdColor = Color(0xFF4C8DFF)   // blue
private val SignalColor = Color(0xFFFF9F40) // orange
private val VolMaColor = Color(0xFFE0A83A)  // muted gold (volume MA)
private const val VOL_MA_PERIOD = 20

private val DrawingColor = Color(0xFF26C6DA)   // cyan (user drawings)
private val FibColor = Color(0xFFF0B90B)       // gold (fib levels)
private val FIB_LEVELS = listOf(0.0, 0.236, 0.382, 0.5, 0.618, 0.786, 1.0)

/** User chart-drawing tools. NONE = normal interaction (pan/zoom/crosshair). */
enum class DrawingTool(val label: String, val anchors: Int) {
    NONE("—", 0),
    HLINE("Line", 1),   // horizontal price line
    TREND("Trend", 2),  // segment between two points
    FIB("Fib", 2),      // retracement between two prices
    RECT("Rect", 2),    // rectangle zone
}

/** One placed anchor: a bar timestamp (X) + a price (Y), so drawings stay put across pan/zoom. */
data class Anchor(val tsNs: Long, val price: Double)

/** A committed drawing: [b] is null for a single-anchor tool (HLINE). */
data class ChartDrawing(val id: Long, val tool: DrawingTool, val a: Anchor, val b: Anchor? = null)

/**
 * A moving-average overlay: [period] candles, [sma] true = simple, false = exponential, drawn in
 * [color]. The Binance-style defaults are MA7 / MA25 / MA99 (all simple) on the close price.
 */
private data class MaSpec(val label: String, val period: Int, val sma: Boolean, val color: Color)

private val MA_SPECS = listOf(
    MaSpec("MA7", 7, sma = true, color = Color(0xFFF0B90B)),   // amber
    MaSpec("MA25", 25, sma = true, color = Color(0xFFE457C6)), // magenta
    MaSpec("MA99", 99, sma = true, color = Color(0xFF8C7CFF)), // violet
)

// Bollinger Bands (20, 2σ) and session VWAP — price-pane overlays, off by default.
private const val BB_PERIOD = 20
private const val BB_MULT = 2.0
private val BbColor = Color(0xFF4C8DFF)   // blue
private val VwapColor = Color(0xFFFF9F40) // orange

/** Precomputed overlay series aligned 1:1 with the full candle list. */
private data class Overlays(
    val ma: List<List<Double?>>,
    val bbMid: List<Double?>,
    val bbUpper: List<Double?>,
    val bbLower: List<Double?>,
    val vwap: List<Double?>,
    val rsi: List<Double?>,
    val macdLine: List<Double?>,
    val macdSignal: List<Double?>,
    val macdHist: List<Double?>,
    val volMa: List<Double?>,
)

private const val MIN_VISIBLE = 12
private const val MAX_VISIBLE = 200
private const val DEFAULT_VISIBLE = 60

/**
 * TradingView-style interactive price chart, dependency-free (pure Compose [Canvas] + the platform
 * [android.graphics.Canvas] for axis text). Dark exchange palette. Supports horizontal pan, pinch-
 * zoom, double-tap-to-reset, a draggable crosshair with an O/H/L/C tooltip card, moving-average
 * overlays (MA7/25/99, toggle via the legend), candle / line / area render modes, a right price
 * axis, an interval-aware bottom time axis, a volume sub-pane, and a dashed last-price line + tag.
 *
 * When [showTimeframes] is false the built-in chip row is hidden (the host supplies its own control).
 */
@Composable
fun CandlestickChart(
    candles: List<Candle>,
    priceScaler: Long,
    modifier: Modifier = Modifier,
    selected: Timeframe = Timeframe.M1,
    chartType: ChartType = ChartType.CANDLES,
    oscillator: Oscillator = Oscillator.NONE,
    drawings: List<ChartDrawing> = emptyList(),
    activeTool: DrawingTool = DrawingTool.NONE,
    onCommitDrawing: (ChartDrawing) -> Unit = {},
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
        val chartHeight = if (oscillator == Oscillator.NONE) 260.dp else 340.dp
        CandlestickCanvas(
            candles = candles,
            priceScaler = priceScaler.coerceAtLeast(1L),
            timeframe = selected,
            chartType = chartType,
            oscillator = oscillator,
            drawings = drawings,
            activeTool = activeTool,
            onCommitDrawing = onCommitDrawing,
            chartHeight = chartHeight,
            modifier = Modifier.fillMaxWidth().height(chartHeight).testTag("candle_chart"),
        )
    }
}

@Composable
private fun CandlestickCanvas(
    candles: List<Candle>,
    priceScaler: Long,
    timeframe: Timeframe,
    chartType: ChartType,
    oscillator: Oscillator,
    drawings: List<ChartDrawing>,
    activeTool: DrawingTool,
    onCommitDrawing: (ChartDrawing) -> Unit,
    chartHeight: androidx.compose.ui.unit.Dp,
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

    var visibleCount by remember { mutableStateOf(DEFAULT_VISIBLE) }
    var scrollOffset by remember { mutableFloatStateOf(0f) }
    var crosshairIdx by remember { mutableStateOf(-1) }
    var crosshairX by remember { mutableFloatStateOf(-1f) }
    var crosshairY by remember { mutableFloatStateOf(-1f) }
    // Per-MA visibility, toggled from the legend chips. Defaults all on.
    val maVisible = remember { mutableStateListOf(true, true, true) }
    var bbOn by remember { mutableStateOf(false) }
    var vwapOn by remember { mutableStateOf(false) }
    // First anchor of a 2-point drawing awaiting its second tap.
    var pendingAnchor by remember { mutableStateOf<Anchor?>(null) }
    if (activeTool == DrawingTool.NONE) pendingAnchor = null

    // All overlays computed over the FULL series (so the visible window's left edge uses prior bars);
    // recomputed only when the candle list changes. Each series is aligned 1:1 with [candles].
    val overlays = remember(candles) {
        val closes = candles.map { it.close.toDouble() }
        val ma = MA_SPECS.map { spec -> if (spec.sma) sma(closes, spec.period) else ema(closes, spec.period) }
        val mid = sma(closes, BB_PERIOD)
        val sd = stdDev(closes, BB_PERIOD)
        val upper = mid.mapIndexed { i, m -> if (m != null && sd[i] != null) m + BB_MULT * sd[i]!! else null }
        val lower = mid.mapIndexed { i, m -> if (m != null && sd[i] != null) m - BB_MULT * sd[i]!! else null }
        val (macdLine, macdSignal, macdHist) = macd(closes)
        val volMa = sma(candles.map { it.volume.toDouble() }, VOL_MA_PERIOD)
        Overlays(ma, mid, upper, lower, vwap(candles), rsi(closes, 14), macdLine, macdSignal, macdHist, volMa)
    }
    val maSeries = overlays.ma

    fun resetView() {
        visibleCount = DEFAULT_VISIBLE.coerceIn(MIN_VISIBLE, MAX_VISIBLE)
        scrollOffset = 0f
    }

    val timeFmt = remember(timeframe) {
        SimpleDateFormat(
            when {
                timeframe.seconds >= 86_400 -> "MMM d"
                timeframe.seconds >= 3_600 -> "dd HH:mm"
                else -> "HH:mm"
            },
            Locale.US,
        )
    }

    // Map a tap in the price pane to a (timestamp, price) anchor for drawing tools.
    fun tapToAnchor(w: Float, h: Float, tapX: Float, tapY: Float): Anchor? {
        if (candles.isEmpty()) return null
        val totalH = h - bottomAxisHeightPx
        val hasOsc = oscillator != Oscillator.NONE
        val priceH = totalH * (if (hasOsc) 0.56f else 0.74f)
        val plotW = w - rightAxisWidthPx
        val vc = visibleCount.coerceIn(1, candles.size)
        val start = (candles.size - vc - scrollOffset.roundToInt()).coerceIn(0, (candles.size - 1).coerceAtLeast(0))
        val end = (start + vc).coerceAtMost(candles.size)
        val win = candles.subList(start, end)
        if (win.isEmpty() || plotW <= 0f) return null
        val minLow = win.minOf { it.low }
        val range = (win.maxOf { it.high } - minLow).coerceAtLeast(1L)
        val slotW = plotW / win.size
        val hoverIdx = (tapX / slotW).toInt().coerceIn(0, win.size - 1)
        val ts = candles[start + hoverIdx].tsStartNs
        val frac = (1f - (tapY / priceH)).coerceIn(0f, 1f).toDouble()
        return Anchor(ts, minLow + frac * range.toDouble())
    }

    val gestureModifier = if (activeTool == DrawingTool.NONE) {
        Modifier
            .pointerInput(candles.size) {
                detectTapGestures(onDoubleTap = { resetView() })
            }
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
            }
    } else {
        Modifier.pointerInput(activeTool, candles.size, visibleCount, scrollOffset.roundToInt()) {
            detectTapGestures { off ->
                val anchor = tapToAnchor(size.width.toFloat(), size.height.toFloat(), off.x, off.y)
                    ?: return@detectTapGestures
                if (activeTool.anchors == 1) {
                    onCommitDrawing(ChartDrawing(id = System.nanoTime(), tool = activeTool, a = anchor))
                } else {
                    val first = pendingAnchor
                    if (first == null) {
                        pendingAnchor = anchor
                    } else {
                        onCommitDrawing(ChartDrawing(id = System.nanoTime(), tool = activeTool, a = first, b = anchor))
                        pendingAnchor = null
                    }
                }
            }
        }
    }

    Box(modifier = modifier) {
        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height(chartHeight)
                .then(gestureModifier),
        ) {
            val plotWidth = size.width - rightAxisWidthPx
            val totalHeight = size.height - bottomAxisHeightPx
            val hasOsc = oscillator != Oscillator.NONE
            val priceHeight = totalHeight * (if (hasOsc) 0.56f else 0.74f)
            val volTop = priceHeight + totalHeight * 0.03f
            val volHeight = if (hasOsc) totalHeight * 0.14f else totalHeight - volTop
            val oscTop = volTop + volHeight + totalHeight * 0.03f
            val oscHeight = if (hasOsc) (totalHeight - oscTop).coerceAtLeast(0f) else 0f

            val vc = visibleCount.coerceIn(1, candles.size.coerceAtLeast(1))
            val startIdx = (candles.size - vc - scrollOffset.roundToInt())
                .coerceIn(0, (candles.size - 1).coerceAtLeast(0))
            val endIdx = (startIdx + vc).coerceAtMost(candles.size)
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

            fun yOfPriceD(price: Double): Float =
                (priceHeight * (1f - ((price - minLow) / range.toDouble()).toFloat()))
                    .coerceIn(0f, priceHeight)

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

            // ---- price series: candles, or a line/area over closes ----
            when (chartType) {
                ChartType.CANDLES -> {
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
                    }
                }
                ChartType.LINE, ChartType.AREA -> {
                    val lineColor = AccentColor
                    if (chartType == ChartType.AREA) {
                        // Fill under the close line down to the price-pane baseline.
                        val path = androidx.compose.ui.graphics.Path()
                        path.moveTo(slot / 2f, priceHeight)
                        window.forEachIndexed { i, c ->
                            path.lineTo(slot * i + slot / 2f, yOfPrice(c.close))
                        }
                        path.lineTo(slot * (n - 1) + slot / 2f, priceHeight)
                        path.close()
                        drawPath(path, lineColor.copy(alpha = 0.14f))
                    }
                    for (i in 0 until n - 1) {
                        val x1 = slot * i + slot / 2f
                        val x2 = slot * (i + 1) + slot / 2f
                        drawLine(
                            lineColor,
                            Offset(x1, yOfPrice(window[i].close)),
                            Offset(x2, yOfPrice(window[i + 1].close)),
                            strokeWidth = 2f,
                        )
                    }
                }
            }

            // ---- volume sub-pane (always drawn, colored by candle direction) ----
            window.forEachIndexed { i, c ->
                val cx = slot * i + slot / 2f
                val up = c.close >= c.open
                val color = if (up) UpColor else DownColor
                val vFrac = c.volume.toFloat() / maxVol.toFloat()
                val vBarH = volHeight * vFrac
                drawRect(
                    color.copy(alpha = 0.45f),
                    Offset(cx - bodyWidth / 2f, volTop + (volHeight - vBarH)),
                    Size(bodyWidth, vBarH),
                )
            }
            // volume moving-average line over the volume pane
            run {
                var prev: Offset? = null
                for (i in 0 until n) {
                    val v = overlays.volMa.getOrNull(startIdx + i)
                    if (v == null) { prev = null; continue }
                    val frac = (v / maxVol.toDouble()).toFloat().coerceIn(0f, 1f)
                    val cur = Offset(slot * i + slot / 2f, volTop + volHeight * (1f - frac))
                    val p = prev
                    if (p != null) drawLine(VolMaColor, p, cur, strokeWidth = 1.2f)
                    prev = cur
                }
            }

            // ---- Bollinger Bands (fill + upper/lower/mid) ----
            if (bbOn) {
                val up = overlays.bbUpper
                val lo = overlays.bbLower
                val mid = overlays.bbMid
                // faint fill between the bands
                val fill = androidx.compose.ui.graphics.Path()
                var started = false
                for (i in 0 until n) {
                    val gi = startIdx + i
                    val u = up.getOrNull(gi) ?: continue
                    if (!started) { fill.moveTo(slot * i + slot / 2f, yOfPriceD(u)); started = true }
                    else fill.lineTo(slot * i + slot / 2f, yOfPriceD(u))
                }
                for (i in (n - 1) downTo 0) {
                    val gi = startIdx + i
                    val l = lo.getOrNull(gi) ?: continue
                    fill.lineTo(slot * i + slot / 2f, yOfPriceD(l))
                }
                if (started) { fill.close(); drawPath(fill, BbColor.copy(alpha = 0.08f)) }
                fun drawBand(series: List<Double?>, dashed: Boolean) {
                    var prev: Offset? = null
                    val effect = if (dashed) PathEffect.dashPathEffect(floatArrayOf(6f, 6f), 0f) else null
                    for (i in 0 until n) {
                        val v = series.getOrNull(startIdx + i)
                        if (v == null) { prev = null; continue }
                        val cur = Offset(slot * i + slot / 2f, yOfPriceD(v))
                        val p = prev
                        if (p != null) drawLine(BbColor, p, cur, strokeWidth = 1f, pathEffect = effect)
                        prev = cur
                    }
                }
                drawBand(up, dashed = false)
                drawBand(lo, dashed = false)
                drawBand(mid, dashed = true)
            }

            // ---- VWAP ----
            if (vwapOn) {
                var prev: Offset? = null
                for (i in 0 until n) {
                    val v = overlays.vwap.getOrNull(startIdx + i)
                    if (v == null) { prev = null; continue }
                    val cur = Offset(slot * i + slot / 2f, yOfPriceD(v))
                    val p = prev
                    if (p != null) drawLine(VwapColor, p, cur, strokeWidth = 1.5f)
                    prev = cur
                }
            }

            // ---- moving-average overlays (over the price pane) ----
            maSeries.forEachIndexed { specIdx, series ->
                if (!maVisible.getOrElse(specIdx) { true }) return@forEachIndexed
                val color = MA_SPECS[specIdx].color
                var prev: Offset? = null
                for (i in 0 until n) {
                    val gi = startIdx + i
                    val v = series.getOrNull(gi)
                    if (v == null) { prev = null; continue }
                    val cur = Offset(slot * i + slot / 2f, yOfPriceD(v))
                    val p = prev
                    if (p != null) drawLine(color, p, cur, strokeWidth = 1.5f)
                    prev = cur
                }
            }

            // ---- oscillator sub-pane (RSI or MACD) ----
            if (hasOsc && oscHeight > 4f) {
                val labelPaint = Paint().apply {
                    color = AxisTextColor.value.toInt(); textSize = axisTextPx; isAntiAlias = true; textAlign = Paint.Align.LEFT
                }
                when (oscillator) {
                    Oscillator.RSI -> {
                        fun yR(v: Double) = oscTop + oscHeight * (1f - (v / 100.0).toFloat())
                        val guide = PathEffect.dashPathEffect(floatArrayOf(4f, 6f), 0f)
                        drawLine(GridColor, Offset(0f, yR(70.0)), Offset(plotWidth, yR(70.0)), strokeWidth = 1f, pathEffect = guide)
                        drawLine(GridColor, Offset(0f, yR(30.0)), Offset(plotWidth, yR(30.0)), strokeWidth = 1f, pathEffect = guide)
                        var prev: Offset? = null
                        var lastVal: Double? = null
                        for (i in 0 until n) {
                            val v = overlays.rsi.getOrNull(startIdx + i)
                            if (v == null) { prev = null; continue }
                            val cur = Offset(slot * i + slot / 2f, yR(v))
                            val p = prev
                            if (p != null) drawLine(RsiColor, p, cur, strokeWidth = 1.5f)
                            prev = cur; lastVal = v
                        }
                        drawContext.canvas.nativeCanvas.drawText(
                            "RSI 14" + (lastVal?.let { "  " + String.format(Locale.US, "%.1f", it) } ?: ""),
                            2f, oscTop + axisTextPx, labelPaint,
                        )
                    }
                    Oscillator.MACD -> {
                        var absMax = 0.0
                        for (i in 0 until n) {
                            val gi = startIdx + i
                            listOf(overlays.macdLine.getOrNull(gi), overlays.macdSignal.getOrNull(gi), overlays.macdHist.getOrNull(gi))
                                .forEach { it?.let { v -> if (abs(v) > absMax) absMax = abs(v) } }
                        }
                        if (absMax <= 0.0) absMax = 1.0
                        fun yM(v: Double) = oscTop + oscHeight * (0.5f - (v / (2 * absMax)).toFloat())
                        drawLine(GridColor, Offset(0f, yM(0.0)), Offset(plotWidth, yM(0.0)), strokeWidth = 1f)
                        for (i in 0 until n) {
                            val h = overlays.macdHist.getOrNull(startIdx + i) ?: continue
                            val cx = slot * i + slot / 2f
                            val yZero = yM(0.0); val yH = yM(h)
                            val top = minOf(yZero, yH); val hgt = abs(yH - yZero).coerceAtLeast(1f)
                            val col = if (h >= 0) UpColor else DownColor
                            drawRect(col.copy(alpha = 0.5f), Offset(cx - bodyWidth / 2f, top), Size(bodyWidth, hgt))
                        }
                        fun drawSeries(series: List<Double?>, color: Color) {
                            var prev: Offset? = null
                            for (i in 0 until n) {
                                val v = series.getOrNull(startIdx + i)
                                if (v == null) { prev = null; continue }
                                val cur = Offset(slot * i + slot / 2f, yM(v))
                                val p = prev
                                if (p != null) drawLine(color, p, cur, strokeWidth = 1.5f)
                                prev = cur
                            }
                        }
                        drawSeries(overlays.macdLine, MacdColor)
                        drawSeries(overlays.macdSignal, SignalColor)
                        drawContext.canvas.nativeCanvas.drawText("MACD 12 26 9", 2f, oscTop + axisTextPx, labelPaint)
                    }
                    Oscillator.NONE -> {}
                }
            }

            // ---- user drawings (horizontal line / trend / fib / rect) ----
            if (drawings.isNotEmpty() || pendingAnchor != null) {
                fun ax(tsNs: Long): Float {
                    val gi = candles.indexOfFirst { it.tsStartNs == tsNs }
                    return when {
                        gi < 0 -> Float.NaN
                        gi < startIdx -> 0f
                        gi >= endIdx -> plotWidth
                        else -> slot * (gi - startIdx) + slot / 2f
                    }
                }
                for (d in drawings) {
                    when (d.tool) {
                        DrawingTool.HLINE -> {
                            val y = yOfPriceD(d.a.price)
                            drawLine(DrawingColor, Offset(0f, y), Offset(plotWidth, y), strokeWidth = 1.5f)
                        }
                        DrawingTool.TREND -> {
                            val b = d.b ?: continue
                            val x1 = ax(d.a.tsNs); val x2 = ax(b.tsNs)
                            if (!x1.isNaN() && !x2.isNaN()) {
                                drawLine(DrawingColor, Offset(x1, yOfPriceD(d.a.price)), Offset(x2, yOfPriceD(b.price)), strokeWidth = 2f)
                            }
                        }
                        DrawingTool.RECT -> {
                            val b = d.b ?: continue
                            val x1 = ax(d.a.tsNs); val x2 = ax(b.tsNs)
                            if (!x1.isNaN() && !x2.isNaN()) {
                                val left = minOf(x1, x2); val right = maxOf(x1, x2)
                                val yA = yOfPriceD(d.a.price); val yB = yOfPriceD(b.price)
                                val top = minOf(yA, yB); val h = abs(yB - yA)
                                drawRect(DrawingColor.copy(alpha = 0.10f), Offset(left, top), Size(right - left, h))
                                drawRect(DrawingColor, Offset(left, top), Size(right - left, 1f))
                                drawRect(DrawingColor, Offset(left, top + h - 1f), Size(right - left, 1f))
                                drawRect(DrawingColor, Offset(left, top), Size(1f, h))
                                drawRect(DrawingColor, Offset(right - 1f, top), Size(1f, h))
                            }
                        }
                        DrawingTool.FIB -> {
                            val b = d.b ?: continue
                            val fibPaint = Paint().apply {
                                color = FibColor.value.toInt(); textSize = axisTextPx * 0.9f; isAntiAlias = true
                            }
                            for (lvl in FIB_LEVELS) {
                                val p = d.a.price + lvl * (b.price - d.a.price)
                                val y = yOfPriceD(p)
                                drawLine(FibColor.copy(alpha = 0.7f), Offset(0f, y), Offset(plotWidth, y), strokeWidth = 1f)
                                drawContext.canvas.nativeCanvas.drawText(
                                    String.format(Locale.US, "%.3f", lvl), 2f, y - 2f, fibPaint,
                                )
                            }
                        }
                        DrawingTool.NONE -> {}
                    }
                }
                pendingAnchor?.let { pa ->
                    val x = ax(pa.tsNs)
                    if (!x.isNaN()) drawCircle(DrawingColor, radius = 6f, center = Offset(x, yOfPriceD(pa.price)))
                }
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

        // ---- MA legend (top-start), each chip toggles its overlay ----
        Row(
            modifier = Modifier.padding(start = 6.dp, top = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            MA_SPECS.forEachIndexed { i, spec ->
                val on = maVisible.getOrElse(i) { true }
                LegendChip(spec.label, spec.color, on) { maVisible[i] = !on }
            }
            LegendChip("BB", BbColor, bbOn) { bbOn = !bbOn }
            LegendChip("VWAP", VwapColor, vwapOn) { vwapOn = !vwapOn }
        }
    }
}

/** A small tappable overlay-legend chip; dims to faint when [on] is false. */
@Composable
private fun LegendChip(label: String, color: Color, on: Boolean, onToggle: () -> Unit) {
    Text(
        text = label,
        color = if (on) color else MarketColors.TextFaint,
        fontSize = 10.sp,
        modifier = Modifier
            .clip(RoundedCornerShape(4.dp))
            .background(MarketColors.Surface.copy(alpha = 0.6f))
            .clickable { onToggle() }
            .testTag("ind_toggle_$label")
            .padding(horizontal = 6.dp, vertical = 2.dp),
    )
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

/** Simple moving average aligned 1:1 with [closes]; null until [period] samples are available. */
private fun sma(closes: List<Double>, period: Int): List<Double?> {
    if (period <= 0) return closes.map { null }
    val out = ArrayList<Double?>(closes.size)
    var sum = 0.0
    for (i in closes.indices) {
        sum += closes[i]
        if (i >= period) sum -= closes[i - period]
        out.add(if (i >= period - 1) sum / period else null)
    }
    return out
}

/** Exponential moving average aligned 1:1 with [closes]; seeded at the first sample. */
private fun ema(closes: List<Double>, period: Int): List<Double?> {
    if (period <= 0 || closes.isEmpty()) return closes.map { null }
    val k = 2.0 / (period + 1)
    val out = ArrayList<Double?>(closes.size)
    var prev = closes[0]
    for (i in closes.indices) {
        prev = if (i == 0) closes[0] else closes[i] * k + prev * (1 - k)
        out.add(if (i >= period - 1) prev else null)
    }
    return out
}

/** Rolling population standard deviation over [period], aligned 1:1 with [closes]. */
private fun stdDev(closes: List<Double>, period: Int): List<Double?> {
    if (period <= 0) return closes.map { null }
    val out = ArrayList<Double?>(closes.size)
    for (i in closes.indices) {
        if (i < period - 1) { out.add(null); continue }
        val window = closes.subList(i - period + 1, i + 1)
        val mean = window.average()
        val variance = window.sumOf { (it - mean) * (it - mean) } / period
        out.add(sqrt(variance))
    }
    return out
}

/** Session VWAP: cumulative Σ(typicalPrice·volume)/Σ(volume) from the start of the loaded series. */
private fun vwap(candles: List<Candle>): List<Double?> {
    var cumPv = 0.0
    var cumV = 0.0
    return candles.map { c ->
        val typical = (c.high + c.low + c.close).toDouble() / 3.0
        val v = c.volume.toDouble()
        cumPv += typical * v
        cumV += v
        if (cumV > 0.0) cumPv / cumV else null
    }
}

/** Wilder RSI over [period], aligned 1:1 with [closes]; null until enough samples. */
private fun rsi(closes: List<Double>, period: Int): List<Double?> {
    val out = arrayOfNulls<Double>(closes.size).toMutableList()
    if (closes.size <= period) return out
    var gain = 0.0
    var loss = 0.0
    for (i in 1..period) {
        val ch = closes[i] - closes[i - 1]
        if (ch >= 0) gain += ch else loss -= ch
    }
    var avgGain = gain / period
    var avgLoss = loss / period
    out[period] = if (avgLoss == 0.0) 100.0 else 100.0 - 100.0 / (1 + avgGain / avgLoss)
    for (i in period + 1 until closes.size) {
        val ch = closes[i] - closes[i - 1]
        val g = if (ch >= 0) ch else 0.0
        val l = if (ch < 0) -ch else 0.0
        avgGain = (avgGain * (period - 1) + g) / period
        avgLoss = (avgLoss * (period - 1) + l) / period
        out[i] = if (avgLoss == 0.0) 100.0 else 100.0 - 100.0 / (1 + avgGain / avgLoss)
    }
    return out
}

/** MACD(12,26,9): returns (macd line, signal, histogram) each aligned 1:1 with [closes]. */
private fun macd(closes: List<Double>): Triple<List<Double?>, List<Double?>, List<Double?>> {
    val fast = emaSeeded(closes, 12)
    val slow = emaSeeded(closes, 26)
    val macdLine = closes.indices.map { i -> if (i >= 25) fast[i] - slow[i] else null }
    val signal = emaNullable(macdLine, 9)
    val hist = closes.indices.map { i ->
        val m = macdLine[i]
        val s = signal[i]
        if (m != null && s != null) m - s else null
    }
    return Triple(macdLine, signal, hist)
}

/** Continuous EMA seeded at the first sample (no leading nulls). */
private fun emaSeeded(closes: List<Double>, period: Int): DoubleArray {
    val k = 2.0 / (period + 1)
    val out = DoubleArray(closes.size)
    for (i in closes.indices) out[i] = if (i == 0) closes[0] else closes[i] * k + out[i - 1] * (1 - k)
    return out
}

/** EMA over a series that may have leading nulls; starts once [period] real samples are seen. */
private fun emaNullable(src: List<Double?>, period: Int): List<Double?> {
    val k = 2.0 / (period + 1)
    val out = arrayOfNulls<Double>(src.size).toMutableList()
    var prev: Double? = null
    var count = 0
    for (i in src.indices) {
        val v = src[i] ?: continue
        prev = if (prev == null) v else v * k + prev!! * (1 - k)
        count++
        if (count >= period) out[i] = prev
    }
    return out
}

private fun formatAxisPrice(v: Double): String {
    val whole = v == v.toLong().toDouble()
    return if (whole) String.format(Locale.US, "%,d", v.toLong())
    else String.format(Locale.US, "%,.2f", v)
}
