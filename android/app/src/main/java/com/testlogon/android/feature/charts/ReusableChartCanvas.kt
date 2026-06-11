package com.testlogon.android.feature.charts

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** AND-255 — line vs bar selector for the reusable chart. */
enum class SeriesChartType { LINE, BAR }

/**
 * AND-255 — the REUSABLE @Composable Canvas chart. It draws ONLY the precomputed [SeriesGeometry] from
 * the pure [ChartGeometryCore] (no chart math here — axis scaling, point/bar geometry, ticks all come
 * from the JVM-tested core). Colors are supplied by the caller (theme-driven at the call site, so this
 * composable hard-codes no Color). Taps map back to the nearest bucket index for tooltip selection.
 *
 * Consumed by BOTH the earnings dashboard (via EarningsChartCanvas, which delegates here) and the
 * engagement-rate trend card (AND-254).
 */
@Composable
fun TestLogonSeriesChart(
    geometry: SeriesGeometry,
    chartType: SeriesChartType,
    lineColor: Color,
    gridColor: Color,
    fillColor: Color,
    selectedColor: Color,
    selectedIndex: Int?,
    onPointSelected: (Int?) -> Unit,
    modifier: Modifier = Modifier,
    height: Dp = 180.dp,
) {
    Canvas(
        modifier = modifier
            .fillMaxWidth()
            .height(height)
            .pointerInput(geometry) {
                detectTapGestures { offset ->
                    val idx = ChartGeometryCore.nearestIndex(geometry, offset.x / size.width.toFloat())
                    onPointSelected(idx)
                }
            },
    ) {
        if (geometry.isEmpty) return@Canvas
        drawGrid(geometry, gridColor)
        when (chartType) {
            SeriesChartType.LINE -> drawSeriesLine(geometry, lineColor, fillColor, selectedColor, selectedIndex)
            SeriesChartType.BAR -> drawSeriesBars(geometry, lineColor, selectedColor, selectedIndex)
        }
    }
}

private fun DrawScope.drawGrid(geometry: SeriesGeometry, gridColor: Color) {
    val w = size.width
    val h = size.height
    geometry.ticks.forEach { tick ->
        val py = (1f - tick.y) * h
        drawLine(
            color = gridColor,
            start = Offset(0f, py),
            end = Offset(w, py),
            strokeWidth = 1f,
        )
    }
}

private fun DrawScope.drawSeriesLine(
    geometry: SeriesGeometry,
    lineColor: Color,
    fillColor: Color,
    selectedColor: Color,
    selectedIndex: Int?,
) {
    val w = size.width
    val h = size.height
    val pts = geometry.points
    if (pts.isEmpty()) return

    val linePath = Path()
    val fillPath = Path()
    pts.forEachIndexed { i, p ->
        val px = p.x * w
        val py = (1f - p.y) * h
        if (i == 0) {
            linePath.moveTo(px, py)
            fillPath.moveTo(px, h)
            fillPath.lineTo(px, py)
        } else {
            linePath.lineTo(px, py)
            fillPath.lineTo(px, py)
        }
    }
    fillPath.lineTo(pts.last().x * w, h)
    fillPath.close()

    drawPath(path = fillPath, color = fillColor)
    drawPath(path = linePath, color = lineColor, style = Stroke(width = 4f))

    pts.forEach { p ->
        val px = p.x * w
        val py = (1f - p.y) * h
        val color = if (p.index == selectedIndex) selectedColor else lineColor
        val radius = if (p.index == selectedIndex) 7f else 4f
        drawCircle(color = color, radius = radius, center = Offset(px, py))
    }
}

private fun DrawScope.drawSeriesBars(
    geometry: SeriesGeometry,
    barColor: Color,
    selectedColor: Color,
    selectedIndex: Int?,
) {
    val w = size.width
    val h = size.height
    geometry.bars.forEach { bar ->
        val left = bar.left * w
        val right = bar.right * w
        val top = (1f - bar.top) * h
        val bottom = (1f - bar.baseline) * h
        val color = if (bar.index == selectedIndex) selectedColor else barColor
        drawRect(
            color = color,
            topLeft = Offset(left, top),
            size = Size(width = (right - left).coerceAtLeast(1f), height = (bottom - top).coerceAtLeast(0f)),
        )
    }
}
