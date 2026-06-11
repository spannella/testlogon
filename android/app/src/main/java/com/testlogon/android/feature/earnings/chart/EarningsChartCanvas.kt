package com.testlogon.android.feature.earnings.chart

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp
import com.testlogon.android.feature.earnings.ChartType

/**
 * AND-252 — the @Composable Canvas chart. It draws ONLY the precomputed [ChartGeometry] from the pure
 * [EarningsChartGeometry] helper (no chart math here — axis scaling, point/bar geometry, ticks all come
 * from the JVM-tested helper). Taps map back to the nearest bucket index for tooltip selection.
 */
@Composable
fun EarningsChartCanvas(
    geometry: ChartGeometry,
    chartType: ChartType,
    lineColor: Color,
    gridColor: Color,
    fillColor: Color,
    selectedColor: Color,
    selectedIndex: Int?,
    onPointSelected: (Int?) -> Unit,
    modifier: Modifier = Modifier,
) {
    Canvas(
        modifier = modifier
            .fillMaxWidth()
            .height(180.dp)
            .pointerInput(geometry) {
                detectTapGestures { offset ->
                    val idx = nearestIndex(geometry, offset.x / size.width.toFloat())
                    onPointSelected(idx)
                }
            },
    ) {
        if (geometry.isEmpty) return@Canvas
        drawGrid(geometry, gridColor)
        when (chartType) {
            ChartType.LINE -> drawLine(geometry, lineColor, fillColor, selectedColor, selectedIndex)
            ChartType.BAR -> drawBars(geometry, lineColor, selectedColor, selectedIndex)
        }
    }
}

private fun DrawScope.drawGrid(geometry: ChartGeometry, gridColor: Color) {
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

private fun DrawScope.drawLine(
    geometry: ChartGeometry,
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

private fun DrawScope.drawBars(
    geometry: ChartGeometry,
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
            size = androidx.compose.ui.geometry.Size(width = (right - left).coerceAtLeast(1f), height = (bottom - top).coerceAtLeast(0f)),
        )
    }
}

/** Maps a normalized x (0..1) to the nearest bucket index, or null when there is no geometry. */
internal fun nearestIndex(geometry: ChartGeometry, normalizedX: Float): Int? {
    val pts = geometry.points
    if (pts.isEmpty()) return null
    return pts.minByOrNull { kotlin.math.abs(it.x - normalizedX) }?.index
}
