package com.testlogon.android.feature.earnings.chart

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import com.testlogon.android.feature.charts.SeriesBar
import com.testlogon.android.feature.charts.SeriesChartType
import com.testlogon.android.feature.charts.SeriesGeometry
import com.testlogon.android.feature.charts.SeriesPoint
import com.testlogon.android.feature.charts.SeriesTick
import com.testlogon.android.feature.charts.TestLogonSeriesChart
import com.testlogon.android.feature.earnings.ChartType

/**
 * AND-252 / AND-255 — the earnings Canvas chart. AND-255 generalized the renderer into the reusable
 * [TestLogonSeriesChart]; this thin wrapper adapts the earnings-named [ChartGeometry] / [ChartType] to
 * the reusable [SeriesGeometry] / [SeriesChartType] and delegates. No drawing/math lives here anymore,
 * so earnings and engagement render through one tested code path (no behavior change for earnings).
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
    TestLogonSeriesChart(
        geometry = geometry.toSeries(),
        chartType = when (chartType) {
            ChartType.LINE -> SeriesChartType.LINE
            ChartType.BAR -> SeriesChartType.BAR
        },
        lineColor = lineColor,
        gridColor = gridColor,
        fillColor = fillColor,
        selectedColor = selectedColor,
        selectedIndex = selectedIndex,
        onPointSelected = onPointSelected,
        modifier = modifier,
    )
}

/** Adapts the earnings-named [ChartGeometry] back to the reusable [SeriesGeometry] for rendering. */
private fun ChartGeometry.toSeries(): SeriesGeometry = SeriesGeometry(
    points = points.map { SeriesPoint(index = it.index, value = it.cents, x = it.x, y = it.y) },
    bars = bars.map {
        SeriesBar(
            index = it.index,
            value = it.cents,
            left = it.left,
            right = it.right,
            top = it.top,
            baseline = it.baseline,
        )
    },
    ticks = ticks.map { SeriesTick(value = it.cents, y = it.y) },
    axisMin = axisMinCents,
    axisMax = axisMaxCents,
    isEmpty = isEmpty,
)
