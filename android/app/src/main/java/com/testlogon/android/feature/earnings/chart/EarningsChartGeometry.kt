package com.testlogon.android.feature.earnings.chart

import com.testlogon.android.feature.charts.ChartGeometryCore
import com.testlogon.android.feature.charts.SeriesGeometry

/**
 * AND-252 / AND-255 — PURE chart-math helper for earnings. NO Compose / Canvas / android imports.
 *
 * AND-255 extracted the math into the reusable [ChartGeometryCore]; this object now DELEGATES to it
 * (no behavior change) and exposes the earnings-named [ChartGeometry] / [ChartPoint] / [ChartBar] /
 * [ChartTick] types the dashboard already renders. The Canvas only consumes the precomputed geometry.
 *
 * Coordinates are normalized fractions in a unit box (x in [0,1] left->right; y in [0,1], 0==axisMin
 * bottom, 1==axisMax top) so the Canvas maps px = x*width, py = (1-y)*height with no further math.
 * Input values are integer cents (Long).
 */

/** A single plotted value: its bucket index, the raw cents, and the normalized point. */
data class ChartPoint(
    val index: Int,
    val cents: Long,
    /** Normalized x in [0,1]. */
    val x: Float,
    /** Normalized y in [0,1] (0 == axisMin, 1 == axisMax). */
    val y: Float,
)

/** A bar's normalized horizontal span [left,right] and its top y (height grows down from y to baseline). */
data class ChartBar(
    val index: Int,
    val cents: Long,
    val left: Float,
    val right: Float,
    /** Normalized top of the bar in [0,1] (1 == axisMax). */
    val top: Float,
    /** Normalized baseline of the bar in [0,1] (where the bar bottom sits; usually 0 for axisMin==0). */
    val baseline: Float,
)

/** A Y-axis tick: its cents value and its normalized y position. */
data class ChartTick(val cents: Long, val y: Float)

/**
 * The full precomputed geometry for one earnings series. [isEmpty] is true when there is nothing to
 * draw (no points, or every point is zero).
 */
data class ChartGeometry(
    val points: List<ChartPoint>,
    val bars: List<ChartBar>,
    val ticks: List<ChartTick>,
    val axisMinCents: Long,
    val axisMaxCents: Long,
    val isEmpty: Boolean,
)

object EarningsChartGeometry {

    private const val DEFAULT_TICK_COUNT = ChartGeometryCore.DEFAULT_TICK_COUNT

    /**
     * Computes earnings geometry for [values] (ordered cents per bucket) by delegating to the reusable
     * [ChartGeometryCore] and adapting the generic geometry to the earnings-named types.
     *
     * @param tickCount number of Y gridline intervals (>= 1).
     */
    fun compute(values: List<Long>, tickCount: Int = DEFAULT_TICK_COUNT): ChartGeometry =
        ChartGeometryCore.compute(values, tickCount).toEarnings()

    /** Normalized x for bucket [i] of [n] (delegates to the reusable core). */
    internal fun xForIndex(i: Int, n: Int): Float = ChartGeometryCore.xForIndex(i, n)

    /** Rounds [value] up to a "nice" axis maximum (delegates to the reusable core). */
    internal fun niceCeil(value: Long): Long = ChartGeometryCore.niceCeil(value)
}

/** Adapts the reusable [SeriesGeometry] to the earnings-named [ChartGeometry] (cents semantics). */
private fun SeriesGeometry.toEarnings(): ChartGeometry = ChartGeometry(
    points = points.map { ChartPoint(index = it.index, cents = it.value, x = it.x, y = it.y) },
    bars = bars.map {
        ChartBar(
            index = it.index,
            cents = it.value,
            left = it.left,
            right = it.right,
            top = it.top,
            baseline = it.baseline,
        )
    },
    ticks = ticks.map { ChartTick(cents = it.value, y = it.y) },
    axisMinCents = axisMin,
    axisMaxCents = axisMax,
    isEmpty = isEmpty,
)
