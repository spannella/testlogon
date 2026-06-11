package com.testlogon.android.feature.earnings.chart

/**
 * AND-252 — PURE chart-math helper. NO Compose / Canvas / android imports: this is fully
 * JVM-unit-testable. The @Composable Canvas only consumes the precomputed geometry produced here and
 * scales the normalized fractions to the actual pixel size.
 *
 * Coordinates are emitted as normalized fractions in a unit box:
 *  - x in [0, 1] left -> right (chronological order, evenly spaced by index)
 *  - y in [0, 1] where 0 == axisMin (bottom) and 1 == axisMax (top)
 * so the Canvas maps px = x * width, py = (1 - y) * height with no further math.
 *
 * All input values are integer cents (Long). Axis scaling, tick steps, point mapping, and bar
 * geometry live here; the Canvas does not re-derive any of it.
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
 * The full precomputed geometry for one series. [isEmpty] is true when there is nothing to draw
 * (no points, or every point is zero). [points]/[bars] are empty in that case.
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

    private const val DEFAULT_TICK_COUNT = 4
    private const val BAR_WIDTH_FRACTION = 0.6f

    /**
     * Computes geometry for [values] (ordered cents per bucket).
     *
     * Edge cases:
     *  - empty list -> [ChartGeometry.isEmpty] == true, axis 0..0.
     *  - all-zero -> isEmpty == true (nothing meaningful to plot).
     *  - single non-zero point -> one point centered horizontally; a flat baseline-to-value bar.
     *
     * @param tickCount number of Y gridline intervals (>= 1).
     */
    fun compute(values: List<Long>, tickCount: Int = DEFAULT_TICK_COUNT): ChartGeometry {
        if (values.isEmpty() || values.all { it == 0L }) {
            return ChartGeometry(
                points = emptyList(),
                bars = emptyList(),
                ticks = emptyList(),
                axisMinCents = 0L,
                axisMaxCents = 0L,
                isEmpty = true,
            )
        }

        val axisMin = 0L // earnings are non-negative; baseline anchored at zero
        val rawMax = values.max()
        val axisMax = niceCeil(rawMax)
        val span = (axisMax - axisMin).coerceAtLeast(1L)

        val n = values.size
        val points = values.mapIndexed { i, cents ->
            ChartPoint(
                index = i,
                cents = cents,
                x = xForIndex(i, n),
                y = ((cents - axisMin).toDouble() / span.toDouble()).toFloat(),
            )
        }

        val slot = 1f / n
        val barHalf = slot * BAR_WIDTH_FRACTION / 2f
        val bars = values.mapIndexed { i, cents ->
            val center = (i + 0.5f) * slot
            ChartBar(
                index = i,
                cents = cents,
                left = (center - barHalf).coerceIn(0f, 1f),
                right = (center + barHalf).coerceIn(0f, 1f),
                top = ((cents - axisMin).toDouble() / span.toDouble()).toFloat(),
                baseline = 0f,
            )
        }

        val steps = tickCount.coerceAtLeast(1)
        val ticks = (0..steps).map { s ->
            val cents = axisMin + span * s / steps
            ChartTick(cents = cents, y = ((cents - axisMin).toDouble() / span.toDouble()).toFloat())
        }

        return ChartGeometry(
            points = points,
            bars = bars,
            ticks = ticks,
            axisMinCents = axisMin,
            axisMaxCents = axisMax,
            isEmpty = false,
        )
    }

    /** Normalized x for bucket [i] of [n]: centered when n==1, else spread edge-to-edge by index. */
    internal fun xForIndex(i: Int, n: Int): Float =
        if (n <= 1) 0.5f else i.toFloat() / (n - 1).toFloat()

    /**
     * Rounds [value] up to a "nice" axis maximum (1/2/5 x 10^k) so the top gridline is a round number.
     * Always >= 1.
     */
    internal fun niceCeil(value: Long): Long {
        if (value <= 0L) return 1L
        var magnitude = 1L
        while (magnitude * 10 <= value) magnitude *= 10
        // candidate multiples of the current magnitude: 1,2,5,10
        for (mult in longArrayOf(1, 2, 5, 10)) {
            val candidate = magnitude * mult
            if (candidate >= value) return candidate
        }
        return magnitude * 10
    }
}
