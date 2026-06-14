package com.testlogon.android.feature.charts

/**
 * AND-255 — the REUSABLE, PURE chart-math core. NO Compose / Canvas / android / java.time imports: this
 * is fully JVM-unit-testable. It is the single source of truth for axis scaling, tick steps, point
 * mapping, and bar geometry across BOTH the earnings dashboard (AND-252) and the engagement-rate trend
 * (AND-254). The @Composable Canvas only consumes the precomputed geometry produced here and scales the
 * normalized fractions to actual pixels.
 *
 * This generalizes AND-252's EarningsChartGeometry: that helper was already pure and operated on
 * List<Long>, so AND-255 lifts the math here unchanged and makes it consumable by any series. The
 * earnings helper now delegates to this core (no behavior change), and the engagement trend reuses it.
 *
 * Coordinates are emitted as normalized fractions in a unit box:
 *  - x in [0, 1] left to right (chronological order, evenly spaced by index)
 *  - y in [0, 1] where 0 == axisMin (bottom) and 1 == axisMax (top)
 * so the Canvas maps px = x * width, py = (1 - y) * height with no further math.
 *
 * Values are integer "units" (Long). For money this is cents; for engagement it is basis points
 * (1 bps == 0.01 percent) so a percentage series stays integer-precise and divide-free. The unit is
 * the caller's concern — the math is unit-agnostic and only requires non-negative magnitudes for the
 * zero-anchored baseline.
 */

/** A single plotted value: its bucket index, the raw units, and the normalized point. */
data class SeriesPoint(
    val index: Int,
    val value: Long,
    /** Normalized x in [0,1]. */
    val x: Float,
    /** Normalized y in [0,1] (0 == axisMin, 1 == axisMax). */
    val y: Float,
)

/** A bar's normalized horizontal span [left,right] and its top y (height grows down from top to baseline). */
data class SeriesBar(
    val index: Int,
    val value: Long,
    val left: Float,
    val right: Float,
    /** Normalized top of the bar in [0,1] (1 == axisMax). */
    val top: Float,
    /** Normalized baseline of the bar in [0,1] (where the bar bottom sits; usually 0 for axisMin==0). */
    val baseline: Float,
)

/** A Y-axis tick: its units value and its normalized y position. */
data class SeriesTick(val value: Long, val y: Float)

/**
 * The full precomputed geometry for one series. [isEmpty] is true when there is nothing to draw
 * (no points, or every point is zero). [points]/[bars]/[ticks] are empty in that case.
 */
data class SeriesGeometry(
    val points: List<SeriesPoint>,
    val bars: List<SeriesBar>,
    val ticks: List<SeriesTick>,
    val axisMin: Long,
    val axisMax: Long,
    val isEmpty: Boolean,
) {
    companion object {
        val EMPTY = SeriesGeometry(
            points = emptyList(),
            bars = emptyList(),
            ticks = emptyList(),
            axisMin = 0L,
            axisMax = 0L,
            isEmpty = true,
        )
    }
}

/**
 * AND-255 — reusable, pure geometry computation shared by every TestLogon chart.
 */
object ChartGeometryCore {

    const val DEFAULT_TICK_COUNT = 4
    private const val BAR_WIDTH_FRACTION = 0.6f

    /**
     * Computes geometry for [values] (ordered units per bucket).
     *
     * Edge cases (covered by JVM tests across series shapes):
     *  - empty list -> [SeriesGeometry.isEmpty] == true, axis 0..0.
     *  - all-zero -> isEmpty == true (nothing meaningful to plot).
     *  - single non-zero point -> one point centered horizontally; a flat baseline-to-value bar.
     *  - negative units are clamped to the zero baseline (the shared baseline is zero-anchored).
     *
     * @param tickCount number of Y gridline intervals (>= 1).
     */
    fun compute(values: List<Long>, tickCount: Int = DEFAULT_TICK_COUNT): SeriesGeometry {
        if (values.isEmpty() || values.all { it == 0L }) return SeriesGeometry.EMPTY

        val axisMin = 0L // zero-anchored baseline; negatives clamp to it
        val rawMax = values.max().coerceAtLeast(0L)
        val axisMax = niceCeil(rawMax)
        val span = (axisMax - axisMin).coerceAtLeast(1L)

        val n = values.size
        val points = values.mapIndexed { i, value ->
            SeriesPoint(
                index = i,
                value = value,
                x = xForIndex(i, n),
                y = yFor(value, axisMin, span),
            )
        }

        val slot = 1f / n
        val barHalf = slot * BAR_WIDTH_FRACTION / 2f
        val bars = values.mapIndexed { i, value ->
            val center = (i + 0.5f) * slot
            SeriesBar(
                index = i,
                value = value,
                left = (center - barHalf).coerceIn(0f, 1f),
                right = (center + barHalf).coerceIn(0f, 1f),
                top = yFor(value, axisMin, span),
                baseline = 0f,
            )
        }

        val steps = tickCount.coerceAtLeast(1)
        val ticks = (0..steps).map { s ->
            val value = axisMin + span * s / steps
            SeriesTick(value = value, y = yFor(value, axisMin, span))
        }

        return SeriesGeometry(
            points = points,
            bars = bars,
            ticks = ticks,
            axisMin = axisMin,
            axisMax = axisMax,
            isEmpty = false,
        )
    }

    /** Normalized y for [value] given [axisMin] and [span]; clamped to [0,1] so negatives sit on the baseline. */
    private fun yFor(value: Long, axisMin: Long, span: Long): Float =
        ((value - axisMin).toDouble() / span.toDouble()).toFloat().coerceIn(0f, 1f)

    /** Normalized x for bucket [i] of [n]: centered when n==1, else spread edge-to-edge by index. */
    fun xForIndex(i: Int, n: Int): Float =
        if (n <= 1) 0.5f else i.toFloat() / (n - 1).toFloat()

    /**
     * Rounds [value] up to a "nice" axis maximum (1/2/5 x 10^k) so the top gridline is a round number.
     * Always >= 1.
     */
    fun niceCeil(value: Long): Long {
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

    /** Maps a normalized x (0..1) to the nearest bucket index, or null when [geometry] has no points. */
    fun nearestIndex(geometry: SeriesGeometry, normalizedX: Float): Int? {
        val pts = geometry.points
        if (pts.isEmpty()) return null
        return pts.minByOrNull { kotlin.math.abs(it.x - normalizedX) }?.index
    }
}
