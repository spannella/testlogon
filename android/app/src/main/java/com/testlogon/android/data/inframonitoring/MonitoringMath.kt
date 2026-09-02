package com.testlogon.android.data.inframonitoring

import kotlin.math.max
import kotlin.math.roundToInt

/**
 * Pure, side-effect-free aggregation + derivation helpers for the instance-monitoring dashboard.
 *
 * Kept free of Android / Retrofit / Moshi types so it is unit-testable on the JVM. The UI and the
 * ViewModel call into this for chart downsampling, series stats, and a client-side health tint that
 * degrades gracefully when the (optional) backend health/restart routes 404.
 *
 * Mirrors the web's client-side treatment in InstanceMonitoringPage.tsx (latest + series + health).
 */
object MonitoringMath {

    /** Derived, ordinal severity for a health string; higher = worse. Unknown sits between ok and warn. */
    enum class HealthLevel(val rank: Int) {
        HEALTHY(0),
        UNKNOWN(1),
        WARNING(2),
        CRITICAL(3),
    }

    /** Simple min/avg/max/last summary over one metric channel. */
    data class SeriesStats(
        val count: Int,
        val min: Int,
        val max: Int,
        val avg: Int,
        val last: Int,
    ) {
        companion object {
            val EMPTY = SeriesStats(count = 0, min = 0, max = 0, avg = 0, last = 0)
        }
    }

    /** Map a backend health_status string onto an ordinal [HealthLevel]. Case/space tolerant. */
    fun healthLevel(status: String?): HealthLevel = when (status?.trim()?.lowercase()) {
        "healthy", "ok", "good", "running" -> HealthLevel.HEALTHY
        "warning", "warn", "degraded" -> HealthLevel.WARNING
        "critical", "unhealthy", "error", "failed" -> HealthLevel.CRITICAL
        else -> HealthLevel.UNKNOWN
    }

    /**
     * Client-side health derivation used when the backend health summary is absent (route 404 /
     * pre-data). Mirrors the backend thresholds coarsely: any channel >= 90 is critical, >= 75 warns.
     * Returns [HealthLevel.UNKNOWN] when there is no datapoint to reason about.
     */
    fun deriveHealth(cpuPct: Int?, memPct: Int?, diskPct: Int?): HealthLevel {
        val values = listOfNotNull(cpuPct, memPct, diskPct)
        if (values.isEmpty()) return HealthLevel.UNKNOWN
        val peak = values.max()
        return when {
            peak >= 90 -> HealthLevel.CRITICAL
            peak >= 75 -> HealthLevel.WARNING
            else -> HealthLevel.HEALTHY
        }
    }

    /**
     * Reconcile the backend-reported health level with the client derivation and pick the WORSE of the
     * two so a stale/empty backend summary never hides a hot datapoint. When [reported] is UNKNOWN we
     * fall through to [derived].
     */
    fun effectiveHealth(reported: HealthLevel, derived: HealthLevel): HealthLevel =
        if (reported == HealthLevel.UNKNOWN) derived
        else if (derived.rank > reported.rank) derived
        else reported

    /** min/avg/max/last over an integer channel. Empty -> [SeriesStats.EMPTY]. */
    fun stats(values: List<Int>): SeriesStats {
        if (values.isEmpty()) return SeriesStats.EMPTY
        var mn = values[0]
        var mx = values[0]
        var sum = 0L
        for (v in values) {
            if (v < mn) mn = v
            if (v > mx) mx = v
            sum += v
        }
        val avg = (sum.toDouble() / values.size).roundToInt()
        return SeriesStats(count = values.size, min = mn, max = mx, avg = avg, last = values.last())
    }

    /**
     * Downsample [values] to at most [maxPoints] entries for a compact chart, preserving order and the
     * FINAL sample (most-recent). Uses even-stride bucketing. When the input already fits, it is
     * returned unchanged. [maxPoints] is clamped to >= 1.
     */
    fun downsample(values: List<Int>, maxPoints: Int): List<Int> {
        val cap = max(1, maxPoints)
        if (values.size <= cap) return values
        val out = ArrayList<Int>(cap)
        // stride across the input; guarantee the last element is included.
        val step = values.size.toDouble() / cap
        var i = 0
        while (i < cap - 1) {
            val idx = (i * step).toInt().coerceIn(0, values.size - 1)
            out.add(values[idx])
            i++
        }
        out.add(values.last())
        return out
    }

    /**
     * Order timeline events NEWEST-first by timestamp (stable for equal ts). Pure list transform used
     * before rendering the lifecycle timeline.
     */
    fun <T> orderTimelineDesc(events: List<T>, tsOf: (T) -> Long): List<T> =
        events.sortedByDescending(tsOf)

    /** Human-friendly label for a restart policy line, e.g. "On · 2/3 used" or "Off". */
    fun restartPolicySummary(enabled: Boolean, restartCount: Int, maxRestarts: Int): String =
        if (!enabled) "Off"
        else "On · ${restartCount.coerceAtLeast(0)}/${maxRestarts.coerceAtLeast(0)} used"
}
