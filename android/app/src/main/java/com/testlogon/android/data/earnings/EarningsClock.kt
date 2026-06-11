package com.testlogon.android.data.earnings

import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-252 — tiny time seam so the range -> from_date/to_date math and fetch timestamps are
 * deterministic in tests. The default reads the wall clock; tests inject a fixed clock.
 *
 * Kept java.time-free (uses System.currentTimeMillis + integer division) so it is safe in
 * JVM-unit-tested code and on API < 26.
 */
interface EarningsClock {
    /** Current UTC days-since-1970. */
    fun todayEpochDay(): Long

    /** Current epoch milliseconds. */
    fun nowEpochMs(): Long
}

@Singleton
class SystemEarningsClock @Inject constructor() : EarningsClock {
    override fun todayEpochDay(): Long = System.currentTimeMillis() / MILLIS_PER_DAY
    override fun nowEpochMs(): Long = System.currentTimeMillis()

    private companion object {
        const val MILLIS_PER_DAY = 86_400_000L
    }
}
