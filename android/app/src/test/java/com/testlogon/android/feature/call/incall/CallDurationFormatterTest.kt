package com.testlogon.android.feature.call.incall

import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-298 — [CallDurationFormatter] mm:ss / h:mm:ss rollover tests. */
class CallDurationFormatterTest {

    @Test
    fun format_zero() = assertEquals("00:00", CallDurationFormatter.format(0))

    @Test
    fun format_underMinute() = assertEquals("00:59", CallDurationFormatter.format(59))

    @Test
    fun format_oneMinute() = assertEquals("01:00", CallDurationFormatter.format(60))

    @Test
    fun format_maxBeforeHour() = assertEquals("59:59", CallDurationFormatter.format(3599))

    @Test
    fun format_oneHour() = assertEquals("1:00:00", CallDurationFormatter.format(3600))

    @Test
    fun format_oneHourOneMinuteOneSecond() = assertEquals("1:01:01", CallDurationFormatter.format(3661))
}
