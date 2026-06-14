package com.testlogon.android.feature.calendar

import java.time.Instant
import java.time.ZoneId
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-271 — resolves the effective display zone (precedence: explicit user override -> device default
 * ZoneId.systemDefault()) and the device zone. Injectable so tests can pin both. java.time is used here
 * (the only place that needs it for zone offsets) — desugaring covers minSdk 24.
 */
@Singleton
open class CalendarZoneProvider @Inject constructor() {

    /** The user's explicit display-zone override, or null to use the device default. */
    open fun overrideZoneId(): String? = null

    /** The device's default zone id. */
    open fun deviceZoneId(): String = ZoneId.systemDefault().id

    /** The effective display zone id (override, else device default). */
    fun displayZoneId(): String = overrideZoneId() ?: deviceZoneId()

    /** Total offset (minutes) of [zoneId] at [instant], for the pure slotting math. */
    fun offsetMinutesAt(zoneId: String, instant: Instant): Int =
        ZoneId.of(zoneId).rules.getOffset(instant).totalSeconds / 60
}

/** AND-271 — injectable clock seam so the "today" focus is deterministic in tests. */
@Singleton
open class CalendarClock @Inject constructor() {
    /** Current UTC epoch millis. */
    open fun nowMillis(): Long = System.currentTimeMillis()

    /** Today's epoch day in [zoneId]. */
    fun todayEpochDay(zoneId: String): Long {
        val offset = ZoneId.of(zoneId).rules.getOffset(Instant.ofEpochMilli(nowMillis())).totalSeconds
        return CalendarMath.localEpochDay(nowMillis(), offset / 60)
    }
}
