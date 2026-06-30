package com.testlogon.android.testseam

import com.testlogon.android.BuildConfig

/**
 * DEBUG-ONLY gate for the media-picker test seam.
 *
 * The seam is INERT unless BOTH are true:
 *   1. BuildConfig.DEBUG  (this file only exists in the debug source set anyway, but we re-check
 *      so the gate is unmistakably debug-scoped), AND
 *   2. the system property  debug.testlogon.testhooks == "1"  (read via android.os.SystemProperties
 *      by reflection; that class is hidden but stable on every Android build).
 *
 * Why this property: the "debug." prefix namespace in Android system properties is world-settable
 * without root, so the host can flip it with:
 *     adb shell setprop debug.testlogon.testhooks 1   (enable)
 *     adb shell setprop debug.testlogon.testhooks 0   (disable; or empty to clear)
 * It is read fresh on every check, so toggling takes effect on the next picker launch (no relaunch
 * needed to DISABLE, though enabling mid-session is fine too).
 *
 * Until the property is "1" the intercepting registry delegates to the REAL ActivityResultRegistry,
 * so the emailed debug APK behaves exactly like an un-instrumented build.
 */
object TestSeamGate {

    const val SYSTEM_PROPERTY = "debug.testlogon.testhooks"

    fun enabled(): Boolean {
        if (!BuildConfig.DEBUG) return false
        return readSystemProperty(SYSTEM_PROPERTY) == "1"
    }

    private fun readSystemProperty(key: String): String? = try {
        val clazz = Class.forName("android.os.SystemProperties")
        val get = clazz.getMethod("get", String::class.java)
        get.invoke(null, key) as? String
    } catch (_: Throwable) {
        null
    }
}
