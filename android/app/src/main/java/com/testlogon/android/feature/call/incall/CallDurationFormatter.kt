package com.testlogon.android.feature.call.incall

/**
 * AND-298 — pure, JVM-testable call-duration formatter.
 *
 * Renders elapsed seconds as "mm:ss" (both zero-padded) and rolls to "h:mm:ss" once the call passes one
 * hour (hour NOT zero-padded; minutes/seconds zero-padded). Pure integer arithmetic — no java.time and no
 * android.text.format — so it unit-tests cleanly. (The existing
 * [com.testlogon.android.feature.call.ui.formatDuration] is mm:ss only and internal to the ui package; this
 * adds the hour-rollover the in-call timer needs.)
 */
object CallDurationFormatter {

    fun format(totalSeconds: Long): String {
        val s = totalSeconds.coerceAtLeast(0)
        val hours = s / 3600
        val minutes = (s % 3600) / 60
        val seconds = s % 60
        return if (hours > 0) {
            "$hours:${pad(minutes)}:${pad(seconds)}"
        } else {
            "${pad(minutes)}:${pad(seconds)}"
        }
    }

    private fun pad(value: Long): String = if (value < 10) "0$value" else value.toString()
}
