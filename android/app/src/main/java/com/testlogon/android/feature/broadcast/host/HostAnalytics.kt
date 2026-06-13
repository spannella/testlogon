package com.testlogon.android.feature.broadcast.host

import android.util.Log
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-317 — fire-and-forget host telemetry seam. No general app-wide Analytics/Logger interface exists in
 * this repo, so a tiny dedicated interface is defined here with a [Log]-backed default impl. AND-318 can
 * substitute a recording fake.
 *
 * It is intentionally minimal: a phase-transition signal + an illegal-transition signal (so the FSM's
 * never-throw no-ops are observable in telemetry rather than silently dropped).
 */
interface HostAnalytics {

    /** A legal phase transition occurred (for funnel/health dashboards). */
    fun phaseChanged(from: String, to: String)

    /** The reducer rejected an event in the current phase (LogIllegalTransition effect). */
    fun illegalTransition(from: String, event: String)
}

/** Default [Log]-backed, fire-and-forget impl. Never throws. */
@Singleton
class LoggingHostAnalytics @Inject constructor() : HostAnalytics {

    override fun phaseChanged(from: String, to: String) {
        Log.d(TAG, "phase $from -> $to")
    }

    override fun illegalTransition(from: String, event: String) {
        Log.w(TAG, "illegal: $event @ $from")
    }

    private companion object {
        const val TAG = "HostBroadcast"
    }
}
