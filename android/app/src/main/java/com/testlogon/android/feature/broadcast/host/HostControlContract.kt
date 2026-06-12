package com.testlogon.android.feature.broadcast.host

import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.HostHealthReport

/**
 * AND-309 — PURE (android-free) UI contract for the host LIVE control surface.
 *
 * [session] is always the LATEST server truth (no optimistic flips — the ViewModel only updates it from a
 * server response). [inFlight] is the single action currently dispatched (the whole control bar is disabled
 * while it is non-null; that in-flight button shows a spinner). [healthStale] is set when a health poll
 * iteration fails but the last [health] report is retained. [showStopConfirm] drives the stop AlertDialog
 * (stop is a two-step confirm). [resumable] is the CLIENT resumability flag fed to [HostControlPolicy]
 * (there is no PAUSED enum member — media is FLAGGED).
 */
data class HostControlUiState(
    val session: BroadcastSession? = null,
    val health: HostHealthReport? = null,
    val healthStale: Boolean = false,
    val inFlight: HostAction? = null,
    val showStopConfirm: Boolean = false,
    val transientError: String? = null,
    val loading: Boolean = true,
    val resumable: Boolean = false,
)

/** AND-309 — the four host lifecycle actions (also the in-flight discriminator). */
enum class HostAction {
    START, STOP, RESUME, RESCHEDULE
}
