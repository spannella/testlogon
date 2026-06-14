package com.testlogon.android.feature.broadcast.privateshow

import com.testlogon.android.data.broadcast.PrivateShowRequest
import com.testlogon.android.data.broadcast.PrivateShowSession
import com.testlogon.android.data.broadcast.PrivateShowSummary

/**
 * AND-315 — the private-show lifecycle state machine (host side).
 *
 * Idle -> Pending(request) -> Active(session, elapsed, accrued) -> Ending -> Ended(summary). The accrued cost
 * in [Active] is a CLIENT ESTIMATE (elapsed * rate / 60); the server end summary in [Ended] is authoritative.
 */
sealed interface PrivateShowState {

    /** No request and no active show. */
    data object Idle : PrivateShowState

    /** A viewer is requesting a private show (awaiting host Accept / Decline). */
    data class Pending(val request: PrivateShowRequest) : PrivateShowState

    /**
     * An accepted, running private show. [elapsedSeconds] / [accruedCents] are client estimates recomputed
     * each tick from the server `started_at` + the viewer-set rate.
     */
    data class Active(
        val session: PrivateShowSession,
        val elapsedSeconds: Long,
        val accruedCents: Long,
    ) : PrivateShowState

    /** An end request is in flight for [privateSessionId]. */
    data class Ending(val privateSessionId: String) : PrivateShowState

    /** The show ended; [summary] carries the authoritative server billing. */
    data class Ended(val summary: PrivateShowSummary) : PrivateShowState
}

/**
 * AND-315 — the full UI state: the lifecycle [state] plus transient action feedback ([actionError]) and an
 * [inFlightAction] flag that disables the action affordances while a REST call is running.
 */
data class PrivateShowUiState(
    val state: PrivateShowState = PrivateShowState.Idle,
    val actionError: String? = null,
    val inFlightAction: Boolean = false,
)

/** The three public-stream behaviors a host can pick when accepting a request (default [PAUSE]). */
enum class PrivateShowBehavior(val wire: String) {
    PAUSE("pause"),
    END("end"),
    CONTINUE("continue"),
}
