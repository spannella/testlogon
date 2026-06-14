package com.testlogon.android.feature.call.incoming

import com.testlogon.android.data.call.CallEvent

/**
 * AND-297 — pure sealed state for the incoming-call surface, the single source of truth held by
 * [IncomingCallController] and observed by the full-screen UI + the notification updater.
 */
sealed interface IncomingCallState {
    data object Idle : IncomingCallState
    data class Ringing(val invite: CallEvent.Invite, val deadlineEpochMs: Long) : IncomingCallState
    data class Connecting(val invite: CallEvent.Invite) : IncomingCallState
    data class Connected(val callId: String) : IncomingCallState
    data class Failed(val invite: CallEvent.Invite, val message: String) : IncomingCallState
    data object Dismissed : IncomingCallState
}

/** Reason carried to POST .../decline (matches CallDeclineIn: web sends "declined" | "busy"). */
enum class DeclineReason(val wire: String) {
    USER("declined"),
    BUSY("busy"),
}

/** Reason carried to POST .../timeout (CallTimeoutIn wire value). */
enum class TimeoutReason(val wire: String) {
    NO_ANSWER("no_answer"),
}
