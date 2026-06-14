package com.testlogon.android.data.call

/**
 * AND-296/297 — dedicated sealed type for INBOUND call-lifecycle events.
 *
 * This is intentionally a SEPARATE sealed hierarchy from
 * [com.testlogon.android.data.messaging.realtime.MessagingEvent] so that adding call events does not force
 * changes to MessagingEvent's exhaustive `when`s. The web reference's SSE stream
 * (reference/src/hooks/useMessagingStream.ts EVENT_TYPES) enumerates the dotted tokens
 * `call.invite`, `call.accept`, `call.decline`, `call.end`, `call.missed`; the same names are assumed for
 * the FCM call data-message `type` (the FCM transport is not in OpenAPI — see AND-297 §13 Open Q1).
 *
 * Pure/framework-free (no android.*); the SDP/ICE signaling envelopes themselves remain AND-290's surface
 * (CallSignalingIn/Out) and are NOT modeled here — this type carries only control-plane lifecycle.
 */
sealed interface CallEvent {

    /** An incoming call invite for [callId] from [callerUserId]. */
    data class Invite(
        val callId: String,
        val conversationId: String,
        val callerUserId: String,
        val callerName: String?,
        val callerAvatarUrl: String?,
        val mode: CallMode,
        val expiresAtEpochSeconds: Long?,
    ) : CallEvent

    /** The peer accepted [callId]. */
    data class Accepted(val callId: String) : CallEvent

    /** The peer declined [callId]. */
    data class Declined(val callId: String) : CallEvent

    /** The call [callId] ended (remote hangup / caller cancel). */
    data class Ended(val callId: String) : CallEvent

    /** The call [callId] was missed (caller cancelled before answer). */
    data class Missed(val callId: String) : CallEvent

    /** A recognized-but-unhandled call event (kept so streams can ignore gracefully). */
    data class Ignore(val type: String) : CallEvent
}

/** The dotted wire `type` tokens for inbound call events. */
object CallEventType {
    const val INVITE = "call.invite"
    const val ACCEPT = "call.accept"
    const val DECLINE = "call.decline"
    const val END = "call.end"
    const val MISSED = "call.missed"

    /** True when [type] is one of the call-lifecycle tokens this app handles. */
    fun isCallEvent(type: String?): Boolean = type in setOf(INVITE, ACCEPT, DECLINE, END, MISSED)
}
