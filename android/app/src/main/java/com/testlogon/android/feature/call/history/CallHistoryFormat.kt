package com.testlogon.android.feature.call.history

import androidx.annotation.StringRes
import com.testlogon.android.R
import com.testlogon.android.data.call.CallDirection
import com.testlogon.android.data.call.CallHistoryEntry
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.call.CallStatus

/**
 * AND-303 — pure label/format helpers shared by the call-history list + detail screens.
 *
 * These map domain enums to string resource ids and are framework-light (just R ids + integer
 * arithmetic), so the screens stay declarative. Duration formatting reuses the in-call mm:ss formatter.
 */

@StringRes
internal fun CallStatus.labelRes(): Int = when (this) {
    CallStatus.COMPLETED -> R.string.call_history_status_completed
    CallStatus.MISSED -> R.string.call_history_status_missed
    CallStatus.DECLINED -> R.string.call_history_status_declined
    CallStatus.NO_ANSWER -> R.string.call_history_status_no_answer
    CallStatus.FAILED -> R.string.call_history_status_failed
    CallStatus.UNKNOWN -> R.string.call_history_status_completed
}

@StringRes
internal fun CallDirection.labelRes(): Int = when (this) {
    CallDirection.INCOMING -> R.string.call_history_direction_incoming
    CallDirection.OUTGOING -> R.string.call_history_direction_outgoing
}

@StringRes
internal fun CallMode.labelRes(): Int = when (this) {
    CallMode.AUDIO -> R.string.call_history_type_audio
    CallMode.VIDEO -> R.string.call_history_type_video
}

/**
 * Whether a duration should be rendered. Missed / declined / no-answer / failed calls never connected,
 * so they have no meaningful duration (rendered as an em-dash).
 */
internal val CallHistoryEntry.hasDuration: Boolean
    get() = status == CallStatus.COMPLETED && durationSeconds > 0

/** The "other party" id from the local user's perspective (best-effort: callee for outgoing). */
internal fun CallHistoryEntry.peerId(): String =
    if (direction == CallDirection.INCOMING) callerId else calleeId
