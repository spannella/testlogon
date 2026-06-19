package com.testlogon.android.feature.call.domain

import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.webrtc.PeerRole

/**
 * AND-296 — the single source of truth for the outgoing/active call phase.
 *
 * Pure sealed type (no android.*, no SDK types) so the state machine is fully JVM-unit-testable. Order:
 * Idle -> Inviting -> Ringing -> Connecting -> Connected, with Ending and the terminal Ended/Failed
 * off-ramps. [Connected.sinceEpochMs] seeds the local duration timer when no heartbeat elapsed is known.
 */
sealed interface CallPhase {
    data object Idle : CallPhase
    data object Inviting : CallPhase
    data object Ringing : CallPhase
    data object Connecting : CallPhase
    data class Connected(val sinceEpochMs: Long) : CallPhase
    data object Ending : CallPhase
    data class Ended(val reason: CallEndReason) : CallPhase
    data class Failed(val reason: CallEndReason) : CallPhase

    /** True for any phase that has fully released resources. */
    val isTerminal: Boolean get() = this is Ended || this is Failed
}

/** Why a call ended/failed (machine token; UI maps to copy). */
enum class CallEndReason {
    HANGUP,
    REMOTE_HANGUP,
    DECLINED,
    NO_ANSWER,
    INSUFFICIENT_BALANCE,
    NEGOTIATION_FAILED,
    NETWORK,
    MEDIA_UNAVAILABLE,
    UNKNOWN,
}

/** The active call's identity + idempotency material. */
data class ActiveCall(
    val callId: String,
    val conversationId: String,
    val peerUserId: String,
    val mode: CallMode,
    val idempotencyKey: String,
    val role: PeerRole = PeerRole.OFFERER,
)

/** Hot, app-scoped snapshot of the current call the screens render. */
data class CallSessionState(
    val phase: CallPhase = CallPhase.Idle,
    val call: ActiveCall? = null,
    val peerName: String? = null,
    val elapsedSeconds: Long = 0,
    val warnLowBalance: Boolean = false,
    val minutesRemaining: Double? = null,
    /**
     * AND-296/297 — set true when the FLAGGED WebRTC media stubs returned NotConfigured, so the UI can
     * surface "call media unavailable" while the CONTROL PLANE still functioned.
     */
    val mediaUnavailable: Boolean = false,
    /**
     * AND-301 — billing snapshot for a PAID call. [paid] / [rateCentsPerMinute] are captured from the
     * invite; [totalCostCents], [balanceRemainingCents] and [maxDurationWarning] are the authoritative
     * values copied from each server heartbeat (alongside the existing elapsedSeconds/warnLowBalance/
     * minutesRemaining). All default to the free-call zero so non-paid calls are unaffected.
     */
    val paid: Boolean = false,
    val rateCentsPerMinute: Int = 0,
    val totalCostCents: Int = 0,
    val balanceRemainingCents: Int = 0,
    val maxDurationWarning: Boolean = false,
)
