package com.testlogon.android.feature.call.fsm

/**
 * AND-305 — the CANONICAL pure call state for the 1:1 call finite-state-machine (FSM).
 *
 * This is the new single source of truth for the call lifecycle. It is android-free (no android.*, no
 * Compose, no coroutines, no java.time) so [CallFsm.reduce] is fully JVM-unit-testable: time is always
 * passed in as `nowMs: Long`. The host ([CallStateMachine]) and the thin ViewModels project this into a
 * coroutine/Compose world.
 *
 * NOTE (migration): a working call runtime already exists
 * ([com.testlogon.android.feature.call.domain.CallManager] + CallPhase + the existing ViewModels, AND-296..
 * 304). [CallState] / [CallFsm] are ADDITIVE — the canonical FSM that those should later delegate to.
 * Migrating CallManager and the screens to drive this reducer is a deliberate FOLLOW-UP; AND-305 delivers
 * the unit-tested FSM, not the rewire.
 *
 * Lifecycle: Idle -> Dialing | IncomingRinging -> Connecting -> Active (with Reconnecting off-ramp) ->
 * Ending -> Ended. Ending/Ended are terminal off-ramps reachable from any non-terminal state.
 */
sealed interface CallState {

    /** The call this state belongs to, or null when there is no call (Idle / some Ended). */
    val callId: String?

    /** No active call. */
    data object Idle : CallState {
        override val callId: String? get() = null
    }

    /** Outgoing call placed; awaiting the remote to accept/decline (or the invite to time out). */
    data class Dialing(
        override val callId: String,
        val peer: PeerRef,
        val isVideo: Boolean,
    ) : CallState

    /** Incoming invite is ringing locally; awaiting local Accept/Decline (or ring timeout). */
    data class IncomingRinging(
        override val callId: String,
        val peer: PeerRef,
        val isVideo: Boolean,
    ) : CallState

    /** Both sides agreed; negotiating media/ICE. Becomes [Active] on IceConnected. */
    data class Connecting(
        override val callId: String,
        val peer: PeerRef,
        val isVideo: Boolean,
    ) : CallState

    /** Media is up. [startedAtMs] anchors the call-duration clock. */
    data class Active(
        override val callId: String,
        val peer: PeerRef,
        val isVideo: Boolean,
        val startedAtMs: Long,
    ) : CallState

    /**
     * ICE dropped while [Active]; attempting to recover. [startedAtMs] is carried through so the duration
     * clock keeps running and resumes seamlessly on IceConnected. [since] is when reconnection began.
     */
    data class Reconnecting(
        override val callId: String,
        val peer: PeerRef,
        val isVideo: Boolean,
        val startedAtMs: Long,
        val since: Long,
    ) : CallState

    /** A terminal teardown is in flight (end POST being sent). Transient; resolves to [Ended]. */
    data class Ending(
        override val callId: String,
        val reason: EndReason,
    ) : CallState

    /**
     * The call is over. [callId] may be null only if it ended from [Idle] (no call existed). [durationMs]
     * is the talk-time from [Active.startedAtMs] when the call ever reached [Active], else 0.
     */
    data class Ended(
        override val callId: String?,
        val reason: EndReason,
        val durationMs: Long,
    ) : CallState

    /** True for the fully-released terminal state. */
    val isTerminal: Boolean get() = this is Ended

    /** True while a call occupies the machine (single-active-call invariant, AND-305). */
    val isActiveCall: Boolean
        get() = this is Dialing || this is IncomingRinging || this is Connecting ||
            this is Active || this is Reconnecting || this is Ending
}

/** Identity of the other party in a 1:1 call. */
data class PeerRef(
    val userId: String,
    val conversationId: String,
    val displayName: String? = null,
)

/** Why a call ended (machine token; the UI maps to copy). Mirrors CallEndReason (AND-296) semantics. */
enum class EndReason {
    LOCAL_HANGUP,
    REMOTE_HANGUP,
    DECLINED,
    TIMED_OUT,
    MISSED,
    NETWORK_LOST,
    BUSY,
    ERROR,
}

/** The bounded timers the FSM arms/cancels via [CallEffect.StartTimer] / [CallEffect.CancelTimer]. */
enum class TimerKey {
    INVITE,
    RECONNECT,
    HEARTBEAT,
}

/** AND-305 — centralized timer budgets (millis). Pure constants so the reducer stays deterministic. */
object CallTimeouts {
    const val INVITE_MS: Long = 30_000L
    const val RING_MS: Long = 30_000L
    const val RECONNECT_MS: Long = 20_000L
    const val HEARTBEAT_MS: Long = 15_000L
}
