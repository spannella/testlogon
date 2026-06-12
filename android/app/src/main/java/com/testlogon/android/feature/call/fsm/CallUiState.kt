package com.testlogon.android.feature.call.fsm

/**
 * AND-305 — display-ready projection of [CallState] for the thin FSM ViewModels. Pure (android-free) so it
 * is unit-testable. The 1Hz duration label is derived from [CallState.Active.startedAtMs] in the VM ticker;
 * [project] takes the current wall clock so the label is deterministic in tests.
 */
data class CallUiState(
    val callId: String? = null,
    val phaseLabel: CallPhaseLabel = CallPhaseLabel.IDLE,
    val peerName: String? = null,
    val isVideo: Boolean = false,
    val formattedDuration: String = "00:00",
    val connectionQuality: CallConnectionQuality = CallConnectionQuality.UNKNOWN,
    val endReason: EndReason? = null,
    val isCallActive: Boolean = false,
) {
    companion object {
        /** Projects a [CallState] into UI state. [nowMs] anchors the running-duration label. */
        fun project(state: CallState, nowMs: Long): CallUiState = when (state) {
            is CallState.Idle -> CallUiState()
            is CallState.Dialing -> CallUiState(
                callId = state.callId,
                phaseLabel = CallPhaseLabel.DIALING,
                peerName = state.peer.displayName,
                isVideo = state.isVideo,
                isCallActive = true,
            )
            is CallState.IncomingRinging -> CallUiState(
                callId = state.callId,
                phaseLabel = CallPhaseLabel.INCOMING,
                peerName = state.peer.displayName,
                isVideo = state.isVideo,
                isCallActive = true,
            )
            is CallState.Connecting -> CallUiState(
                callId = state.callId,
                phaseLabel = CallPhaseLabel.CONNECTING,
                peerName = state.peer.displayName,
                isVideo = state.isVideo,
                isCallActive = true,
            )
            is CallState.Active -> CallUiState(
                callId = state.callId,
                phaseLabel = CallPhaseLabel.ACTIVE,
                peerName = state.peer.displayName,
                isVideo = state.isVideo,
                formattedDuration = formatMs((nowMs - state.startedAtMs).coerceAtLeast(0L)),
                connectionQuality = CallConnectionQuality.GOOD,
                isCallActive = true,
            )
            is CallState.Reconnecting -> CallUiState(
                callId = state.callId,
                phaseLabel = CallPhaseLabel.RECONNECTING,
                peerName = state.peer.displayName,
                isVideo = state.isVideo,
                // Duration freezes at the disconnect point while reconnecting (talk-time so far).
                formattedDuration = formatMs((state.since - state.startedAtMs).coerceAtLeast(0L)),
                connectionQuality = CallConnectionQuality.LOST,
                isCallActive = true,
            )
            is CallState.Ending -> CallUiState(
                callId = state.callId,
                phaseLabel = CallPhaseLabel.ENDING,
                endReason = state.reason,
            )
            is CallState.Ended -> CallUiState(
                callId = state.callId,
                phaseLabel = CallPhaseLabel.ENDED,
                formattedDuration = formatMs(state.durationMs),
                endReason = state.reason,
            )
        }

        /** mm:ss (or h:mm:ss past an hour). Pure; no java.time. */
        fun formatMs(ms: Long): String {
            val totalSeconds = (ms / 1_000L).coerceAtLeast(0L)
            val hours = totalSeconds / 3_600L
            val minutes = (totalSeconds % 3_600L) / 60L
            val seconds = totalSeconds % 60L
            return if (hours > 0L) {
                "%d:%02d:%02d".format(hours, minutes, seconds)
            } else {
                "%02d:%02d".format(minutes, seconds)
            }
        }
    }
}

/** Coarse UI phase label derived from [CallState]. */
enum class CallPhaseLabel { IDLE, DIALING, INCOMING, CONNECTING, ACTIVE, RECONNECTING, ENDING, ENDED }

/** Connection-quality hint for the UI. */
enum class CallConnectionQuality { UNKNOWN, GOOD, LOST }
