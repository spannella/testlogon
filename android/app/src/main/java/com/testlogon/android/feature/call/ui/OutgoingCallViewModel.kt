package com.testlogon.android.feature.call.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.feature.call.domain.CallEndReason
import com.testlogon.android.feature.call.domain.CallManager
import com.testlogon.android.feature.call.domain.CallPhase
import com.testlogon.android.feature.call.domain.CallSessionState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-296 — per-phase UI label key + duration the outgoing-call screen renders. */
data class CallUiState(
    val peerName: String?,
    val phase: CallUiPhase,
    val elapsedSeconds: Long,
    val mediaUnavailable: Boolean,
    val canRetry: Boolean,
)

/** Coarse UI phase derived from the domain [CallPhase]. */
enum class CallUiPhase { CALLING, RINGING, CONNECTING, CONNECTED, ENDING, ENDED, FAILED }

/** One-shot effects (close the screen). Channel + receiveAsFlow (never distinctUntilChanged). */
sealed interface OutgoingCallEffect {
    data object Finish : OutgoingCallEffect
}

/**
 * AND-296 — thin adapter mapping [CallManager.state] -> [CallUiState]. The CallManager owns the lifecycle
 * (app-scoped) so this VM is stateless beyond the mapping; placing the call is driven from the entry point
 * via [start] (single-active guarded by the manager).
 */
@HiltViewModel
class OutgoingCallViewModel @Inject constructor(
    private val callManager: CallManager,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val conversationId: String = savedState.get<String>(ARG_CONVERSATION_ID).orEmpty()
    private val calleeUserId: String = savedState.get<String>(ARG_CALLEE_USER_ID).orEmpty()
    private val mode: CallMode = CallMode.fromWire(savedState.get<String>(ARG_MODE))
    private val peerName: String? = savedState.get<String>(ARG_PEER_NAME)

    private val effects = Channel<OutgoingCallEffect>(Channel.BUFFERED)
    val effect = effects.receiveAsFlow()

    val uiState: StateFlow<CallUiState> = callManager.state
        .map { it.toUi() }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = CallSessionState().toUi(),
        )

    init {
        // Place the call once if the manager is idle (re-entering the screen after a config change must
        // not re-invite — the manager guards via isBusy()).
        start()
    }

    fun start() {
        if (conversationId.isBlank() || calleeUserId.isBlank()) return
        callManager.placeCall(
            conversationId = conversationId,
            calleeUserId = calleeUserId,
            mode = mode,
            peerName = peerName,
        )
    }

    fun onHangUp() = callManager.endCall(CallEndReason.HANGUP)

    /** User dismissed a terminal/failed call: reset the manager and ask the screen to finish. */
    fun onClose() {
        callManager.reset()
        viewModelScope.launch { effects.send(OutgoingCallEffect.Finish) }
    }

    private fun CallSessionState.toUi(): CallUiState = CallUiState(
        peerName = peerName,
        phase = phase.toUiPhase(),
        elapsedSeconds = elapsedSeconds,
        mediaUnavailable = mediaUnavailable,
        canRetry = phase is CallPhase.Failed,
    )

    private fun CallPhase.toUiPhase(): CallUiPhase = when (this) {
        CallPhase.Idle, CallPhase.Inviting -> CallUiPhase.CALLING
        CallPhase.Ringing -> CallUiPhase.RINGING
        CallPhase.Connecting -> CallUiPhase.CONNECTING
        is CallPhase.Connected -> CallUiPhase.CONNECTED
        CallPhase.Ending -> CallUiPhase.ENDING
        is CallPhase.Ended -> CallUiPhase.ENDED
        is CallPhase.Failed -> CallUiPhase.FAILED
    }

    companion object {
        const val ARG_CONVERSATION_ID = "conversationId"
        const val ARG_CALLEE_USER_ID = "calleeUserId"
        const val ARG_MODE = "mode"
        const val ARG_PEER_NAME = "peerName"
    }
}
