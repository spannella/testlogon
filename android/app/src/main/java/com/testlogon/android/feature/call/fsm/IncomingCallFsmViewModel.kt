package com.testlogon.android.feature.call.fsm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

/** AND-305 — the ringing slice the incoming-call screen renders. */
data class IncomingCallUiState(
    val isRinging: Boolean = false,
    val callId: String? = null,
    val peerName: String? = null,
    val isVideo: Boolean = false,
)

/**
 * AND-305 — thin, ADDITIVE ViewModel exposing only the incoming-ringing slice + accept/decline. Named
 * IncomingCallFsmViewModel to avoid clashing with the existing
 * [com.testlogon.android.feature.call.incoming.IncomingCallController] / screen (AND-297), which stay as-is.
 * Not wired into navigation; migration is a FOLLOW-UP.
 */
@HiltViewModel
class IncomingCallFsmViewModel @Inject constructor(
    private val stateMachine: CallStateMachine,
) : ViewModel() {

    val uiState: StateFlow<IncomingCallUiState> = stateMachine.state
        .map { state ->
            if (state is CallState.IncomingRinging) {
                IncomingCallUiState(
                    isRinging = true,
                    callId = state.callId,
                    peerName = state.peer.displayName,
                    isVideo = state.isVideo,
                )
            } else {
                IncomingCallUiState(isRinging = false)
            }
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000L),
            initialValue = IncomingCallUiState(),
        )

    fun accept() = stateMachine.dispatch(CallEvent.Accept)

    fun decline() = stateMachine.dispatch(CallEvent.Decline)
}
