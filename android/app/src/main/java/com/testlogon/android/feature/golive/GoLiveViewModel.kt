package com.testlogon.android.feature.golive

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.webrtc.BroadcastPublisher
import com.testlogon.android.data.webrtc.GoLiveResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-288 — host "Go Live" presentation logic.
 *
 * Owns the permission/availability state machine and the go-live action. The actual go-live engine is the
 * FLAGGED [BroadcastPublisher] seam, so the action ALWAYS resolves to "broadcasting unavailable" until the
 * native WebRTC SDK is wired — the ViewModel never starts capture/peer/media itself. Permission *results*
 * are reported in by the screen (which owns the AndroidX activity-result launcher); the ViewModel keeps
 * the resulting status and gates [goLive] on it.
 *
 * One-shot effects (request-permissions, open-settings, notices) use Channel + receiveAsFlow (never
 * distinctUntilChanged on a StateFlow). The go-live VM launch is fire-and-forget — the stub publisher
 * call does no IO, so no dispatcher injection is needed.
 */
@HiltViewModel
class GoLiveViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val publisher: BroadcastPublisher,
) : ViewModel() {

    val sessionId: String = savedStateHandle.get<String>(ARG_SESSION_ID).orEmpty()
    val inputId: String = savedStateHandle.get<String>(ARG_INPUT_ID).orEmpty()

    private val _uiState = MutableStateFlow(GoLiveUiState())
    val uiState: StateFlow<GoLiveUiState> = _uiState.asStateFlow()

    private val _effects = Channel<GoLiveEffect>(Channel.BUFFERED)
    val effects = _effects.receiveAsFlow()

    /** The user tapped "Go Live". If permissions aren't granted, request them; otherwise start. */
    fun onGoLiveClicked() {
        when (_uiState.value.permission) {
            AvPermissionStatus.GRANTED -> startBroadcast()
            AvPermissionStatus.PERMANENTLY_DENIED -> _effects.trySend(GoLiveEffect.OpenAppSettings)
            AvPermissionStatus.NOT_REQUESTED,
            AvPermissionStatus.DENIED,
            -> _effects.trySend(GoLiveEffect.RequestPermissions)
        }
    }

    /**
     * Called by the screen with the result of the CAMERA + RECORD_AUDIO request. [cameraGranted] /
     * [micGranted] are the per-permission grants; [showRationale] is the OR of
     * shouldShowRequestPermissionRationale for the still-denied permissions (false-after-deny =>
     * permanently denied).
     */
    fun onPermissionResult(cameraGranted: Boolean, micGranted: Boolean, showRationale: Boolean) {
        val status = when {
            cameraGranted && micGranted -> AvPermissionStatus.GRANTED
            showRationale -> AvPermissionStatus.DENIED
            else -> AvPermissionStatus.PERMANENTLY_DENIED
        }
        _uiState.update { it.copy(permission = status) }
        if (status == AvPermissionStatus.GRANTED) startBroadcast()
    }

    /** Re-checks permission status on resume (e.g. after returning from Settings). */
    fun onPermissionStateRefreshed(cameraGranted: Boolean, micGranted: Boolean) {
        if (cameraGranted && micGranted) {
            _uiState.update { it.copy(permission = AvPermissionStatus.GRANTED) }
        }
    }

    /**
     * Drives the FLAGGED publisher. Because the bound implementation is [com.testlogon.android.data.webrtc
     * .StubBroadcastPublisher], this resolves to [GoLiveResult.NotConfigured] -> "broadcasting
     * unavailable" and never starts capture/peer/media.
     */
    private fun startBroadcast() {
        _uiState.update { it.copy(publish = GoLivePublishState.STARTING) }
        viewModelScope.launch {
            when (publisher.goLive(sessionId, inputId)) {
                GoLiveResult.Started ->
                    _uiState.update { it.copy(publish = GoLivePublishState.LIVE) }
                is GoLiveResult.Failed -> {
                    _uiState.update { it.copy(publish = GoLivePublishState.FAILED) }
                    _effects.trySend(GoLiveEffect.Notice(GoLiveNotice.GO_LIVE_FAILED))
                }
                GoLiveResult.NotConfigured -> {
                    _uiState.update {
                        it.copy(
                            publish = GoLivePublishState.UNAVAILABLE,
                            broadcastingUnavailable = true,
                        )
                    }
                    _effects.trySend(GoLiveEffect.Notice(GoLiveNotice.BROADCASTING_UNAVAILABLE))
                }
            }
        }
    }

    override fun onCleared() {
        publisher.stop()
    }

    companion object {
        const val ARG_SESSION_ID = "sessionId"
        const val ARG_INPUT_ID = "inputId"
    }
}
