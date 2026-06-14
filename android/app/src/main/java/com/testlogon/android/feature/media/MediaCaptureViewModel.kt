package com.testlogon.android.feature.media

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.webrtc.BroadcastPublisher
import com.testlogon.android.data.webrtc.CaptureSelectionReducer
import com.testlogon.android.data.webrtc.CaptureSelectionState
import com.testlogon.android.data.webrtc.GoLiveResult
import com.testlogon.android.data.webrtc.MediaDeviceProvider
import com.testlogon.android.data.webrtc.ResolutionPreset
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
 * AND-292 — local media-capture + device-selection presentation logic.
 *
 * Owns the pure [com.testlogon.android.data.webrtc.CaptureSelectionState] (selected camera/mic/audio
 * output, mute + camera-off toggles, mirroring, resolution), driven through [CaptureSelectionReducer]. The
 * device inventory comes from the [MediaDeviceProvider] seam (the FLAGGED [com.testlogon.android.data
 * .webrtc.StubMediaDeviceProvider] returns EMPTY — never touches hardware). The capture START is the
 * FLAGGED [BroadcastPublisher]; with the stub bound it ALWAYS resolves to "capture unavailable" and never
 * opens a camera/mic or starts a peer.
 *
 * One-shot effects use Channel + receiveAsFlow (never distinctUntilChanged on a StateFlow).
 */
@HiltViewModel
class MediaCaptureViewModel @Inject constructor(
    private val deviceProvider: MediaDeviceProvider,
    private val publisher: BroadcastPublisher,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MediaCaptureUiState())
    val uiState: StateFlow<MediaCaptureUiState> = _uiState.asStateFlow()

    private val _effects = Channel<MediaCaptureEffect>(Channel.BUFFERED)
    val effects = _effects.receiveAsFlow()

    init {
        refreshDevices()
    }

    /** Re-enumerate available devices (the stub provider returns an empty set; never opens hardware). */
    fun refreshDevices() {
        viewModelScope.launch {
            val devices = deviceProvider.enumerate()
            _uiState.update {
                it.copy(selection = CaptureSelectionReducer.onDevicesEnumerated(it.selection, devices))
            }
        }
    }

    fun onToggleCamera() = mutate { CaptureSelectionReducer.toggleCamera(it) }

    fun onToggleMute() = mutate { CaptureSelectionReducer.toggleMute(it) }

    fun onSwitchCamera() = mutate { CaptureSelectionReducer.switchCamera(it) }

    fun onSelectCamera(cameraId: String) = mutate { CaptureSelectionReducer.selectCamera(it, cameraId) }

    fun onSelectMicrophone(micId: String) = mutate { CaptureSelectionReducer.selectMicrophone(it, micId) }

    fun onSelectAudioOutput(outputId: String) =
        mutate { CaptureSelectionReducer.selectAudioOutput(it, outputId) }

    fun onSelectResolution(preset: ResolutionPreset) =
        mutate { CaptureSelectionReducer.setResolution(it, preset) }

    private fun mutate(reduce: (CaptureSelectionState) -> CaptureSelectionState) {
        _uiState.update { it.copy(selection = reduce(it.selection)) }
    }

    /**
     * Begin capturing + going live for [sessionId]/[inputId]. Drives the FLAGGED publisher; with the stub
     * bound this resolves to [GoLiveResult.NotConfigured] -> "capture unavailable" and never opens a
     * camera/mic or starts a peer.
     */
    fun onStartCapture(sessionId: String, inputId: String) {
        _uiState.update { it.copy(starting = true) }
        viewModelScope.launch {
            when (publisher.goLive(sessionId, inputId)) {
                GoLiveResult.Started ->
                    _uiState.update {
                        it.copy(
                            starting = false,
                            broadcastingUnavailable = false,
                            selection = it.selection.copy(captureConfigured = true),
                        )
                    }
                is GoLiveResult.Failed -> {
                    _uiState.update { it.copy(starting = false) }
                    _effects.trySend(MediaCaptureEffect.Notice(MediaCaptureNotice.CAPTURE_FAILED))
                }
                GoLiveResult.NotConfigured -> {
                    _uiState.update { it.copy(starting = false, broadcastingUnavailable = true) }
                    _effects.trySend(MediaCaptureEffect.Notice(MediaCaptureNotice.CAPTURE_UNAVAILABLE))
                }
            }
        }
    }

    override fun onCleared() {
        publisher.stop()
    }
}
