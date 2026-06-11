package com.testlogon.android.data.webrtc

/**
 * AND-292 — pure device-selection + capture-toggle state for the local media-capture surface.
 *
 * This is the single source of truth for which camera/mic/audio-output is selected and the mute /
 * camera-off toggles (and mirroring + resolution). It is a pure value type collapsed from the enumerated
 * [MediaDevices] by [CaptureSelectionReducer], so the whole selection state machine is JVM-unit-testable
 * with a fixture inventory and never opens a camera/mic. The actual capture START stays behind the FLAGGED
 * [BroadcastPublisher] ([GoLiveResult.NotConfigured]); [captureConfigured] reflects whether a real engine
 * is wired (false while flagged) so the UI can surface "broadcasting unavailable".
 *
 * Mirroring follows the selected camera facing (front mirrored, back not — AND-292 FR-3). The
 * camera-switch control is enabled only with >= 2 cameras ([canSwitchCamera]).
 */
data class CaptureSelectionState(
    val devices: MediaDevices = MediaDevices.EMPTY,
    val selectedCameraId: String? = null,
    val selectedMicId: String? = null,
    val selectedAudioOutputId: String? = null,
    val cameraOff: Boolean = false,
    val micMuted: Boolean = false,
    val resolution: ResolutionPreset = ResolutionPreset.HD_720,
    /** True only when a real (non-FLAGGED) capture engine is wired. The stub keeps this false. */
    val captureConfigured: Boolean = false,
) {
    val selectedCamera: MediaDevice? get() = devices.cameraById(selectedCameraId)

    /** Front-camera selection drives preview mirroring (AND-292 FR-3 / AND-293 FR-2). */
    val isFrontFacing: Boolean
        get() = selectedCamera?.facing != CameraFacing.BACK

    val cameraCount: Int get() = devices.cameraCount

    /** Switch is enabled only with two or more cameras (AND-292 FR-3 / AC-3). */
    val canSwitchCamera: Boolean get() = devices.hasMultipleCameras && !cameraOff

    /** True when the enumeration found no camera at all (controls disable gracefully — AND-292 §8). */
    val hasNoCamera: Boolean get() = !devices.hasCamera
}

/**
 * AND-292 — pure reducer for the device-selection state machine. Every function returns a new
 * [CaptureSelectionState]; nothing here opens hardware. Illegal/no-op selections (unknown id, single
 * camera switch, no camera) are coerced to a safe no-op so the machine never crashes.
 */
object CaptureSelectionReducer {

    /**
     * Apply a freshly enumerated [devices] set, (re)selecting sensible defaults: front camera, first mic,
     * first audio output. Preserves a still-present prior selection across re-enumeration.
     */
    fun onDevicesEnumerated(
        state: CaptureSelectionState,
        devices: MediaDevices,
    ): CaptureSelectionState {
        val camera = devices.cameraById(state.selectedCameraId) ?: devices.defaultCamera
        val mic = devices.microphones.firstOrNull { it.id == state.selectedMicId }
            ?: devices.defaultMicrophone
        val output = devices.audioOutputs.firstOrNull { it.id == state.selectedAudioOutputId }
            ?: devices.defaultAudioOutput
        return state.copy(
            devices = devices,
            selectedCameraId = camera?.id,
            selectedMicId = mic?.id,
            selectedAudioOutputId = output?.id,
        )
    }

    /** Select a specific camera by id; ignored (no-op) if the id is not a known camera. */
    fun selectCamera(state: CaptureSelectionState, cameraId: String): CaptureSelectionState =
        if (state.devices.cameraById(cameraId) != null) {
            state.copy(selectedCameraId = cameraId)
        } else {
            state
        }

    /** Select a microphone by id; ignored if unknown. */
    fun selectMicrophone(state: CaptureSelectionState, micId: String): CaptureSelectionState =
        if (state.devices.microphones.any { it.id == micId }) {
            state.copy(selectedMicId = micId)
        } else {
            state
        }

    /** Select an audio output by id; ignored if unknown. */
    fun selectAudioOutput(state: CaptureSelectionState, outputId: String): CaptureSelectionState =
        if (state.devices.audioOutputs.any { it.id == outputId }) {
            state.copy(selectedAudioOutputId = outputId)
        } else {
            state
        }

    /**
     * Flip between front and back camera. No-op when fewer than two cameras exist (AND-292 FR-3/AC-3) or
     * when the camera is off. Picks the first camera whose facing differs from the current selection.
     */
    fun switchCamera(state: CaptureSelectionState): CaptureSelectionState {
        if (!state.canSwitchCamera) return state
        val current = state.selectedCamera
        val next = state.devices.cameras.firstOrNull { it.facing != current?.facing }
            ?: state.devices.cameras.firstOrNull { it.id != current?.id }
            ?: return state
        return state.copy(selectedCameraId = next.id)
    }

    /** Toggle the camera-off state (FR-1). Pure flag flip; no HAL teardown happens here. */
    fun toggleCamera(state: CaptureSelectionState): CaptureSelectionState =
        state.copy(cameraOff = !state.cameraOff)

    fun setCameraOff(state: CaptureSelectionState, off: Boolean): CaptureSelectionState =
        state.copy(cameraOff = off)

    /** Toggle mic mute (FR-2). Pure flag flip; mute is reversible and never tears down the mic. */
    fun toggleMute(state: CaptureSelectionState): CaptureSelectionState =
        state.copy(micMuted = !state.micMuted)

    fun setMuted(state: CaptureSelectionState, muted: Boolean): CaptureSelectionState =
        state.copy(micMuted = muted)

    /** Choose a capture resolution preset (FR-4). Pure; a real engine would reconfigure the capturer. */
    fun setResolution(state: CaptureSelectionState, preset: ResolutionPreset): CaptureSelectionState =
        state.copy(resolution = preset)
}
