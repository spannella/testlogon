package com.testlogon.android.data.webrtc

/**
 * AND-292 — pure (SDK-free) device-enumeration domain model for the local media-capture seam.
 *
 * These types describe the audio/video capture + output devices the host can choose between (front/back
 * camera, microphones, speaker/earpiece audio outputs). They are deliberately free of any org.webrtc /
 * android.* / hardware types so the enumeration model + the [CaptureSelectionState] reducer stay
 * JVM-unit-testable and never open a real Camera/AudioManager. The [MediaDeviceProvider] seam supplies the
 * set; the FLAGGED [BroadcastPublisher] still owns the (NotConfigured) capture start, so nothing here
 * opens a camera/mic.
 */

/** What kind of device a [MediaDevice] is. */
enum class MediaDeviceKind {
    /** A camera capture device (front- or back-facing). */
    CAMERA,

    /** A microphone audio capture device. */
    MICROPHONE,

    /** An audio output (speaker / earpiece / wired / bluetooth). */
    AUDIO_OUTPUT,
}

/** Camera lens facing. [UNKNOWN] for external/USB or undeterminable lenses. */
enum class CameraFacing { FRONT, BACK, UNKNOWN }

/** Audio output routing target. Mirrors the web call's speaker/earpiece toggle. */
enum class AudioOutputKind { EARPIECE, SPEAKER, WIRED, BLUETOOTH, UNKNOWN }

/**
 * One enumerated device. [id] is a stable, opaque, redaction-safe identifier (never a raw camera serial in
 * logs — only front/back/kind is log-safe per AND-292 §8). [facing] is meaningful only for [CameraFacing]
 * cameras; [audioOutputKind] only for [MediaDeviceKind.AUDIO_OUTPUT].
 */
data class MediaDevice(
    val id: String,
    val kind: MediaDeviceKind,
    val label: String,
    val facing: CameraFacing = CameraFacing.UNKNOWN,
    val audioOutputKind: AudioOutputKind = AudioOutputKind.UNKNOWN,
) {
    val isFrontCamera: Boolean get() = kind == MediaDeviceKind.CAMERA && facing == CameraFacing.FRONT
    val isBackCamera: Boolean get() = kind == MediaDeviceKind.CAMERA && facing == CameraFacing.BACK
}

/**
 * The enumerated device inventory. Convenience views ([cameras]/[microphones]/[audioOutputs]) filter by
 * kind; [cameraCount] gates the camera-switch control (disabled when < 2 — AND-292 FR-3/AC-3).
 */
data class MediaDevices(
    val devices: List<MediaDevice> = emptyList(),
) {
    val cameras: List<MediaDevice> get() = devices.filter { it.kind == MediaDeviceKind.CAMERA }
    val microphones: List<MediaDevice> get() = devices.filter { it.kind == MediaDeviceKind.MICROPHONE }
    val audioOutputs: List<MediaDevice> get() = devices.filter { it.kind == MediaDeviceKind.AUDIO_OUTPUT }

    val cameraCount: Int get() = cameras.size
    val hasCamera: Boolean get() = cameras.isNotEmpty()
    val hasMultipleCameras: Boolean get() = cameras.size >= 2

    fun cameraById(id: String?): MediaDevice? = cameras.firstOrNull { it.id == id }

    /** First front camera, else first camera (front is the default capture per AND-292 §4.2). */
    val defaultCamera: MediaDevice?
        get() = cameras.firstOrNull { it.facing == CameraFacing.FRONT } ?: cameras.firstOrNull()

    val defaultMicrophone: MediaDevice? get() = microphones.firstOrNull()
    val defaultAudioOutput: MediaDevice? get() = audioOutputs.firstOrNull()

    companion object {
        val EMPTY = MediaDevices()
    }
}

/** Capture resolution presets (AND-292 §6 — SD/720/1080 @ 30fps). */
enum class ResolutionPreset(val width: Int, val height: Int, val fps: Int) {
    SD_480(640, 480, 30),
    HD_720(1280, 720, 30),
    FHD_1080(1920, 1080, 30),
}
