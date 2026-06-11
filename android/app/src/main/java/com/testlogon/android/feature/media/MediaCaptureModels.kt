package com.testlogon.android.feature.media

import com.testlogon.android.data.webrtc.CaptureSelectionState

/**
 * AND-292 — UI state + one-shot effects for the local media-capture / device-selection surface.
 *
 * The capture controls (camera toggle, mute, switch, resolution, device pickers) operate on the pure
 * [com.testlogon.android.data.webrtc.CaptureSelectionState] reducer; the actual capture START is gated
 * behind the FLAGGED [com.testlogon.android.data.webrtc.BroadcastPublisher] seam, so
 * `broadcastingUnavailable` surfaces once the engine reports NotConfigured. Nothing here opens a
 * camera/mic.
 */
data class MediaCaptureUiState(
    val selection: CaptureSelectionState = CaptureSelectionState(),
    /** True while a (FLAGGED) go-live attempt is in flight. */
    val starting: Boolean = false,
    /** True once the engine reported it is not configured (broadcasting unavailable). */
    val broadcastingUnavailable: Boolean = false,
)

/** One-shot effects consumed exactly once by the screen (Channel + receiveAsFlow). */
sealed interface MediaCaptureEffect {
    /** Surface a transient notice (e.g. "broadcasting unavailable / capture not configured"). */
    data class Notice(val kind: MediaCaptureNotice) : MediaCaptureEffect
}

enum class MediaCaptureNotice { CAPTURE_UNAVAILABLE, CAPTURE_FAILED }
