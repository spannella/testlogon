package com.testlogon.android.feature.golive

/**
 * AND-288 — UI state + one-shot effects for the host "Go Live" entry.
 *
 * The screen owns the CAMERA + RECORD_AUDIO runtime permission flow (AndroidX activity-result); the
 * ViewModel owns the availability/permission state machine and the go-live action, which is gated behind
 * the FLAGGED [com.testlogon.android.data.webrtc.BroadcastPublisher] seam.
 */
data class GoLiveUiState(
    val permission: AvPermissionStatus = AvPermissionStatus.NOT_REQUESTED,
    val publish: GoLivePublishState = GoLivePublishState.IDLE,
    /** True once the engine has reported it is not configured (broadcasting unavailable). */
    val broadcastingUnavailable: Boolean = false,
) {
    /** The go-live button is enabled only when both permissions are granted and not already starting. */
    val canGoLive: Boolean
        get() = permission == AvPermissionStatus.GRANTED && publish != GoLivePublishState.STARTING
}

/** Combined CAMERA + RECORD_AUDIO permission status. */
enum class AvPermissionStatus { NOT_REQUESTED, GRANTED, DENIED, PERMANENTLY_DENIED }

/** Publish progress as the UI sees it. */
enum class GoLivePublishState { IDLE, STARTING, LIVE, FAILED, UNAVAILABLE }

/** One-shot effects consumed exactly once by the screen (Channel + receiveAsFlow). */
sealed interface GoLiveEffect {
    /** Ask the screen to launch the system permission request for CAMERA + RECORD_AUDIO. */
    data object RequestPermissions : GoLiveEffect

    /** Ask the screen to deep-link to the app's system settings (permanent denial). */
    data object OpenAppSettings : GoLiveEffect

    /** Surface a transient notice (e.g. "broadcasting unavailable"). */
    data class Notice(val kind: GoLiveNotice) : GoLiveEffect
}

enum class GoLiveNotice { BROADCASTING_UNAVAILABLE, GO_LIVE_FAILED }
