package com.testlogon.android.core.model

/**
 * AND-079 — call media (WebRTC) preferences, mirroring the backend
 * `MediaPreferencesIn` / `MediaPreferencesOut` contract (web `src/api/types.ts`).
 *
 * Verified endpoints: GET / PUT `/ui/media/preferences`.
 */
enum class VideoResolution(val wire: String) {
    P360("360"),
    P480("480"),
    P720("720"),
    P1080("1080"),
    ;

    companion object {
        fun fromWire(value: String?): VideoResolution =
            entries.firstOrNull { it.wire == value } ?: P720
    }
}

/**
 * Preferred capture/playback device ids are opaque, nullable strings; null means "system default".
 * Server defaults: muted=false, videoOff=false, resolution="720".
 */
data class MediaPreferences(
    val preferredAudioInputId: String? = null,
    val preferredVideoInputId: String? = null,
    val preferredAudioOutputId: String? = null,
    val defaultAudioMuted: Boolean = false,
    val defaultVideoOff: Boolean = false,
    val videoResolution: VideoResolution = VideoResolution.P720,
)
