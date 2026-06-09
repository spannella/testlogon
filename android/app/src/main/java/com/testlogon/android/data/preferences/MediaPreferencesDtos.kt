package com.testlogon.android.data.preferences

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.MediaPreferences
import com.testlogon.android.core.model.VideoResolution

/**
 * AND-079 — Moshi DTOs for `/ui/media/preferences`, mirroring `MediaPreferencesIn` /
 * `MediaPreferencesOut` (verified: `src/api/types.ts`). The Out type carries server-managed ad
 * fields which this feature ignores (they are not declared here, so Moshi drops them).
 */
@JsonClass(generateAdapter = true)
data class MediaPreferencesOutDto(
    @Json(name = "preferred_audio_input_id") val preferredAudioInputId: String? = null,
    @Json(name = "preferred_video_input_id") val preferredVideoInputId: String? = null,
    @Json(name = "preferred_audio_output_id") val preferredAudioOutputId: String? = null,
    @Json(name = "default_audio_muted") val defaultAudioMuted: Boolean? = null,
    @Json(name = "default_video_off") val defaultVideoOff: Boolean? = null,
    @Json(name = "video_resolution") val videoResolution: String? = null,
)

/** PUT body — the full desired state (server overwrites on PUT). */
@JsonClass(generateAdapter = true)
data class MediaPreferencesInDto(
    @Json(name = "preferred_audio_input_id") val preferredAudioInputId: String? = null,
    @Json(name = "preferred_video_input_id") val preferredVideoInputId: String? = null,
    @Json(name = "preferred_audio_output_id") val preferredAudioOutputId: String? = null,
    @Json(name = "default_audio_muted") val defaultAudioMuted: Boolean = false,
    @Json(name = "default_video_off") val defaultVideoOff: Boolean = false,
    @Json(name = "video_resolution") val videoResolution: String = VideoResolution.P720.wire,
)

internal fun MediaPreferencesOutDto.toDomain(): MediaPreferences = MediaPreferences(
    preferredAudioInputId = preferredAudioInputId,
    preferredVideoInputId = preferredVideoInputId,
    preferredAudioOutputId = preferredAudioOutputId,
    defaultAudioMuted = defaultAudioMuted ?: false,
    defaultVideoOff = defaultVideoOff ?: false,
    videoResolution = VideoResolution.fromWire(videoResolution),
)

internal fun MediaPreferences.toRequestDto(): MediaPreferencesInDto = MediaPreferencesInDto(
    preferredAudioInputId = preferredAudioInputId,
    preferredVideoInputId = preferredVideoInputId,
    preferredAudioOutputId = preferredAudioOutputId,
    defaultAudioMuted = defaultAudioMuted,
    defaultVideoOff = defaultVideoOff,
    videoResolution = videoResolution.wire,
)
