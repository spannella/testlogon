package com.testlogon.android.data.preferences

import android.content.Context
import android.content.SharedPreferences
import com.testlogon.android.core.model.MediaPreferences
import com.testlogon.android.core.model.VideoResolution
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-079 — local mirror of the last server-confirmed [MediaPreferences] so the screen can render
 * saved values offline and survive relaunch (FR-7). The interface keeps the repository unit-testable
 * with an in-memory fake.
 */
interface MediaPreferencesMirror {
    fun read(): MediaPreferences?
    fun write(value: MediaPreferences)
}

/** SharedPreferences-backed mirror; values are non-sensitive (booleans, enum, opaque device ids). */
@Singleton
class MediaPreferencesStore @Inject constructor(
    @ApplicationContext context: Context,
) : MediaPreferencesMirror {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    override fun read(): MediaPreferences? {
        if (!prefs.contains(KEY_RESOLUTION)) return null
        return MediaPreferences(
            preferredAudioInputId = prefs.getString(KEY_MIC, null),
            preferredVideoInputId = prefs.getString(KEY_CAM, null),
            preferredAudioOutputId = prefs.getString(KEY_SPEAKER, null),
            defaultAudioMuted = prefs.getBoolean(KEY_MUTED, false),
            defaultVideoOff = prefs.getBoolean(KEY_VIDEO_OFF, false),
            videoResolution = VideoResolution.fromWire(prefs.getString(KEY_RESOLUTION, null)),
        )
    }

    override fun write(value: MediaPreferences) {
        prefs.edit()
            .putString(KEY_MIC, value.preferredAudioInputId)
            .putString(KEY_CAM, value.preferredVideoInputId)
            .putString(KEY_SPEAKER, value.preferredAudioOutputId)
            .putBoolean(KEY_MUTED, value.defaultAudioMuted)
            .putBoolean(KEY_VIDEO_OFF, value.defaultVideoOff)
            .putString(KEY_RESOLUTION, value.videoResolution.wire)
            .apply()
    }

    private companion object {
        const val PREFS_NAME = "tl_media_prefs"
        const val KEY_MIC = "mic"
        const val KEY_CAM = "cam"
        const val KEY_SPEAKER = "speaker"
        const val KEY_MUTED = "muted"
        const val KEY_VIDEO_OFF = "video_off"
        const val KEY_RESOLUTION = "resolution"
    }
}
