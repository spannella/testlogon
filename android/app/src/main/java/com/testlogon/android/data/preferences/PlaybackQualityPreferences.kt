package com.testlogon.android.data.preferences

import android.content.Context
import android.content.SharedPreferences
import com.testlogon.android.feature.player.PlaybackPolicy
import com.testlogon.android.feature.player.QualityPolicy
import com.testlogon.android.feature.player.VideoQuality
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-169 §6 — on-device HLS playback-quality + data-saver preferences.
 *
 * REAL-CONTRACT NOTE: the verified backend `GET`/`PUT /ui/media/preferences` (CALL-003) carries
 * WebRTC *call* defaults (mic/cam/speaker, video_resolution) — NOT HLS *playback* quality — so it is
 * intentionally not used here (AND-169 §5). This store keeps the playback quality / data-saver / cap
 * choice entirely local (SharedPreferences), surviving process death and app restart (FR-2). It is
 * the equivalent of the spec's AND-079 "MediaPreferencesRepository" extension; the WebRTC
 * `MediaPreferences*` of [com.testlogon.android.core.model.MediaPreferences] is a distinct concept.
 *
 * Values are non-sensitive enums/booleans; no encryption beyond app-private storage is needed (§8).
 */
interface PlaybackQualityPreferences {
    /** Emits the current [QualityPolicy] immediately, then on every change (FR-4 live application). */
    fun qualityPolicy(): Flow<QualityPolicy>

    /** Synchronous last-known policy (for the post-prepare apply, AND-169 §4.5). */
    fun currentPolicy(): QualityPolicy

    /** AND-169 — autoplay is disabled while data-saver (cap-on-metered) is enabled (FR/§1). */
    fun autoplayEnabled(): Boolean

    fun setPreferredQuality(quality: VideoQuality)
    fun setCapOnMetered(enabled: Boolean)
    fun setAutoplayEnabled(enabled: Boolean)
}

@Singleton
class PlaybackQualityPreferencesStore @Inject constructor(
    @ApplicationContext context: Context,
) : PlaybackQualityPreferences {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    override fun qualityPolicy(): Flow<QualityPolicy> = callbackFlow {
        trySend(currentPolicy())
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ -> trySend(currentPolicy()) }
        prefs.registerOnSharedPreferenceChangeListener(listener)
        awaitClose { prefs.unregisterOnSharedPreferenceChangeListener(listener) }
    }.distinctUntilChanged()

    override fun currentPolicy(): QualityPolicy = QualityPolicy(
        userSelection = VideoQuality.fromName(prefs.getString(KEY_QUALITY, null)),
        capOnMetered = prefs.getBoolean(KEY_CAP_METERED, true),
        meteredMaxHeightPx = prefs.getInt(KEY_METERED_MAX_HEIGHT, QualityPolicy.DEFAULT_METERED_MAX_HEIGHT_PX),
    )

    override fun autoplayEnabled(): Boolean =
        PlaybackPolicy.autoplayEnabled(
            userAutoplay = prefs.getBoolean(KEY_AUTOPLAY, true),
            capOnMetered = prefs.getBoolean(KEY_CAP_METERED, true),
        )

    override fun setPreferredQuality(quality: VideoQuality) {
        prefs.edit().putString(KEY_QUALITY, quality.name).apply()
    }

    override fun setCapOnMetered(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_CAP_METERED, enabled).apply()
    }

    override fun setAutoplayEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_AUTOPLAY, enabled).apply()
    }

    private companion object {
        const val PREFS_NAME = "tl_playback_quality_prefs"
        const val KEY_QUALITY = "media_preferred_quality"
        const val KEY_CAP_METERED = "media_cap_on_metered"
        const val KEY_METERED_MAX_HEIGHT = "media_metered_max_height"
        const val KEY_AUTOPLAY = "media_autoplay_enabled"
    }
}

/** AND-169 — binds the playback-quality preferences seam. */
@Module
@InstallIn(SingletonComponent::class)
abstract class PlaybackQualityPreferencesModule {
    @Binds
    @Singleton
    abstract fun bindPlaybackQualityPreferences(
        impl: PlaybackQualityPreferencesStore,
    ): PlaybackQualityPreferences
}
