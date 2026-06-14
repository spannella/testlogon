package com.testlogon.android.feature.player

import androidx.media3.common.Player
import kotlinx.coroutines.flow.StateFlow

/**
 * AND-166 — the seam over a single ExoPlayer used by the reusable video UI. Like the AND-133 voice
 * controller, the interface keeps ExoPlayer/Media3 out of unit-tested code: the runtime
 * [ExoVideoPlayerController] is the only ExoPlayer-touching class and is created PER-SCREEN by
 * [VideoPlayerFactory], released on screen disposal — NEVER an eager DI singleton @Provides.
 *
 * Pure state ([PlayerUiState]) and all mapping ([PlayerStateMapper], [PlayerTimeFormat],
 * [MediaSourceResolver]) live in PlayerLogic.kt and are JVM-tested; this seam only brokers the
 * runtime player.
 */
interface VideoPlayerController {

    /** Observable, pure playback state collected by ViewModels/Compose. */
    val state: StateFlow<PlayerUiState>

    /**
     * The underlying Media3 [Player] for binding to a PlayerView surface. Runtime-only; never touched
     * by unit-tested code. Bind/unbind happens in the Compose [VideoPlayer] surface.
     */
    fun player(): Player

    /** Sets/replaces the media (HLS or progressive resolved from [spec]) and prepares it. */
    fun setMedia(spec: MediaSourceSpec, autoPlay: Boolean = true)

    /** Convenience for a bare URI (AUTO type), preserving AND-166's simple setMediaItem path. */
    fun setMediaUri(uri: String, autoPlay: Boolean = true)

    fun play()
    fun pause()
    fun playPause()

    /** Seeks to [positionMs] (clamped by the player). */
    fun seekTo(positionMs: Long)

    /** Relative skip by [deltaMs] (negative rewinds); used by the 10s skip affordances. */
    fun skipBy(deltaMs: Long)

    /** Sets volume 0f..1f. */
    fun setVolume(volume: Float)

    /**
     * AND-169 — applies the resolved [EffectiveQuality] to the underlying ABR track selector live,
     * without recreating the player or restarting playback position (FR-4). Maps to
     * TrackSelectionParameters max-video-size / clear constraints via the pure [QualityTrackParams].
     */
    fun applyQuality(quality: EffectiveQuality)

    /** Re-prepares after an error (AND-168 Retry / AND-167 bounded recovery). */
    fun retry()

    /** Stops and releases the underlying ExoPlayer; the controller must not be reused after this. */
    fun release()
}
