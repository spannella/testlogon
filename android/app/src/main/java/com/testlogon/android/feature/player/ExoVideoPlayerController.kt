package com.testlogon.android.feature.player

import androidx.media3.common.C
import androidx.media3.common.Format
import androidx.media3.common.PlaybackException
import androidx.media3.common.Player
import androidx.media3.common.Timeline
import androidx.media3.common.Tracks
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.trackselection.DefaultTrackSelector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * AND-166 / AND-167 — the runtime [VideoPlayerController] over a single [ExoPlayer]. Created
 * PER-SCREEN by [VideoPlayerFactory] and released from the screen/ViewModel lifecycle — NOT an eager
 * DI singleton (exactly the AND-131 InlineVideoPlayer / AND-133 voice pattern). Position is polled
 * (~250ms) only while playing. NOT JVM-unit-tested (ExoPlayer is runtime-only); all pure logic it
 * relies on ([PlayerStateMapper], [MediaSourceResolver]) lives in PlayerLogic.kt and IS tested.
 *
 * ABR (AND-167 FR4) is on by default via [DefaultTrackSelector] with no pinned video track; live vs
 * VOD (FR3) is derived from the loaded timeline; behind-live-window (AC4) auto-recovers to the edge.
 */
@OptIn(UnstableApi::class)
class ExoVideoPlayerController(
    private val player: ExoPlayer,
    private val sourceFactory: MediaSourceFactoryProvider,
) : VideoPlayerController {

    private val _state = MutableStateFlow(PlayerUiState())
    override val state: StateFlow<PlayerUiState> = _state.asStateFlow()

    private val scope = CoroutineScope(Dispatchers.Main)
    private var pollJob: Job? = null
    private var pendingRetries = 0

    init {
        player.addListener(object : Player.Listener {
            override fun onPlaybackStateChanged(playbackState: Int) {
                val phase = PlayerStateMapper.toPhase(playbackState)
                _state.value = _state.value.copy(
                    phase = phase,
                    durationMs = if (player.duration == C.TIME_UNSET) {
                        PlayerUiState.DURATION_UNSET
                    } else {
                        player.duration
                    },
                )
                if (playbackState == Player.STATE_READY) pendingRetries = 0
            }

            override fun onIsPlayingChanged(isPlaying: Boolean) {
                _state.value = _state.value.copy(isPlaying = isPlaying)
                if (isPlaying) startPolling() else stopPolling()
            }

            override fun onTimelineChanged(timeline: Timeline, reason: Int) {
                _state.value = _state.value.copy(isLive = player.isCurrentMediaItemLive)
            }

            override fun onTracksChanged(tracks: Tracks) {
                val videoFormat = selectedVideoFormat(tracks)
                _state.value = _state.value.copy(
                    selectedVideoHeight = videoFormat?.height ?: PlayerUiState.VALUE_UNSET,
                    selectedVideoBitrate = videoFormat?.bitrate ?: PlayerUiState.VALUE_UNSET,
                )
            }

            override fun onVolumeChanged(volume: Float) {
                _state.value = _state.value.copy(volume = volume)
            }

            override fun onPlayerError(error: PlaybackException) {
                // AND-167 AC4: behind-live-window auto-recovers to the edge instead of surfacing.
                if (error.errorCode == PlaybackException.ERROR_CODE_BEHIND_LIVE_WINDOW) {
                    player.seekToDefaultPosition()
                    player.prepare()
                    return
                }
                _state.value = _state.value.copy(
                    isPlaying = false,
                    error = PlayerStateMapper.toError(error.errorCode, error.errorCodeName),
                )
            }
        })
    }

    override fun player(): Player = player

    override fun setMedia(spec: MediaSourceSpec, autoPlay: Boolean) {
        pendingRetries = 0
        _state.value = _state.value.copy(error = null)
        player.setMediaSource(sourceFactory.create(spec))
        player.prepare()
        player.playWhenReady = autoPlay
    }

    override fun setMediaUri(uri: String, autoPlay: Boolean) =
        setMedia(MediaSourceSpec(uri = uri), autoPlay)

    override fun play() {
        player.play()
    }

    override fun pause() {
        player.pause()
    }

    override fun playPause() {
        if (player.isPlaying) player.pause() else player.play()
    }

    override fun seekTo(positionMs: Long) {
        player.seekTo(positionMs.coerceAtLeast(0L))
        _state.value = _state.value.copy(positionMs = positionMs.coerceAtLeast(0L))
    }

    override fun skipBy(deltaMs: Long) {
        val target = (player.currentPosition + deltaMs).coerceAtLeast(0L)
        player.seekTo(target)
    }

    override fun setVolume(volume: Float) {
        player.volume = volume.coerceIn(0f, 1f)
    }

    override fun applyQuality(quality: EffectiveQuality) {
        val params = quality.toTrackParams()
        val builder = player.trackSelectionParameters.buildUpon()
        when {
            params.forceLowest -> builder.setMaxVideoSize(1, 1)
            params.maxHeightPx != null -> builder.setMaxVideoSize(Int.MAX_VALUE, params.maxHeightPx)
            else -> builder.clearVideoSizeConstraints()
        }
        player.trackSelectionParameters = builder.build()
    }

    override fun retry() {
        _state.value = _state.value.copy(error = null)
        player.seekToDefaultPosition()
        player.prepare()
        player.play()
    }

    override fun release() {
        stopPolling()
        scope.cancel()
        player.release()
    }

    private fun selectedVideoFormat(tracks: Tracks): Format? =
        tracks.groups
            .firstOrNull { it.type == C.TRACK_TYPE_VIDEO && it.isSelected }
            ?.let { group ->
                (0 until group.length)
                    .firstOrNull { group.isTrackSelected(it) }
                    ?.let { group.getTrackFormat(it) }
            }

    private fun startPolling() {
        if (pollJob?.isActive == true) return
        pollJob = scope.launch {
            while (isActive) {
                _state.value = _state.value.copy(
                    positionMs = player.currentPosition.coerceAtLeast(0L),
                    bufferedPositionMs = player.bufferedPosition.coerceAtLeast(0L),
                    durationMs = if (player.duration == C.TIME_UNSET) {
                        PlayerUiState.DURATION_UNSET
                    } else {
                        player.duration
                    },
                )
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    private fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    companion object {
        private const val POLL_INTERVAL_MS = 250L

        /**
         * AND-167 FR4 — an ABR-friendly [DefaultTrackSelector]: no forced highest bitrate, no SD cap
         * (AND-169 owns caps), mixed-MIME adaptiveness allowed so the default AdaptiveTrackSelection
         * drives variant switching from bandwidth estimates.
         */
        fun abrTrackSelector(context: android.content.Context): DefaultTrackSelector =
            DefaultTrackSelector(context).apply {
                setParameters(
                    buildUponParameters()
                        .setForceHighestSupportedBitrate(false)
                        .setAllowVideoMixedMimeTypeAdaptiveness(true)
                        .build(),
                )
            }
    }
}
