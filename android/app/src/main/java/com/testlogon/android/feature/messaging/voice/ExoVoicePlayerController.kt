package com.testlogon.android.feature.messaging.voice

import android.content.Context
import androidx.media3.common.MediaItem
import androidx.media3.common.Player
import androidx.media3.exoplayer.ExoPlayer
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
 * AND-133 — runtime [VoicePlayerController] over a single [ExoPlayer]. Created PER-SCREEN by
 * [VoicePlayerFactory] and released from the composer/thread lifecycle — NOT an eager DI singleton.
 * Position is polled (~50ms) only while playing. NOT JVM-unit-tested (ExoPlayer is runtime-only).
 */
class ExoVoicePlayerController(
    appContext: Context,
) : VoicePlayerController {

    private val player: ExoPlayer = ExoPlayer.Builder(appContext).build()
    private val _playback = MutableStateFlow(VoicePlaybackState())
    override val playback: StateFlow<VoicePlaybackState> = _playback.asStateFlow()

    private val scope = CoroutineScope(Dispatchers.Main)
    private var pollJob: Job? = null
    private var boundUrl: String? = null

    init {
        player.addListener(object : Player.Listener {
            override fun onPlaybackStateChanged(state: Int) {
                if (state == Player.STATE_READY) {
                    _playback.value = _playback.value.copy(durationMs = player.duration.coerceAtLeast(0L))
                } else if (state == Player.STATE_ENDED) {
                    player.pause()
                    player.seekTo(0L)
                    _playback.value = _playback.value.copy(playing = false, positionMs = 0L)
                    stopPolling()
                }
            }

            override fun onIsPlayingChanged(isPlaying: Boolean) {
                _playback.value = _playback.value.copy(playing = isPlaying)
                if (isPlaying) startPolling() else stopPolling()
            }

            override fun onPlayerError(error: androidx.media3.common.PlaybackException) {
                _playback.value = _playback.value.copy(
                    playing = false,
                    error = VoiceError.Playback(error.errorCodeName),
                )
            }
        })
    }

    override fun toggle(messageId: String, url: String) {
        val current = _playback.value
        if (current.activeMessageId == messageId && boundUrl == url) {
            if (player.isPlaying) player.pause() else player.play()
            return
        }
        // Switch clips: stop the previous, bind & play the new one (one-at-a-time).
        player.stop()
        player.clearMediaItems()
        player.setMediaItem(MediaItem.fromUri(url))
        player.prepare()
        player.play()
        boundUrl = url
        _playback.value = VoicePlaybackState(activeMessageId = messageId, playing = true)
    }

    override fun seekTo(messageId: String, fraction: Float) {
        if (_playback.value.activeMessageId != messageId) return
        val target = _playback.value.positionForFraction(fraction)
        player.seekTo(target)
        _playback.value = _playback.value.copy(positionMs = target)
    }

    override fun release() {
        stopPolling()
        scope.cancel()
        player.release()
    }

    private fun startPolling() {
        if (pollJob?.isActive == true) return
        pollJob = scope.launch {
            while (isActive) {
                _playback.value = _playback.value.copy(
                    positionMs = player.currentPosition.coerceAtLeast(0L),
                    durationMs = player.duration.coerceAtLeast(0L),
                )
                delay(50L)
            }
        }
    }

    private fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }
}
