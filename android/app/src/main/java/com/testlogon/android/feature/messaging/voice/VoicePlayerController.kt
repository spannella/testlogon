package com.testlogon.android.feature.messaging.voice

import kotlinx.coroutines.flow.StateFlow

/**
 * AND-133 — playback controller for voice bubbles. Wraps a single ExoPlayer so only one clip plays
 * at a time across the screen. The interface keeps ExoPlayer out of unit-tested code; the runtime
 * [ExoVoicePlayerController] is the only ExoPlayer-touching class and is lifecycle-scoped (released
 * on screen disposal), never an eager DI singleton.
 */
interface VoicePlayerController {
    val playback: StateFlow<VoicePlaybackState>

    /** Prepare (or resume) playback of [url], identified by [messageId]; starts a new clip pauses any other. */
    fun toggle(messageId: String, url: String)

    /** Seek the currently-bound clip to [fraction] (0..1) of its duration. */
    fun seekTo(messageId: String, fraction: Float)

    /** Stop and release the underlying player. */
    fun release()
}

/**
 * AND-133 — shared playback state. [activeMessageId] identifies which bubble is currently bound so
 * the UI can show progress on exactly one bubble (one-at-a-time).
 */
data class VoicePlaybackState(
    val activeMessageId: String? = null,
    val playing: Boolean = false,
    val positionMs: Long = 0L,
    val durationMs: Long = 0L,
    val error: VoiceError? = null,
) {
    val fraction: Float get() = if (durationMs <= 0L) 0f else (positionMs.toFloat() / durationMs).coerceIn(0f, 1f)

    /** Position (ms) for a [fraction] of [durationMs]; pure seek mapping, unit-testable. */
    fun positionForFraction(fraction: Float): Long =
        (durationMs * fraction.coerceIn(0f, 1f)).toLong()
}
