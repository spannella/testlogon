package com.testlogon.android.feature.messaging.voice

import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File

/**
 * AND-133 — recorder abstraction. The platform `MediaRecorder` is hidden behind this interface so
 * the composer logic is testable with a fake; the concrete [MediaRecorderVoiceRecorder] is the only
 * class that touches Android media APIs (runtime-only, NOT JVM-unit-tested).
 */
interface VoiceRecorder {
    val state: StateFlow<RecorderState>

    /** Max amplitude (0..32767) emitted at ~60ms cadence while recording. */
    val amplitudes: SharedFlow<Int>

    /** Begin capturing AAC-LC/m4a into [outputFile]. Transitions state to [RecorderState.Recording]. */
    fun start(outputFile: File)

    /** Stop and finalize; returns null (and deletes the temp file) if below [RecorderLimits.MIN_DURATION_MS]. */
    fun stop(): RecordingResult?

    /** Abort and delete the temp file. */
    fun cancel()

    /** Release any underlying recorder resources (call from the screen's lifecycle). */
    fun release()
}

sealed interface RecorderState {
    data object Idle : RecorderState
    data class Recording(val elapsedMs: Long) : RecorderState
    data class Stopped(val result: RecordingResult) : RecorderState
    data class Error(val cause: VoiceError) : RecorderState
}

data class RecordingResult(
    val file: File,
    val durationMs: Long,
    /** Raw max-amplitude samples captured during recording (downsampled for the wire on send). */
    val amplitudes: List<Int>,
)

/** AND-133 — voice feature errors (recorder, permission, upload, playback). */
sealed interface VoiceError {
    data object PermissionDenied : VoiceError
    data object RecorderUnavailable : VoiceError
    data object StorageFull : VoiceError
    data object TooShort : VoiceError
    data class Upload(val message: String) : VoiceError
    data class Playback(val message: String) : VoiceError
}

/** AND-133 — pure recording-limit policy (no Android types) so the rules are unit-testable. */
object RecorderLimits {
    const val MIN_DURATION_MS = 1_000L
    const val MAX_DURATION_MS = 120_000L
    const val COUNTDOWN_START_MS = 110_000L
    const val AMPLITUDE_CADENCE_MS = 60L

    /** A finished recording is kept only if it reached the minimum length. */
    fun isKeepable(durationMs: Long): Boolean = durationMs >= MIN_DURATION_MS

    /** Whether elapsed time has hit the hard cap and recording must auto-stop. */
    fun shouldAutoStop(elapsedMs: Long): Boolean = elapsedMs >= MAX_DURATION_MS

    /** Remaining seconds shown during the final countdown; null before the countdown window. */
    fun countdownSeconds(elapsedMs: Long): Int? =
        if (elapsedMs >= COUNTDOWN_START_MS) {
            ((MAX_DURATION_MS - elapsedMs).coerceAtLeast(0L) / 1000L).toInt()
        } else {
            null
        }

    /** Clamp duration to the hard cap (a slightly-over capture from the ticker is trimmed). */
    fun clampDuration(durationMs: Long): Long = durationMs.coerceIn(0L, MAX_DURATION_MS)
}
