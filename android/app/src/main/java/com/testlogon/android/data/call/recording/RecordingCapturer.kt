package com.testlogon.android.data.call.recording

import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-302 — call-recording capture seam (SCAFFOLD ONLY — FLAGGED, native media engine not configured).
 *
 * STOP-AND-FLAG: a real capturer would MediaRecorder(MPEG_4) the MIXED call audio/video into [outputFile],
 * which needs the FLAGGED WebRTC media engine (AND-289/290) that produces the local+remote tracks — that
 * native SDK is deliberately NOT integrated. So [StubRecordingCapturer] NEVER opens a MediaRecorder, NEVER
 * captures, NEVER touches the microphone/camera: every method returns [CaptureResult.NotConfigured]. This
 * mirrors the [com.testlogon.android.data.webrtc.PeerConnectionController] /
 * [com.testlogon.android.data.webrtc.SignalingTransport] stub-seam pattern.
 *
 * Because capture is unavailable, the recording flow may reach Granted (consent succeeds on the REAL server
 * endpoint) but capture then yields NotConfigured -> the UI surfaces "recording unavailable (media not
 * configured)" and the state machine returns to Idle WITHOUT entering a fake Recording/upload of a real
 * file. The consent protocol, state machine, durable queue, and upload (presign -> PUT -> complete) are all
 * fully implemented and unit-tested with a FAKE capturer that returns a temp file.
 */
interface RecordingCapturer {

    /**
     * Begin capturing the mixed call media into [outputFile]. The stub returns [CaptureResult.NotConfigured]
     * (no MediaRecorder created, no file written).
     */
    suspend fun start(outputFile: File): CaptureResult

    /** Stop capturing and finalize the file. The stub returns [CaptureResult.NotConfigured]. */
    suspend fun stop(): CaptureResult

    /** Abandon an in-progress capture and delete any partial artifact. The stub is a no-op. */
    fun discard()
}

/**
 * Result of a capture op. [NotConfigured] is what the FLAGGED stub always returns; the flow MUST surface
 * "recording unavailable" and MUST NOT transition to a real Recording/upload when it sees this.
 */
sealed interface CaptureResult {
    /** Capture started; [file] is the (real-impl) output being written. */
    data class Started(val file: File) : CaptureResult

    /** Capture stopped cleanly; [file] holds the finalized artifact, [durationSeconds] its length. */
    data class Stopped(val file: File, val durationSeconds: Float) : CaptureResult

    /**
     * No real capturer is wired (native WebRTC media engine FLAGGED, not integrated). The flow MUST surface
     * "recording unavailable (media not configured)" and MUST NOT capture. [StubRecordingCapturer] always
     * returns this.
     */
    data object NotConfigured : CaptureResult
}

/**
 * AND-302 — default (FLAGGED) capturer. NEVER opens a MediaRecorder, NEVER captures the mic/camera/call
 * audio, NEVER writes a file. Every op returns [CaptureResult.NotConfigured]. The real
 * MediaRecorder(MPEG_4)-backed binding replaces this @Binds once the native WebRTC media engine is wired.
 */
@Singleton
class StubRecordingCapturer @Inject constructor() : RecordingCapturer {
    override suspend fun start(outputFile: File): CaptureResult = CaptureResult.NotConfigured

    override suspend fun stop(): CaptureResult = CaptureResult.NotConfigured

    override fun discard() { /* no-op: nothing was ever opened or written */ }
}
