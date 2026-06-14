package com.testlogon.android.data.upload

/**
 * AND-129 — pure, framework-free state machine for an attachment-upload attempt.
 *
 * Holds NO Android/OkHttp types, so it is fully JVM-unit-testable. The runtime uploader
 * ([DefaultAttachmentUploader]) drives it with events and renders [UploadProgress] from the state;
 * this object owns the transition rules (queued to uploading% to uploaded to failed, plus where a
 * retry resumes from).
 */
enum class UploadStatus { QUEUED, PRESIGNING, UPLOADING, CONFIRMING, UPLOADED, FAILED, CANCELLED }

/** Immutable snapshot of an upload attempt. */
data class UploadState(
    val status: UploadStatus = UploadStatus.QUEUED,
    val bytesSent: Long = 0L,
    val totalBytes: Long = 0L,
    val error: UploadError? = null,
    val failedPhase: UploadPhase? = null,
    /** True once the storage PUT has fully completed (drives confirm-resume on retry). */
    val putComplete: Boolean = false,
) {
    val fraction: Float
        get() = if (totalBytes <= 0L) 0f else (bytesSent.toFloat() / totalBytes).coerceIn(0f, 1f)

    val isTerminal: Boolean
        get() = status == UploadStatus.UPLOADED ||
            status == UploadStatus.FAILED ||
            status == UploadStatus.CANCELLED
}

/** Events the runtime feeds into the machine. */
sealed interface UploadEvent {
    data class TotalKnown(val totalBytes: Long) : UploadEvent
    data object PresignStarted : UploadEvent
    data object PresignDone : UploadEvent
    data class BytesSent(val bytesSent: Long) : UploadEvent
    data object PutDone : UploadEvent
    data object ConfirmStarted : UploadEvent
    data object Succeeded : UploadEvent
    data class Failed(val error: UploadError, val phase: UploadPhase) : UploadEvent
    data object Cancelled : UploadEvent
}

object UploadStateMachine {

    /**
     * Applies [event] to [state]. Progress monotonicity is enforced: a [UploadEvent.BytesSent] that
     * would move the counter backwards is clamped to the current value. Events after a terminal
     * state are ignored (the flow never emits past a terminal value).
     */
    fun reduce(state: UploadState, event: UploadEvent): UploadState {
        if (state.isTerminal) return state
        return when (event) {
            is UploadEvent.TotalKnown -> state.copy(totalBytes = event.totalBytes.coerceAtLeast(0L))
            UploadEvent.PresignStarted -> state.copy(status = UploadStatus.PRESIGNING)
            UploadEvent.PresignDone -> state.copy(status = UploadStatus.UPLOADING)
            is UploadEvent.BytesSent -> state.copy(
                status = UploadStatus.UPLOADING,
                bytesSent = maxOf(state.bytesSent, event.bytesSent).coerceAtMost(
                    if (state.totalBytes > 0L) state.totalBytes else event.bytesSent,
                ),
            )
            UploadEvent.PutDone -> state.copy(
                bytesSent = if (state.totalBytes > 0L) state.totalBytes else state.bytesSent,
                putComplete = true,
            )
            UploadEvent.ConfirmStarted -> state.copy(status = UploadStatus.CONFIRMING)
            UploadEvent.Succeeded -> state.copy(status = UploadStatus.UPLOADED)
            is UploadEvent.Failed ->
                state.copy(status = UploadStatus.FAILED, error = event.error, failedPhase = event.phase)
            UploadEvent.Cancelled -> state.copy(status = UploadStatus.CANCELLED)
        }
    }

    /**
     * Where a user-driven retry should resume.
     *
     * Resumes at CONFIRM only when the bytes were fully PUT and the failure was at confirm — relying
     * on backend `complete-upload` idempotency on `ticket_id` (AND-129 §16.14, unverified). Otherwise
     * restarts at presign, since presigned URLs are short-lived and an expired-URL (403 on PUT) must
     * re-presign.
     */
    fun resumePhase(state: UploadState): UploadPhase =
        if (state.failedPhase == UploadPhase.CONFIRM && state.putComplete) {
            UploadPhase.CONFIRM
        } else {
            UploadPhase.PRESIGN
        }
}
