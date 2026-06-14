package com.testlogon.android.feature.call.recording

/**
 * AND-302 — PURE reducer for the call-recording consent + upload sub-state. No android.*, no Compose, no
 * suspend, no I/O — every transition is a pure [RecordingUiState] -> [RecordingUiState] function so the
 * consent GATE is exhaustively JVM-unit-testable.
 *
 * The CONSENT GATE is the safety-critical invariant: [canStartCapture] is TRUE only for
 * [RecordingPhase.Granted]. The controller MUST consult it before calling
 * [com.testlogon.android.data.call.recording.RecordingCapturer.start]; capture can therefore never begin
 * from RequestPending/ConsentPrompt/Declined/Idle/etc. — only after the server consent endpoint returned a
 * granted status with started_at present (mapped to Granted via [onConsentGranted]).
 */
object RecordingStateMachine {

    /**
     * The CONSENT GATE. Capture may ONLY start from [RecordingPhase.Granted]. Returning false for every
     * other phase is what guarantees the consent protocol cannot be bypassed.
     */
    fun canStartCapture(phase: RecordingPhase): Boolean = phase == RecordingPhase.Granted

    /** Requester opened a consent prompt (server POST .../request succeeded). */
    fun onRequest(state: RecordingUiState, recordingId: String): RecordingUiState =
        state.copy(
            phase = RecordingPhase.RequestPending,
            recordingId = recordingId,
            isRequester = true,
            mediaUnavailable = false,
            error = null,
        )

    /** A remote consent request arrived for the callee (rides the FLAGGED signaling seam). */
    fun onRemoteRequest(state: RecordingUiState, requesterName: String?): RecordingUiState =
        state.copy(
            phase = RecordingPhase.ConsentPrompt,
            requesterName = requesterName,
            isRequester = false,
            mediaUnavailable = false,
            error = null,
        )

    /**
     * Consent GRANTED by the server (consent endpoint returned granted + started_at). Opens the capture
     * gate; the controller then attempts capture (which, FLAGGED, yields NotConfigured -> [onCaptureUnavailable]).
     */
    fun onConsentGranted(state: RecordingUiState, recordingId: String): RecordingUiState =
        state.copy(
            phase = RecordingPhase.Granted,
            recordingId = recordingId,
            error = null,
        )

    /** Consent was declined (by either side). Surfaces Declined then settles back to Idle. */
    fun onDeclined(state: RecordingUiState): RecordingUiState =
        state.copy(phase = RecordingPhase.Declined)

    /** Capture actually began (real impl only; gated by [canStartCapture]). */
    fun onCaptureStarted(state: RecordingUiState): RecordingUiState =
        if (canStartCapture(state.phase)) {
            state.copy(phase = RecordingPhase.Recording)
        } else {
            // Defensive: capture must never start outside Granted. Ignore the stray transition.
            state
        }

    /**
     * Capture is UNAVAILABLE (FLAGGED capturer returned NotConfigured). Surface "recording unavailable" and
     * return to Idle WITHOUT entering Recording/PendingUpload (no real file exists).
     */
    fun onCaptureUnavailable(state: RecordingUiState): RecordingUiState =
        RecordingUiState(
            phase = RecordingPhase.Idle,
            isRequester = state.isRequester,
            mediaUnavailable = true,
        )

    /**
     * Capture stopped (user stop or call ended) WITH a captured file -> enqueue for upload. Only valid from
     * [RecordingPhase.Recording]; if there is no active capture (any other phase) this is a no-op so a stop
     * never fabricates a PendingUpload without a file.
     */
    fun onStop(state: RecordingUiState): RecordingUiState =
        if (state.phase == RecordingPhase.Recording) {
            state.copy(phase = RecordingPhase.PendingUpload)
        } else {
            state
        }

    /** Upload progressed; [percent] clamped 0..100. Enters/stays Uploading. */
    fun onUploadProgress(state: RecordingUiState, percent: Int): RecordingUiState =
        state.copy(
            phase = RecordingPhase.Uploading,
            uploadProgress = percent.coerceIn(0, 100),
        )

    /** Upload + complete succeeded. */
    fun onUploaded(state: RecordingUiState): RecordingUiState =
        state.copy(phase = RecordingPhase.Uploaded, uploadProgress = 100)

    /** User cancelled (consent prompt, or an in-flight/queued upload). */
    fun onCancel(state: RecordingUiState): RecordingUiState =
        state.copy(phase = RecordingPhase.Cancelled)

    /** A recoverable error (consent/presign/PUT/complete failure). [message] is redaction-safe copy. */
    fun onError(state: RecordingUiState, message: String?): RecordingUiState =
        state.copy(phase = RecordingPhase.Failed, error = message)

    /** Reset back to the neutral Idle sub-state (e.g. after a terminal phase is observed). */
    fun reset(): RecordingUiState = RecordingUiState()
}
