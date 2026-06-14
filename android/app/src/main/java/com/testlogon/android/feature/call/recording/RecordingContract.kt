package com.testlogon.android.feature.call.recording

/**
 * AND-302 — PURE (android-free) UI contract for the call-recording consent + upload sub-state.
 *
 * No android.*, no Compose, no java.time — the state machine ([RecordingStateMachine]) reduces over these so
 * it is fully JVM-unit-testable. This is an ADDITIVE sub-state alongside the AND-296 call phase; it does not
 * replace [com.testlogon.android.feature.call.domain.CallSessionState].
 */

/**
 * The recording sub-state phase. Order (requester): Idle -> RequestPending -> Granted -> Recording ->
 * PendingUpload -> Uploading -> Uploaded; (callee): Idle -> ConsentPrompt -> Granted/Declined. Declined,
 * Cancelled, Failed are off-ramps. Granted is the ONLY phase from which capture may start (the consent
 * GATE — see [RecordingStateMachine.canStartCapture]).
 */
enum class RecordingPhase {
    Idle,
    RequestPending,
    ConsentPrompt,
    Granted,
    Declined,
    Recording,
    PendingUpload,
    Uploading,
    Uploaded,
    Failed,
    Cancelled,
}

/**
 * Hot snapshot the in-call screen renders for the recording affordances.
 *
 * [mediaUnavailable] is set when capture returned NotConfigured (FLAGGED seam) — the UI shows "recording
 * unavailable (media not configured)" and the phase returns to [RecordingPhase.Idle]. [isRequester]
 * distinguishes the side that initiated (shows the Record button) from the side prompted for consent (shows
 * the dialog). [uploadProgress] is 0..100.
 */
data class RecordingUiState(
    val phase: RecordingPhase = RecordingPhase.Idle,
    val recordingId: String? = null,
    val requesterName: String? = null,
    val uploadProgress: Int = 0,
    val isRequester: Boolean = false,
    val mediaUnavailable: Boolean = false,
    val error: String? = null,
)
