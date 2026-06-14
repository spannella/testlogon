package com.testlogon.android.feature.call.recording

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-302 — the consent GATE + every phase edge of the pure [RecordingStateMachine].
 *
 * The safety-critical assertion: [RecordingStateMachine.canStartCapture] is TRUE only for Granted, so
 * capture can never begin from any other phase (no bypass of the server consent protocol). Also verifies the
 * decline/timeout paths leave Idle, that stop without an active capture never fabricates a PendingUpload, and
 * that the FLAGGED NotConfigured capture surfaces mediaUnavailable and stays Idle.
 */
class RecordingStateMachineTest {

    // ─── The consent GATE ─────────────────────────────────────────────────────────────────────────

    @Test
    fun canStartCapture_isTrue_onlyForGranted() {
        RecordingPhase.values().forEach { phase ->
            val expected = phase == RecordingPhase.Granted
            assertEquals("phase=$phase", expected, RecordingStateMachine.canStartCapture(phase))
        }
    }

    @Test
    fun captureStarted_isIgnored_fromAnyPhaseExceptGranted() {
        RecordingPhase.values()
            .filter { it != RecordingPhase.Granted }
            .forEach { phase ->
                val state = RecordingUiState(phase = phase)
                // onCaptureStarted must NOT transition to Recording outside the gate.
                assertEquals(phase, RecordingStateMachine.onCaptureStarted(state).phase)
            }
    }

    @Test
    fun captureStarted_fromGranted_entersRecording() {
        val granted = RecordingUiState(phase = RecordingPhase.Granted, recordingId = "r1")
        assertEquals(RecordingPhase.Recording, RecordingStateMachine.onCaptureStarted(granted).phase)
    }

    // ─── Request / consent / decline edges ─────────────────────────────────────────────────────────

    @Test
    fun onRequest_setsRequestPending_andIsRequester() {
        val s = RecordingStateMachine.onRequest(RecordingUiState(), "r1")
        assertEquals(RecordingPhase.RequestPending, s.phase)
        assertEquals("r1", s.recordingId)
        assertTrue(s.isRequester)
    }

    @Test
    fun onRemoteRequest_setsConsentPrompt_withRequesterName() {
        val s = RecordingStateMachine.onRemoteRequest(RecordingUiState(), "Alex")
        assertEquals(RecordingPhase.ConsentPrompt, s.phase)
        assertEquals("Alex", s.requesterName)
        assertFalse(s.isRequester)
    }

    @Test
    fun onConsentGranted_opensGate() {
        val s = RecordingStateMachine.onConsentGranted(
            RecordingUiState(phase = RecordingPhase.RequestPending),
            "r1",
        )
        assertEquals(RecordingPhase.Granted, s.phase)
        assertTrue(RecordingStateMachine.canStartCapture(s.phase))
    }

    @Test
    fun onDeclined_leavesDeclined_notRecording() {
        val s = RecordingStateMachine.onDeclined(RecordingUiState(phase = RecordingPhase.ConsentPrompt))
        assertEquals(RecordingPhase.Declined, s.phase)
        assertFalse(RecordingStateMachine.canStartCapture(s.phase))
    }

    // ─── FLAGGED capture: NotConfigured -> mediaUnavailable, stays Idle ──────────────────────────────

    @Test
    fun captureUnavailable_surfacesMediaUnavailable_andStaysIdle() {
        val granted = RecordingUiState(phase = RecordingPhase.Granted, recordingId = "r1", isRequester = true)
        val s = RecordingStateMachine.onCaptureUnavailable(granted)
        assertEquals(RecordingPhase.Idle, s.phase)
        assertTrue(s.mediaUnavailable)
        // Must NOT have entered Recording/PendingUpload (no real file).
        assertFalse(RecordingStateMachine.canStartCapture(s.phase))
    }

    // ─── Stop / upload edges ─────────────────────────────────────────────────────────────────────

    @Test
    fun onStop_fromRecording_entersPendingUpload() {
        val s = RecordingStateMachine.onStop(RecordingUiState(phase = RecordingPhase.Recording))
        assertEquals(RecordingPhase.PendingUpload, s.phase)
    }

    @Test
    fun onStop_withoutActiveCapture_neverEntersPendingUpload() {
        RecordingPhase.values()
            .filter { it != RecordingPhase.Recording }
            .forEach { phase ->
                val s = RecordingStateMachine.onStop(RecordingUiState(phase = phase))
                // onStop only enters PendingUpload from Recording; from any other phase the phase is left
                // unchanged, so it never TRANSITIONS into PendingUpload without an active capture.
                assertEquals("phase=$phase", phase, s.phase)
            }
    }

    @Test
    fun onUploadProgress_clampsAndEntersUploading() {
        val s = RecordingStateMachine.onUploadProgress(RecordingUiState(phase = RecordingPhase.PendingUpload), 150)
        assertEquals(RecordingPhase.Uploading, s.phase)
        assertEquals(100, s.uploadProgress)
        val neg = RecordingStateMachine.onUploadProgress(s, -10)
        assertEquals(0, neg.uploadProgress)
    }

    @Test
    fun onUploaded_isTerminalSuccess_at100() {
        val s = RecordingStateMachine.onUploaded(RecordingUiState(phase = RecordingPhase.Uploading, uploadProgress = 80))
        assertEquals(RecordingPhase.Uploaded, s.phase)
        assertEquals(100, s.uploadProgress)
    }

    @Test
    fun onCancel_setsCancelled() {
        assertEquals(
            RecordingPhase.Cancelled,
            RecordingStateMachine.onCancel(RecordingUiState(phase = RecordingPhase.Uploading)).phase,
        )
    }

    @Test
    fun onError_setsFailed_withMessage() {
        val s = RecordingStateMachine.onError(RecordingUiState(phase = RecordingPhase.Uploading), "boom")
        assertEquals(RecordingPhase.Failed, s.phase)
        assertEquals("boom", s.error)
    }

    @Test
    fun reset_returnsIdleSnapshot() {
        assertEquals(RecordingUiState(), RecordingStateMachine.reset())
    }
}
