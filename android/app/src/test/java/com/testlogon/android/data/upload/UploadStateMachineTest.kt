package com.testlogon.android.data.upload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-129 — pure JVM tests for the upload state machine (queued/uploading%/uploaded/failed/retry). */
class UploadStateMachineTest {

    private fun reduce(state: UploadState, vararg events: UploadEvent): UploadState =
        events.fold(state) { acc, e -> UploadStateMachine.reduce(acc, e) }

    @Test
    fun happyPath_progressesQueuedToUploaded() {
        val end = reduce(
            UploadState(),
            UploadEvent.TotalKnown(100),
            UploadEvent.PresignStarted,
            UploadEvent.PresignDone,
            UploadEvent.BytesSent(40),
            UploadEvent.BytesSent(100),
            UploadEvent.PutDone,
            UploadEvent.ConfirmStarted,
            UploadEvent.Succeeded,
        )
        assertEquals(UploadStatus.UPLOADED, end.status)
        assertEquals(100L, end.bytesSent)
        assertEquals(1f, end.fraction, 0.0001f)
        assertTrue(end.isTerminal)
    }

    @Test
    fun progress_isMonotonic_backwardsBytesAreClamped() {
        val s = reduce(
            UploadState(totalBytes = 100),
            UploadEvent.BytesSent(60),
            UploadEvent.BytesSent(30), // out-of-order/backwards -> clamped to 60
        )
        assertEquals(60L, s.bytesSent)
    }

    @Test
    fun progress_neverExceedsTotal() {
        val s = reduce(UploadState(totalBytes = 100), UploadEvent.BytesSent(150))
        assertEquals(100L, s.bytesSent)
    }

    @Test
    fun putDone_snapsToTotal() {
        val s = reduce(UploadState(totalBytes = 200), UploadEvent.BytesSent(120), UploadEvent.PutDone)
        assertEquals(200L, s.bytesSent)
        assertTrue(s.putComplete)
    }

    @Test
    fun failed_isTerminal_andIgnoresLaterEvents() {
        val failed = reduce(
            UploadState(),
            UploadEvent.PresignStarted,
            UploadEvent.Failed(UploadError(UploadError.Kind.SERVER, 500), UploadPhase.PRESIGN),
            UploadEvent.PresignDone, // ignored after terminal
        )
        assertEquals(UploadStatus.FAILED, failed.status)
        assertEquals(UploadPhase.PRESIGN, failed.failedPhase)
        assertTrue(failed.isTerminal)
    }

    @Test
    fun retry_afterConfirmFailureWithPutComplete_resumesAtConfirm() {
        val state = reduce(
            UploadState(totalBytes = 100),
            UploadEvent.PresignDone,
            UploadEvent.BytesSent(100),
            UploadEvent.PutDone,
            UploadEvent.ConfirmStarted,
            UploadEvent.Failed(UploadError(UploadError.Kind.SERVER, 503), UploadPhase.CONFIRM),
        )
        assertEquals(UploadPhase.CONFIRM, UploadStateMachine.resumePhase(state))
    }

    @Test
    fun retry_afterExpiredPresignOnPut_restartsAtPresign() {
        val state = reduce(
            UploadState(totalBytes = 100),
            UploadEvent.PresignDone,
            UploadEvent.Failed(UploadError(UploadError.Kind.EXPIRED, 403), UploadPhase.PUT),
        )
        assertFalse(state.putComplete)
        assertEquals(UploadPhase.PRESIGN, UploadStateMachine.resumePhase(state))
    }

    @Test
    fun cancelled_isTerminal() {
        val s = reduce(UploadState(), UploadEvent.PresignDone, UploadEvent.Cancelled)
        assertEquals(UploadStatus.CANCELLED, s.status)
        assertTrue(s.isTerminal)
    }
}
