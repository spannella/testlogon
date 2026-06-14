package com.testlogon.android.feature.signing.submit

import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.feature.signing.model.PacketLegalNotice
import java.io.File
import java.time.Instant

/**
 * AND-343 - UI contract for the TERMINAL e-sign step (flush placements -> acknowledge legal notice ->
 * mark-done -> confirm + download completed PDF).
 *
 * This is the FOCUSED submit surface; AND-344 will aggregate the full signing state machine. There is
 * NO bulk submit, NO license-agreements endpoint and NO `signed` status here.
 */
sealed interface SubmitUiState {

    /** Loading the packet detail (legal notice + remaining-required check). */
    data object Loading : SubmitUiState

    /**
     * The terminal-action surface. [legalNotice] is the packet's inline notice (null when none);
     * [canMarkDone] is true once every required field is satisfied AND the legal gate is cleared;
     * [submitting] blocks duplicate taps while the flush + mark-done is in flight.
     */
    data class Ready(
        val legalNotice: PacketLegalNotice?,
        val canMarkDone: Boolean,
        val submitting: Boolean,
    ) : SubmitUiState

    /**
     * The terminal confirmation. [status] is the resolved packet status (terminal is
     * [PacketStatus.COMPLETED]); [completedAt] is the packet's completed_at; [canDownloadPdf] is true
     * only when the packet reached completed (the final-pdf endpoint is valid only then).
     */
    data class Confirmed(
        val status: PacketStatus,
        val completedAt: Instant?,
        val canDownloadPdf: Boolean,
    ) : SubmitUiState

    /** A terminal error (load or mark-done). [retryable] gates a Retry affordance. */
    data class Error(
        val message: String,
        val retryable: Boolean,
    ) : SubmitUiState
}

/** One-shot events from the terminal e-sign surface. */
sealed interface SubmitSignEvent {

    /**
     * The completed PDF has been streamed to [file]; the screen opens it via the FileProvider
     * ACTION_VIEW open-with (reusing AND-331/AND-334).
     */
    data class OpenCompletedPdf(val packetId: String, val file: File) : SubmitSignEvent
}
