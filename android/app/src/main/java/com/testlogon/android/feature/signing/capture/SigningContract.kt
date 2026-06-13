package com.testlogon.android.feature.signing.capture

import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.SignatureAsset
import com.testlogon.android.feature.signing.capture.model.SignatureField
import com.testlogon.android.feature.signing.capture.model.SignedPacketDraft

/**
 * AND-342 - UI contract for the signature CAPTURE + PLACEMENT surface.
 *
 * SCOPE: capture + placement + a validated in-memory [SignedPacketDraft]. NO network submit (AND-343
 * consumes the draft via the one-shot [SigningEvent.ContinueToSubmit] event).
 */
sealed interface SigningUiState {

    /** Loading the packet + projecting the viewer's fields. */
    data object Loading : SigningUiState

    /**
     * The editable capture surface. [fields] are the viewer's assigned fields (projected from AND-340);
     * [placements] is keyed by fieldId; [asset] is the captured signature (null until captured);
     * [requiredDone] / [requiredTotal] drive the progress chip; [isComplete] gates Continue.
     */
    data class Editing(
        val fields: List<SignatureField>,
        val placements: Map<String, FieldPlacement>,
        val asset: SignatureAsset?,
        val savedAsset: SignatureAsset?,
        val requiredTotal: Int,
        val requiredDone: Int,
        val isComplete: Boolean,
    ) : SigningUiState

    /** A terminal load error. [retryable] gates the Retry action. */
    data class Error(
        val message: String,
        val retryable: Boolean,
    ) : SigningUiState
}

/** One-shot events from the capture + placement surface. */
sealed interface SigningEvent {

    /** Every required field is satisfied; carries the validated draft for AND-343 to submit. */
    data class ContinueToSubmit(val draft: SignedPacketDraft) : SigningEvent
}
