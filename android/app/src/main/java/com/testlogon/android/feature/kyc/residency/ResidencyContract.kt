package com.testlogon.android.feature.kyc.residency

import com.testlogon.android.feature.kyc.residency.model.AddressForm
import com.testlogon.android.feature.kyc.residency.model.AddressVerification
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocType
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocument
import java.io.File

// AND-326 - UI state + supporting types for the KYC residency / address-verification screen.

/**
 * An attached proof file the user captured (live camera) or picked (ACTION_OPEN_DOCUMENT / GetContent),
 * before it is base64-encoded for upload. [displayName] backs the attached-file chip.
 */
data class ProofAttachment(
    val file: File,
    val displayName: String,
)

/**
 * Per-field + per-attachment validation flags for the proof-of-residency form, surfaced inline so the
 * screen can gate Submit and show field errors without throwing.
 */
data class ResidencyValidation(
    val typeMissing: Boolean = false,
    val issuerMissing: Boolean = false,
    val dateMissing: Boolean = false,
    val proofMissing: Boolean = false,
    val proofTooLarge: Boolean = false,
) {
    val isValid: Boolean
        get() = !typeMissing && !issuerMissing && !dateMissing && !proofMissing && !proofTooLarge
}

/** The sealed UI state for the residency / address-verification flow. */
sealed interface ResidencyUiState {

    /** Initial load of existing documents (+ optional address status when a case id is present). */
    data object Loading : ResidencyUiState

    /**
     * The editable form state: proof-of-residency capture/upload + structured address verification. Both
     * sections live here so the screen can present them as two tabs/sections.
     */
    data class Editing(
        val addressForm: AddressForm = AddressForm(),
        val acceptedProofTypes: List<ResidencyDocType> = ResidencyDocType.selectable,
        val selectedProofType: ResidencyDocType? = null,
        val issuingEntity: String = "",
        val documentDate: String = "",
        val proof: ProofAttachment? = null,
        val validation: ResidencyValidation = ResidencyValidation(),
        val submitEnabled: Boolean = false,
        val latestDocument: ResidencyDocument? = null,
        val addressResult: AddressVerification? = null,
        val inlineError: String? = null,
    ) : ResidencyUiState

    /** A proof upload OR an address verify POST is in flight (drives the busy affordance + double-send guard). */
    data object Submitting : ResidencyUiState

    /** The latest uploaded proof document is awaiting review. */
    data class Pending(val document: ResidencyDocument) : ResidencyUiState

    /** The latest uploaded proof document was verified. */
    data class Verified(val document: ResidencyDocument) : ResidencyUiState

    /** The latest uploaded proof document was rejected; [reason] is the optional review note. */
    data class Rejected(val document: ResidencyDocument, val reason: String?) : ResidencyUiState

    /** A completed address-verification result. */
    data class AddressResult(val verification: AddressVerification) : ResidencyUiState

    /** A terminal-for-now error. [retryable] gates the retry affordance. */
    data class Error(val message: String, val retryable: Boolean) : ResidencyUiState
}
