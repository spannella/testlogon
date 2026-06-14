package com.testlogon.android.feature.kyc.residency

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.capture.CaptureError
import com.testlogon.android.feature.kyc.capture.CaptureImageProcessor
import com.testlogon.android.feature.kyc.residency.data.ResidencyRepository
import com.testlogon.android.feature.kyc.residency.model.AddressForm
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocType
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocument
import com.testlogon.android.feature.kyc.residency.model.ResidencyStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

/**
 * AND-326 - presentation logic for the two KYC residency / address-verification surfaces.
 *
 * REAL REST, TWO SURFACES (NO vendor / ML / CameraX SDK, NO flagged seam):
 *   1. PROOF-OF-RESIDENCY DOCUMENT: the SCREEN owns the dependency-free acquisition launchers (TakePicture
 *      via a FileProvider Uri for the live system camera, ACTION_OPEN_DOCUMENT / GetContent for "choose a
 *      file"); the VM receives a [File] ([onProofCaptured]), processes the proof bytes -> base64 OFF-MAIN
 *      via AND-321's [CaptureImageProcessor] (REUSE), and POSTs the inline-base64 upload.
 *   2. STRUCTURED ADDRESS VERIFICATION: the user fills line_1..country and the VM verifies it server-side
 *      against the case (case-scoped).
 *
 * case_id is sourced from [SavedStateHandle] (the optional nav arg [ARG_CASE_ID]). It is OPTIONAL for the
 * proof upload (the backend may infer it) but REQUIRED for address verification (the endpoint is
 * case-scoped); without a case id the address Verify action is disabled by the screen.
 *
 * NO POLL LOOP: [uiState] is a plain (synchronous) MutableStateFlow; [onScreenEntered] loads the existing
 * documents and (if a case id is present) the current address status ONCE (single, non-looping).
 *
 * DOUBLE-SEND GUARD: both POSTs are NON-IDEMPOTENT. A single [submitJob] gates them — a submit/verify is a
 * no-op while one is already in flight — so a double tap never fires a second upload / verify.
 *
 * SIZE GUARD: a proof larger than [MAX_PROOF_BYTES] (4 MB) is rejected inline BEFORE any base64 encode; the
 * processor additionally enforces the cap on re-encoded images.
 */
@HiltViewModel
class ResidencyViewModel @Inject constructor(
    private val repository: ResidencyRepository,
    private val processor: CaptureImageProcessor,
    private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val caseId: String? =
        savedStateHandle.get<String>(ARG_CASE_ID)?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow<ResidencyUiState>(ResidencyUiState.Loading)
    val uiState: StateFlow<ResidencyUiState> = _uiState.asStateFlow()

    /** Single in-flight POST guard (double-send guard for the non-idempotent upload + verify). */
    private var submitJob: Job? = null

    /** True once a case id is available -> the screen enables the address Verify action. */
    val canVerifyAddress: Boolean get() = caseId != null

    /**
     * Loads existing documents and (when a case id is present) the current address-verification status ONCE.
     * Lands on [ResidencyUiState.Editing] seeded with the latest document + any existing address result.
     */
    fun onScreenEntered() {
        _uiState.value = ResidencyUiState.Loading
        viewModelScope.launch {
            val latest = when (val docs = repository.residencyDocuments()) {
                is ApiResult.Success -> docs.data.maxByOrNull { it.createdAt }
                is ApiResult.Failure -> {
                    _uiState.value = ResidencyUiState.Error(docs.error.message, retryable = true)
                    return@launch
                }
                is ApiResult.NetworkError -> {
                    _uiState.value = ResidencyUiState.Error(OFFLINE, retryable = true)
                    return@launch
                }
            }

            val addressResult = caseId?.let { id ->
                when (val res = repository.getAddressVerification(id)) {
                    is ApiResult.Success -> res.data
                    // A missing/absent address status on entry is non-fatal: just start with no result.
                    is ApiResult.Failure -> null
                    is ApiResult.NetworkError -> null
                }
            }

            _uiState.value = ResidencyUiState.Editing(
                latestDocument = latest,
                addressResult = addressResult,
            )
        }
    }

    // ---- Proof-of-residency editing ----

    fun onProofTypeSelected(docType: ResidencyDocType) = updateEditing { current ->
        current.copy(selectedProofType = docType).withRevalidatedSubmit()
    }

    fun onIssuingEntityChanged(value: String) = updateEditing { current ->
        current.copy(issuingEntity = value).withRevalidatedSubmit()
    }

    fun onDocumentDateChanged(value: String) = updateEditing { current ->
        current.copy(documentDate = value).withRevalidatedSubmit()
    }

    /** The screen captured a live-camera proof File. Reject >4MB inline before anything else. */
    fun onProofCaptured(file: File) = attachProof(file)

    /** The screen picked a proof File (copied from an ACTION_OPEN_DOCUMENT / GetContent content:// Uri). */
    fun onProofPicked(file: File) = attachProof(file)

    private fun attachProof(file: File) = updateEditing { current ->
        val tooLarge = file.length() > MAX_PROOF_BYTES
        current.copy(
            proof = if (tooLarge) null else ProofAttachment(file = file, displayName = file.name),
            validation = current.validation.copy(proofTooLarge = tooLarge, proofMissing = false),
        ).withRevalidatedSubmit()
    }

    fun onRemoveProof() = updateEditing { current ->
        current.copy(proof = null).withRevalidatedSubmit()
    }

    fun onAddressFieldChanged(transform: (AddressForm) -> AddressForm) = updateEditing { current ->
        current.copy(addressForm = transform(current.addressForm))
    }

    /**
     * Validates the proof form, then (off-main) base64-encodes the proof via AND-321's CaptureImageProcessor
     * and POSTs it. On success, maps the returned status to [Pending] / [Verified] / [Rejected]. DEBOUNCED by
     * [submitJob] (the upload POST is non-idempotent).
     */
    fun submitResidency() {
        val current = _uiState.value as? ResidencyUiState.Editing ?: return
        if (submitJob?.isActive == true) return // double-send guard.

        val validation = current.validateForSubmit()
        if (!validation.isValid) {
            _uiState.value = current.copy(validation = validation, submitEnabled = false)
            return
        }

        val docType = current.selectedProofType ?: return
        val proof = current.proof ?: return

        _uiState.value = ResidencyUiState.Submitting
        submitJob = viewModelScope.launch {
            val contentB64 = try {
                processor.encodeBase64(proof.file)
            } catch (e: CaptureError) {
                _uiState.value = current.copy(
                    inlineError = e.message ?: GENERIC_PROCESS_ERROR,
                    validation = if (e is CaptureError.TooLarge) {
                        current.validation.copy(proofTooLarge = true)
                    } else {
                        current.validation
                    },
                )
                return@launch
            }

            when (
                val result = repository.uploadResidency(
                    docType = docType,
                    issuingEntity = current.issuingEntity.trim(),
                    documentDate = current.documentDate.trim(),
                    fileName = proof.displayName,
                    contentB64 = contentB64,
                    caseId = caseId,
                )
            ) {
                is ApiResult.Success -> _uiState.value = result.data.toStatusState()
                is ApiResult.Failure ->
                    _uiState.value = ResidencyUiState.Error(result.error.message, retryable = true)
                is ApiResult.NetworkError ->
                    _uiState.value = ResidencyUiState.Error(OFFLINE, retryable = true)
            }
        }
    }

    /**
     * Validates the address form, then verifies it server-side for the case. DEBOUNCED by [submitJob] (the
     * verify POST is non-idempotent). No-op without a case id (the screen disables the action).
     */
    fun submitAddress() {
        val current = _uiState.value as? ResidencyUiState.Editing ?: return
        val id = caseId ?: return
        if (submitJob?.isActive == true) return // double-send guard.

        val form = current.addressForm
        if (!form.isVerifiable()) {
            _uiState.value = current.copy(inlineError = ADDRESS_INCOMPLETE)
            return
        }

        _uiState.value = ResidencyUiState.Submitting
        submitJob = viewModelScope.launch {
            when (val result = repository.verifyAddress(id, form)) {
                is ApiResult.Success ->
                    _uiState.value = ResidencyUiState.AddressResult(result.data)
                is ApiResult.Failure ->
                    _uiState.value = ResidencyUiState.Error(result.error.message, retryable = true)
                is ApiResult.NetworkError ->
                    _uiState.value = ResidencyUiState.Error(OFFLINE, retryable = true)
            }
        }
    }

    /** Re-runs the initial load after a terminal error (the safe, idempotent re-entry path). */
    fun retrySubmit() = onScreenEntered()

    // ---- helpers ----

    private inline fun updateEditing(transform: (ResidencyUiState.Editing) -> ResidencyUiState.Editing) {
        val current = _uiState.value as? ResidencyUiState.Editing ?: return
        _uiState.value = transform(current.copy(inlineError = null))
    }

    /** Recomputes [ResidencyUiState.Editing.submitEnabled] from a light (non-blocking) form check. */
    private fun ResidencyUiState.Editing.withRevalidatedSubmit(): ResidencyUiState.Editing {
        val ready = selectedProofType != null &&
            issuingEntity.isNotBlank() &&
            documentDate.isNotBlank() &&
            proof != null &&
            !validation.proofTooLarge
        return copy(submitEnabled = ready)
    }

    /** Full validation used to gate the actual upload POST. */
    private fun ResidencyUiState.Editing.validateForSubmit(): ResidencyValidation = ResidencyValidation(
        typeMissing = selectedProofType == null,
        issuerMissing = issuingEntity.isBlank(),
        dateMissing = documentDate.isBlank(),
        proofMissing = proof == null,
        proofTooLarge = validation.proofTooLarge,
    )

    private fun AddressForm.isVerifiable(): Boolean =
        line1.isNotBlank() && city.isNotBlank() && state.isNotBlank() &&
            postalCode.isNotBlank() && country.isNotBlank()

    private fun ResidencyDocument.toStatusState(): ResidencyUiState = when (status) {
        ResidencyStatus.VERIFIED -> ResidencyUiState.Verified(this)
        ResidencyStatus.REJECTED -> ResidencyUiState.Rejected(this, reason = reviewNote)
        ResidencyStatus.EXPIRED -> ResidencyUiState.Rejected(this, reason = reviewNote)
        // pending / unknown -> awaiting review.
        ResidencyStatus.PENDING, ResidencyStatus.UNKNOWN -> ResidencyUiState.Pending(this)
    }

    companion object {
        const val ARG_CASE_ID = "caseId"

        /** Reject a proof larger than this BEFORE any base64 encode (matches the processor's cap). */
        const val MAX_PROOF_BYTES = 4L * 1024 * 1024

        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val GENERIC_PROCESS_ERROR = "Could not process the file."
        private const val ADDRESS_INCOMPLETE = "Fill in every required address field."
    }
}
