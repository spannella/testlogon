package com.testlogon.android.feature.kyc.facial

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.capture.CaptureError
import com.testlogon.android.feature.kyc.capture.CaptureImageProcessor
import com.testlogon.android.feature.kyc.facial.data.FaceComparisonRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

/**
 * AND-323 - presentation logic for the KYC facial-comparison (selfie vs. ID) flow.
 *
 * CONTROL PLANE IS REAL: the SCREEN acquires a selfie via the AND-321 system-intent capture (camera /
 * picker), [onSelfieAcquired] processes it off-main (REUSING AND-321's [CaptureImageProcessor]) and
 * moves to REVIEW; [submit] uploads + attaches + runs the SERVER-SIDE comparison (REUSING the AND-129
 * presign+PUT pipeline + AND-319 attachFile) and lands on RESULT.
 *
 * FLAGGED SEAM: the embedded CameraX front-camera live preview + oval face-guide + on-device liveness
 * auto-capture are DEFERRED (STOP-AND-FLAG: needs CameraX + face ML = a human decision). The state's
 * [FaceComparisonUiState.autoCaptureUnavailable] is therefore always true (the screen shows the
 * "auto face-capture not configured" note) while the manual capture + real comparison work end-to-end.
 *
 * VERSION CONFLICT: a 409 on attach surfaces as an [ApiResult.Failure] with status 409; the repo
 * re-reads the case version on every submit, so the VM simply prompts the user to retry the submit (a
 * re-submit picks up the fresh version).
 *
 * DOUBLE-SEND GUARD: the repository de-dupes the upload+attach within an in-flight submit (a re-submit
 * of the SAME captured File only re-runs compareFace). [uiState] is a plain MutableStateFlow; there is
 * NO delay/poll loop.
 *
 * case_id is sourced from [SavedStateHandle] (the nav arg [ARG_CASE_ID]); a blank/absent case id lands
 * the VM in a non-retryable error state ("no KYC case") so the flow cannot proceed without a real case.
 */
@HiltViewModel
class FaceComparisonViewModel @Inject constructor(
    private val repository: FaceComparisonRepository,
    private val processor: CaptureImageProcessor,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val caseId: String = savedStateHandle.get<String>(ARG_CASE_ID).orEmpty()

    private val _uiState = MutableStateFlow(
        if (caseId.isBlank()) {
            FaceComparisonUiState(error = UiError(message = ERROR_NO_CASE, retryable = false))
        } else {
            FaceComparisonUiState()
        },
    )
    val uiState: StateFlow<FaceComparisonUiState> = _uiState.asStateFlow()

    private var work: Job? = null

    private fun update(transform: (FaceComparisonUiState) -> FaceComparisonUiState) {
        _uiState.value = transform(_uiState.value)
    }

    /**
     * The SCREEN acquired a selfie [file] (system-intent camera / picker output). Process it off-main
     * (REUSING AND-321's [CaptureImageProcessor]) then advance to REVIEW.
     */
    fun onSelfieAcquired(file: File) {
        if (caseId.isBlank()) return
        if (work?.isActive == true) return
        work = viewModelScope.launch {
            try {
                val processed = processor.process(file)
                update {
                    it.copy(
                        capturedFile = processed.file,
                        phase = FacePhase.REVIEW,
                        result = null,
                        error = null,
                    )
                }
            } catch (e: CaptureError) {
                update { it.copy(error = UiError(e.message ?: GENERIC_PROCESS_ERROR, retryable = true)) }
            }
            work = null
        }
    }

    /** Discard the captured selfie and return to CAPTURE (a fresh selfie re-uploads cleanly). */
    fun onRetake() {
        if (work?.isActive == true) return
        update {
            it.copy(
                capturedFile = null,
                phase = FacePhase.CAPTURE,
                result = null,
                error = null,
            )
        }
    }

    /**
     * Submit the captured selfie: upload + attach + run the server-side comparison. SEQUENTIAL inside
     * the repository; the repo's double-send guard avoids re-uploading the same File on a re-submit.
     */
    fun submit() {
        if (caseId.isBlank()) return
        if (work?.isActive == true) return
        val file = _uiState.value.capturedFile ?: return
        update { it.copy(phase = FacePhase.SUBMITTING, submitting = true, error = null) }
        work = viewModelScope.launch {
            when (val result = repository.submitSelfie(caseId, file)) {
                is ApiResult.Success -> update {
                    it.copy(
                        phase = FacePhase.RESULT,
                        submitting = false,
                        result = result.data,
                        error = null,
                    )
                }
                is ApiResult.Failure -> {
                    val conflict = result.error.status == HTTP_CONFLICT
                    update {
                        it.copy(
                            // A version conflict returns to REVIEW so the user can simply re-submit (the
                            // repo re-reads the fresh version); other failures also return to REVIEW with
                            // the parsed message.
                            phase = FacePhase.REVIEW,
                            submitting = false,
                            error = UiError(
                                message = if (conflict) VERSION_CONFLICT else result.error.message,
                                retryable = true,
                            ),
                        )
                    }
                }
                is ApiResult.NetworkError -> update {
                    it.copy(
                        phase = FacePhase.REVIEW,
                        submitting = false,
                        error = UiError(OFFLINE, retryable = true),
                    )
                }
            }
            work = null
        }
    }

    /** Retry after a FAIL verdict (only valid when [FaceComparisonUiState.canRetry]); back to CAPTURE. */
    fun retryAfterFail() {
        if (work?.isActive == true) return
        if (!_uiState.value.canRetry) return
        update {
            it.copy(
                capturedFile = null,
                phase = FacePhase.CAPTURE,
                result = null,
                error = null,
            )
        }
    }

    /** Loads the case's prior face-comparison attempts (the collapsed history list). */
    fun loadHistory() {
        if (caseId.isBlank()) return
        viewModelScope.launch {
            when (val result = repository.listHistory(caseId)) {
                is ApiResult.Success -> update { it.copy(history = result.data) }
                is ApiResult.Failure -> Unit // History is auxiliary; a failure leaves the prior list intact.
                is ApiResult.NetworkError -> Unit
            }
        }
    }

    /** Dismiss the current inline error (returns to the prior surface for the phase). */
    fun dismissError() {
        update { it.copy(error = null) }
    }

    companion object {
        const val ARG_CASE_ID = "caseId"
        private const val ERROR_NO_CASE = "No KYC case to verify against."
        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val VERSION_CONFLICT = "Your case changed. Try submitting again."
        private const val GENERIC_PROCESS_ERROR = "Could not process the selfie."

        /** HTTP status for the optimistic-concurrency version conflict on attach. */
        private const val HTTP_CONFLICT = 409
    }
}
