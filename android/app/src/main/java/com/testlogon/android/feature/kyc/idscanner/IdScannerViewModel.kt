package com.testlogon.android.feature.kyc.idscanner

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.capture.CaptureError
import com.testlogon.android.feature.kyc.capture.CaptureImageProcessor
import com.testlogon.android.feature.kyc.idscanner.data.IdScannerRepository
import com.testlogon.android.feature.kyc.idscanner.model.IdDocumentType
import com.testlogon.android.feature.kyc.idscanner.model.IdSide
import com.testlogon.android.feature.kyc.idscanner.model.ScanResult
import com.testlogon.android.feature.kyc.idscanner.model.ScanStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

/**
 * AND-322 - presentation logic for the KYC guided ID capture+scan flow.
 *
 * CONTROL PLANE IS REAL: selectType -> validate-document (server tells us the required sides + MRZ
 * expectation) -> the user captures each side via the SCREEN's AND-321 system-intent acquisition (camera /
 * picker) -> confirmAndUpload uploads each side (base64, REUSING AND-321's KycDocumentsRepository) -> scans
 * each side (scan-document) -> RESULT.
 *
 * FLAGGED SEAM: the on-device auto-capture quality gates + MRZ OCR live behind [IdFrameAnalyzer]; the bound
 * [StubIdFrameAnalyzer] reports auto-capture as unavailable (so [IdScannerUiState.mediaUnavailable] is set
 * and the screen shows the "auto-capture / MRZ not configured" note) and returns NO MRZ lines. The manual
 * path is unaffected and fully works.
 *
 * DOUBLE-SEND GUARD: upload + scan are NON-IDEMPOTENT. A side that already has a documentId is NOT re-uploaded
 * on retry; a side that already produced a non-rejected ScanResult is NOT re-scanned. [uiState] is a plain
 * MutableStateFlow; there is NO delay/poll loop.
 *
 * case_id is sourced from [SavedStateHandle] (the nav arg [ARG_CASE_ID]); a blank/absent case id lands the VM
 * in an error state ("no KYC case") so the flow cannot proceed without a real case.
 */
@HiltViewModel
class IdScannerViewModel @Inject constructor(
    private val repository: IdScannerRepository,
    private val analyzer: IdFrameAnalyzer,
    private val processor: CaptureImageProcessor,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val caseId: String = savedStateHandle.get<String>(ARG_CASE_ID).orEmpty()

    private val _uiState = MutableStateFlow(
        if (caseId.isBlank()) {
            IdScannerUiState(error = UiError(message = ERROR_NO_CASE, retryable = false))
        } else {
            IdScannerUiState()
        },
    )
    val uiState: StateFlow<IdScannerUiState> = _uiState.asStateFlow()

    private var work: Job? = null

    private fun update(transform: (IdScannerUiState) -> IdScannerUiState) {
        _uiState.value = transform(_uiState.value)
    }

    /** The user picked a document type: validate it server-side, then move to CAPTURE for the first side. */
    fun selectType(type: IdDocumentType) {
        if (caseId.isBlank()) return
        if (work?.isActive == true) return
        update {
            it.copy(
                selectedType = type,
                validation = null,
                captured = emptyMap(),
                results = emptyList(),
                error = null,
                isOffline = false,
                step = IdScannerStep.TYPE_SELECT,
            )
        }
        work = viewModelScope.launch {
            when (val result = repository.validate(caseId, type)) {
                is ApiResult.Success -> update {
                    val validation = result.data
                    val first = sidesFor(type, validation).firstOrNull() ?: IdSide.FRONT
                    it.copy(
                        validation = validation,
                        currentSide = first,
                        step = IdScannerStep.CAPTURE,
                        // The FLAGGED auto-capture / MRZ analyzer is not configured; the note is shown but
                        // manual capture still works.
                        mediaUnavailable = !analyzer.isAutoCaptureAvailable,
                    )
                }
                is ApiResult.Failure -> update {
                    it.copy(error = UiError(result.error.message, retryable = true))
                }
                is ApiResult.NetworkError -> update {
                    it.copy(error = UiError(OFFLINE, retryable = true), isOffline = true)
                }
            }
            work = null
        }
    }

    /**
     * The SCREEN acquired an image File for [side] (system-intent camera / picker output). Process it
     * off-main (REUSING AND-321's [CaptureImageProcessor]), store it, then advance to the next un-captured
     * side or to REVIEW once every required side is captured.
     */
    fun onImageAcquired(side: IdSide, file: File) {
        if (work?.isActive == true) return
        work = viewModelScope.launch {
            try {
                val processed = processor.process(file)
                update { state ->
                    val captured = state.captured + (side to CapturedSide(side = side, file = processed.file))
                    val updated = state.copy(captured = captured, error = null)
                    val next = updated.requiredSides.firstOrNull { it !in captured.keys }
                    if (next == null) {
                        updated.copy(step = IdScannerStep.REVIEW)
                    } else {
                        updated.copy(currentSide = next, step = IdScannerStep.CAPTURE)
                    }
                }
            } catch (e: CaptureError) {
                update { it.copy(error = UiError(e.message ?: GENERIC_PROCESS_ERROR, retryable = true)) }
            }
            work = null
        }
    }

    /** Discard a captured side and return to CAPTURE for it (clears any prior upload/scan for that side). */
    fun retake(side: IdSide) {
        if (work?.isActive == true) return
        update { state ->
            state.copy(
                captured = state.captured - side,
                results = state.results.filterNot { it.side == side },
                currentSide = side,
                step = IdScannerStep.CAPTURE,
                error = null,
            )
        }
    }

    /**
     * Upload then scan every captured side IN ORDER. DOUBLE-SEND GUARD: a side that already has a documentId
     * is not re-uploaded; a side that already produced a non-rejected ScanResult is not re-scanned.
     */
    fun confirmAndUpload() {
        if (caseId.isBlank()) return
        if (work?.isActive == true) return
        val type = _uiState.value.selectedType ?: return
        if (_uiState.value.captured.isEmpty()) return
        work = viewModelScope.launch {
            if (!uploadAll(type = type)) {
                work = null
                return@launch
            }
            scanAll(type = type)
            work = null
        }
    }

    /** Restart the capture after a rejection/decline (keeps the selected type, clears captures + results). */
    fun retryAfterReject() {
        if (work?.isActive == true) return
        val type = _uiState.value.selectedType
        update {
            val first = sidesFor(type, it.validation).firstOrNull() ?: IdSide.FRONT
            it.copy(
                captured = emptyMap(),
                results = emptyList(),
                currentSide = first,
                step = IdScannerStep.CAPTURE,
                error = null,
                isOffline = false,
            )
        }
    }

    /** Cancel everything: stop in-flight work and clear the cached captures/results back to type select. */
    fun cancel() {
        work?.cancel()
        work = null
        update {
            it.copy(
                step = IdScannerStep.TYPE_SELECT,
                selectedType = null,
                validation = null,
                captured = emptyMap(),
                results = emptyList(),
                currentSide = IdSide.FRONT,
                error = null,
                isOffline = false,
            )
        }
    }

    /** Dismiss the current inline error (returns to the prior surface for the step). */
    fun dismissError() {
        update { it.copy(error = null) }
    }

    /** Returns true if every required side ended with a documentId; false (and sets error) otherwise. */
    private suspend fun uploadAll(type: IdDocumentType): Boolean {
        update { it.copy(step = IdScannerStep.UPLOADING, error = null) }
        val sides = _uiState.value.requiredSides
        for (side in sides) {
            val captured = _uiState.value.captured[side] ?: continue
            // DOUBLE-SEND GUARD: never re-upload a side that already has a server document id.
            if (captured.documentId != null) continue

            val b64 = processor.encodeBase64(captured.file)
            when (val result = repository.uploadSide(
                caseId = caseId,
                fileType = side.fileType,
                fileName = captured.file.name,
                contentB64 = b64,
            )) {
                is ApiResult.Success -> update { state ->
                    val updated = state.captured[side]?.copy(documentId = result.data)
                    if (updated == null) state else state.copy(captured = state.captured + (side to updated))
                }
                is ApiResult.Failure -> {
                    update { it.copy(step = IdScannerStep.REVIEW, error = UiError(result.error.message, retryable = true)) }
                    return false
                }
                is ApiResult.NetworkError -> {
                    update { it.copy(step = IdScannerStep.REVIEW, error = UiError(OFFLINE, retryable = true), isOffline = true) }
                    return false
                }
            }
        }
        return true
    }

    /** Scans each required side in order; skips a side that already has a non-rejected result. */
    private suspend fun scanAll(type: IdDocumentType) {
        update { it.copy(step = IdScannerStep.SCANNING, error = null) }
        val sides = _uiState.value.requiredSides
        for (side in sides) {
            // DOUBLE-SEND GUARD: don't re-scan a side that already produced an acceptable (non-rejected) result.
            val existing = _uiState.value.results.firstOrNull { it.side == side }
            if (existing != null && existing.status != ScanStatus.REJECTED && existing.status != ScanStatus.DECLINED) {
                continue
            }
            val imageRef = _uiState.value.captured[side]?.documentId
            // FLAGGED: the stub analyzer returns NO MRZ lines (the server scans without client-supplied MRZ).
            val mrzLines = _uiState.value.captured[side]?.let { analyzer.readMrz(it.file) }.orEmpty()
            when (val result = repository.scanSide(
                caseId = caseId,
                docType = type,
                side = side,
                imageRef = imageRef,
                mrzLines = mrzLines,
            )) {
                is ApiResult.Success -> update { state ->
                    state.copy(results = state.results.filterNot { it.side == side } + result.data)
                }
                is ApiResult.Failure -> {
                    update { it.copy(step = IdScannerStep.REVIEW, error = UiError(result.error.message, retryable = true)) }
                    return
                }
                is ApiResult.NetworkError -> {
                    update { it.copy(step = IdScannerStep.REVIEW, error = UiError(OFFLINE, retryable = true), isOffline = true) }
                    return
                }
            }
        }
        update { it.copy(step = IdScannerStep.RESULT) }
    }

    companion object {
        const val ARG_CASE_ID = "caseId"
        private const val ERROR_NO_CASE = "No KYC case to scan against."
        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val GENERIC_PROCESS_ERROR = "Could not process the image."

        /** Convenience for the result panel / tests: whether a status is a success verdict. */
        fun ScanResult.isSuccess(): Boolean =
            status == ScanStatus.MATCHED || status == ScanStatus.APPROVED
    }
}
