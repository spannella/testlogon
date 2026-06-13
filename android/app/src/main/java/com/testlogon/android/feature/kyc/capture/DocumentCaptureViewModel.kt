package com.testlogon.android.feature.kyc.capture

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.capture.data.KycDocumentsRepository
import com.testlogon.android.feature.kyc.capture.model.KycDocument
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

/**
 * AND-321 - presentation logic for the KYC document capture+upload flow.
 *
 * DEPENDENCY-FREE CAPTURE: the SCREEN owns the ActivityResult launchers (TakePicture via a FileProvider
 * Uri for the live system camera, PickVisualMedia/GetContent for "choose from library") and the runtime
 * CAMERA permission request. The VM never touches the camera; it only receives [onImageAcquired] (a File)
 * and drives processing + the upload state machine.
 *
 * FLOW: onSelectType -> (screen acquires an image) -> onImageAcquired -> process (off-main, in the
 * processor) -> Reviewing. onRetake discards + returns to type select; onConfirm records the confirmed
 * image and either advances to the next required slot (a TWO-image id_front+id_back flow) or, once every
 * required slot is confirmed, the user starts the upload. startUpload base64-encodes each confirmed image
 * (off-main, in the processor) and POSTs them SEQUENTIALLY via the repo, updating progress = done/total;
 * on all-success it lands on Success(last document). cancelUpload stops BEFORE the next not-yet-sent image.
 *
 * DOUBLE-SEND GUARD: the endpoint is non-idempotent, so each confirmed slot's [uploadedDocId] is recorded
 * on success and an upload pass SKIPS any slot already uploaded. A retry after a mid-sequence failure thus
 * re-POSTs only the not-yet-succeeded images, never the ones that already went through.
 *
 * [uiState] is a plain (synchronous) MutableStateFlow. NO delay/poll loop anywhere.
 */
@HiltViewModel
class DocumentCaptureViewModel @Inject constructor(
    private val repository: KycDocumentsRepository,
    private val processor: CaptureImageProcessor,
    @Suppress("unused") private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<DocumentCaptureUiState>(
        DocumentCaptureUiState.SelectingType(available = requiredTypes),
    )
    val uiState: StateFlow<DocumentCaptureUiState> = _uiState.asStateFlow()

    // Confirmed images keyed by slot, in capture order. uploadedDocId != null once successfully POSTed.
    private val confirmed = LinkedHashMap<DocType, ConfirmedSlot>()
    private var pending: ConfirmedImage? = null
    private var uploadJob: Job? = null

    private data class ConfirmedSlot(val file: File, var uploadedDocId: String? = null)

    /** The slot the user is currently capturing (set by [onSelectType], consumed by [onImageAcquired]). */
    private var activeType: DocType? = null

    /** The user chose which document to capture; the screen now launches camera / picker. */
    fun onSelectType(docType: DocType) {
        activeType = docType
    }

    /** Optional: caller may pass a case id to associate the documents with a KYC case. */
    fun setCaseId(caseId: String?) {
        this.caseId = caseId
    }

    private var caseId: String? = null

    /**
     * The screen acquired an image File (live-camera output or a copy of a picked Uri). Process it
     * off-main, then move to Reviewing. A processor [CaptureError] (e.g. >4MB) surfaces inline.
     */
    fun onImageAcquired(file: File) {
        val docType = activeType ?: return
        _uiState.value = DocumentCaptureUiState.Loading
        viewModelScope.launch {
            try {
                val processed = processor.process(file)
                pending = ConfirmedImage(docType = docType, file = processed.file)
                _uiState.value = DocumentCaptureUiState.Reviewing(
                    docType = docType,
                    file = processed.file,
                    confirmedCount = confirmed.size,
                    totalCount = requiredTypes.size,
                )
            } catch (e: CaptureError) {
                _uiState.value = DocumentCaptureUiState.Error(
                    message = e.message ?: GENERIC_PROCESS_ERROR,
                    retryable = true,
                )
            }
        }
    }

    /** Discard the image under review and return to type selection (re-acquire). */
    fun onRetake() {
        pending = null
        showSelectOrUpload()
    }

    /** Confirm the reviewed image; advance to the next required slot or to the upload-ready select state. */
    fun onConfirm() {
        val image = pending ?: return
        confirmed[image.docType] = ConfirmedSlot(file = image.file)
        pending = null
        showSelectOrUpload()
    }

    /** Begin (or resume) the sequential upload of all confirmed-but-not-yet-uploaded images. */
    fun onStartUpload() {
        if (confirmed.isEmpty()) return
        if (uploadJob?.isActive == true) return
        uploadJob = viewModelScope.launch { runUpload() }
    }

    /** Retry after an upload failure: re-runs the upload, which skips already-succeeded images. */
    fun onRetry() {
        // Re-acquire path for a processing error: nothing confirmed yet -> back to selection.
        if (confirmed.isEmpty()) {
            _uiState.value = DocumentCaptureUiState.SelectingType(available = remainingTypes())
            return
        }
        onStartUpload()
    }

    /** Cancel an in-flight upload BEFORE the next not-yet-sent image is POSTed. */
    fun onCancel() {
        uploadJob?.cancel()
        uploadJob = null
        showSelectOrUpload()
    }

    private suspend fun runUpload() {
        val slots = confirmed.entries.toList()
        val total = slots.size
        fun statuses(currentlyUploading: DocType?): List<ItemStatus> = slots.map { (type, slot) ->
            ItemStatus(
                docType = type,
                state = when {
                    slot.uploadedDocId != null -> ItemUploadState.SUCCEEDED
                    type == currentlyUploading -> ItemUploadState.UPLOADING
                    else -> ItemUploadState.PENDING
                },
            )
        }

        var done = slots.count { it.value.uploadedDocId != null }
        var last: KycDocument? = null
        _uiState.value = DocumentCaptureUiState.Uploading(
            progress = done.toFloat() / total,
            perItem = statuses(currentlyUploading = null),
        )

        for ((type, slot) in slots) {
            // DOUBLE-SEND GUARD: never re-POST an image that already succeeded (non-idempotent endpoint).
            if (slot.uploadedDocId != null) continue

            _uiState.value = DocumentCaptureUiState.Uploading(
                progress = done.toFloat() / total,
                perItem = statuses(currentlyUploading = type),
            )

            val b64 = processor.encodeBase64(slot.file)
            val result = repository.uploadDocument(
                documentType = type.wireType,
                fileName = slot.file.name,
                contentB64 = b64,
                caseId = caseId,
            )
            when (result) {
                is ApiResult.Success -> {
                    slot.uploadedDocId = result.data.documentId
                    last = result.data
                    done++
                    _uiState.value = DocumentCaptureUiState.Uploading(
                        progress = done.toFloat() / total,
                        perItem = statuses(currentlyUploading = null),
                    )
                }
                is ApiResult.Failure -> {
                    _uiState.value = DocumentCaptureUiState.Error(result.error.message, retryable = true)
                    return
                }
                is ApiResult.NetworkError -> {
                    _uiState.value = DocumentCaptureUiState.Error(OFFLINE, retryable = true)
                    return
                }
            }
        }

        uploadJob = null
        last?.let { _uiState.value = DocumentCaptureUiState.Success(it) }
    }

    /**
     * After a confirm/retake/cancel: if every required slot is confirmed, expose an upload-ready state
     * (SelectingType with an empty available list -> the screen shows "upload"); otherwise let the user
     * pick the next un-confirmed slot.
     */
    private fun showSelectOrUpload() {
        _uiState.value = DocumentCaptureUiState.SelectingType(available = remainingTypes())
    }

    private fun remainingTypes(): List<DocType> = requiredTypes.filter { it !in confirmed.keys }

    /** True once every required slot has a confirmed image (the screen enables the upload action). */
    val allConfirmed: Boolean get() = confirmed.keys.containsAll(requiredTypes)

    /** Camera-permission outcomes from the screen's RequestPermission launcher. */
    fun onPermissionDenied(permanentlyDenied: Boolean) {
        _uiState.value = DocumentCaptureUiState.PermissionRequired(permanentlyDenied)
    }

    /** Permission was (re)granted; resume at the type selection. */
    fun onPermissionGranted() {
        showSelectOrUpload()
    }

    companion object {
        // A front+back ID is the required two-image flow per the AND-321 contract.
        val requiredTypes: List<DocType> = listOf(DocType.ID_FRONT, DocType.ID_BACK)
        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val GENERIC_PROCESS_ERROR = "Could not process the image."
    }
}
