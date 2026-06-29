package com.testlogon.android.feature.support.ui

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.feature.support.data.SupportMediaItem
import com.testlogon.android.feature.support.data.SupportMediaUploader
import com.testlogon.android.feature.support.data.SupportRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/** B-SUP (batch 7) - create-a-support-ticket form (USER). Pre-validates length; the server is authoritative. */
data class CreateTicketUiState(
    val subject: String = "",
    val description: String = "",
    val priority: String = "medium",
    val submitting: Boolean = false,
    val error: String? = null,
    val createdTicketId: String? = null,
    // B10 B-HELPMEDIA #5 - the ordered list of staged attachments (images/videos/files/file-mgr refs).
    val media: List<StagedMedia> = emptyList(),
) {
    val subjectValid: Boolean
        get() = subject.trim().length in SupportRepository.SUBJECT_MIN..SupportRepository.SUBJECT_MAX
    val descriptionValid: Boolean
        get() = description.trim().length in SupportRepository.DESCRIPTION_MIN..SupportRepository.DESCRIPTION_MAX
    /** Any attachment still uploading blocks submit. */
    val uploadingMedia: Boolean get() = media.any { it.uploading }
    /** True once the attachment cap is reached (matches the backend media list max). */
    val mediaFull: Boolean get() = media.size >= SupportMediaUploader.MAX_MEDIA
    val canSubmit: Boolean get() = subjectValid && descriptionValid && !submitting && !uploadingMedia
}

@HiltViewModel
class CreateTicketViewModel @Inject constructor(
    private val repository: SupportRepository,
    private val mediaUploader: SupportMediaUploader,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CreateTicketUiState())
    val uiState: StateFlow<CreateTicketUiState> = _uiState.asStateFlow()

    val priorities = listOf("low", "medium", "high", "urgent")

    fun onSubjectChange(v: String) { _uiState.value = _uiState.value.copy(subject = v, error = null) }
    fun onDescriptionChange(v: String) { _uiState.value = _uiState.value.copy(description = v, error = null) }
    fun onPriorityChange(v: String) { _uiState.value = _uiState.value.copy(priority = v) }

    // ---- B10 B-HELPMEDIA #5: staged attachments ----

    fun addImage(uri: Uri) = stageUpload(uri.toString(), isImage = true) { mediaUploader.uploadImage(uri) }
    fun addVideo(uri: Uri) = stageUpload(null, isImage = false) { mediaUploader.uploadVideo(uri) }
    fun addFile(uri: Uri) = stageUpload(null, isImage = false) { mediaUploader.uploadFile(uri) }

    /** Attach an already-stored file-manager file (no upload). */
    fun addFileRef(node: FileNode) {
        if (_uiState.value.mediaFull) return
        val item = mediaUploader.fileRefFor(node)
        _uiState.value = _uiState.value.copy(
            media = _uiState.value.media + StagedMedia(
                localId = UUID.randomUUID().toString(),
                uploading = false,
                item = item,
                label = item.displayName,
            ),
        )
    }

    private fun stageUpload(
        localPreview: String?,
        isImage: Boolean,
        upload: suspend () -> ApiResult<SupportMediaItem>,
    ) {
        if (_uiState.value.mediaFull) return
        val id = UUID.randomUUID().toString()
        _uiState.value = _uiState.value.copy(
            error = null,
            media = _uiState.value.media + StagedMedia(
                localId = id,
                uploading = true,
                localPreview = localPreview,
                label = if (isImage) "Image" else "Uploading...",
            ),
        )
        viewModelScope.launch {
            when (val r = upload()) {
                is ApiResult.Success -> patch(id) { it.copy(uploading = false, item = r.data, label = r.data.displayName) }
                is ApiResult.Failure -> { drop(id); _uiState.value = _uiState.value.copy(error = r.error.message) }
                is ApiResult.NetworkError -> { drop(id); _uiState.value = _uiState.value.copy(error = "You appear to be offline.") }
            }
        }
    }

    fun removeMedia(localId: String) = drop(localId)

    private fun drop(localId: String) {
        _uiState.value = _uiState.value.copy(media = _uiState.value.media.filterNot { it.localId == localId })
    }

    private fun patch(localId: String, transform: (StagedMedia) -> StagedMedia) {
        _uiState.value = _uiState.value.copy(
            media = _uiState.value.media.map { if (it.localId == localId) transform(it) else it },
        )
    }

    fun submit() {
        val s = _uiState.value
        if (!s.canSubmit) return
        viewModelScope.launch {
            _uiState.value = s.copy(submitting = true, error = null)
            val resolved = _uiState.value.media.mapNotNull { it.item }
            when (val r = repository.createTicket(s.subject, s.description, s.priority, media = resolved)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(submitting = false, createdTicketId = r.data.ticketId)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(submitting = false, error = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(submitting = false, error = "You appear to be offline.")
            }
        }
    }

    fun consumeCreated() { _uiState.value = _uiState.value.copy(createdTicketId = null) }
}
