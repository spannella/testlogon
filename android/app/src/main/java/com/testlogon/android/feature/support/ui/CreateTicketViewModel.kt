package com.testlogon.android.feature.support.ui

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.CommentImageUploader
import com.testlogon.android.feature.support.data.SupportRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** B-SUP (batch 7) — create-a-support-ticket form (USER). Pre-validates length; the server is authoritative. */
data class CreateTicketUiState(
    val subject: String = "",
    val description: String = "",
    val priority: String = "medium",
    val submitting: Boolean = false,
    val error: String? = null,
    val createdTicketId: String? = null,
    // Helpdesk #14 — an optional attached image (uploaded to a platform URL before submit).
    val stagedImageUrl: String? = null,
    val uploadingImage: Boolean = false,
) {
    val subjectValid: Boolean
        get() = subject.trim().length in SupportRepository.SUBJECT_MIN..SupportRepository.SUBJECT_MAX
    val descriptionValid: Boolean
        get() = description.trim().length in SupportRepository.DESCRIPTION_MIN..SupportRepository.DESCRIPTION_MAX
    val canSubmit: Boolean get() = subjectValid && descriptionValid && !submitting && !uploadingImage
}

@HiltViewModel
class CreateTicketViewModel @Inject constructor(
    private val repository: SupportRepository,
    private val imageUploader: CommentImageUploader,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CreateTicketUiState())
    val uiState: StateFlow<CreateTicketUiState> = _uiState.asStateFlow()

    val priorities = listOf("low", "medium", "high", "urgent")

    fun onSubjectChange(v: String) { _uiState.value = _uiState.value.copy(subject = v, error = null) }
    fun onDescriptionChange(v: String) { _uiState.value = _uiState.value.copy(description = v, error = null) }
    fun onPriorityChange(v: String) { _uiState.value = _uiState.value.copy(priority = v) }

    /** Helpdesk #14 — upload a picked image and stage its URL for the opening message. */
    fun stageImage(uri: Uri) {
        if (_uiState.value.uploadingImage) return
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(uploadingImage = true, error = null)
            when (val r = imageUploader.uploadImage(uri)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(uploadingImage = false, stagedImageUrl = r.data)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(uploadingImage = false, error = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(uploadingImage = false, error = "You appear to be offline.")
            }
        }
    }

    fun clearStagedImage() { _uiState.value = _uiState.value.copy(stagedImageUrl = null) }

    fun submit() {
        val s = _uiState.value
        if (!s.canSubmit) return
        viewModelScope.launch {
            _uiState.value = s.copy(submitting = true, error = null)
            when (val r = repository.createTicket(s.subject, s.description, s.priority, s.stagedImageUrl)) {
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
