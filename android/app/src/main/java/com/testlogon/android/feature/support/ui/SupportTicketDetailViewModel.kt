package com.testlogon.android.feature.support.ui

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.feature.support.data.SupportMediaItem
import com.testlogon.android.feature.support.data.SupportMediaUploader
import com.testlogon.android.feature.support.data.SupportRepository
import com.testlogon.android.feature.support.data.SupportTicket
import com.testlogon.android.navigation.SupportTicketDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/**
 * B-SUP (batch 7) - one ticket: messages thread + a reply composer. Shared by both roles (the SAME thread).
 * Admin-only status/assign controls are exposed via isAdmin; a USER never sees them (server 403s anyway).
 */
data class SupportTicketDetailUiState(
    val loading: Boolean = true,
    val ticket: SupportTicket? = null,
    val error: String? = null,
    val reply: String = "",
    val sending: Boolean = false,
    val actionError: String? = null,
    val actionInFlight: Boolean = false,
    val isAdmin: Boolean = false,
    // B8 #15 - owner close/cancel
    val closing: Boolean = false,
    // B10 B-HELPMEDIA #5 - the ordered list of staged attachments on the next reply.
    val media: List<StagedMedia> = emptyList(),
    // Helpdesk #17 - owner reopen of a terminal ticket.
    val reopening: Boolean = false,
) {
    val canReply: Boolean
        get() = ticket != null && (isAdmin || !ticket.isTerminal)

    val uploadingMedia: Boolean get() = media.any { it.uploading }
    val mediaFull: Boolean get() = media.size >= SupportMediaUploader.MAX_MEDIA
    val resolvedMedia: List<SupportMediaItem> get() = media.mapNotNull { it.item }

    val canSend: Boolean
        get() = canReply &&
            !sending &&
            !uploadingMedia &&
            (resolvedMedia.isNotEmpty() || reply.trim().length in SupportRepository.REPLY_MIN..SupportRepository.REPLY_MAX)

    val canClose: Boolean
        get() = !isAdmin && ticket != null && !ticket.isTerminal && !closing && !actionInFlight

    val canReopen: Boolean
        get() = !isAdmin && ticket != null && ticket.isTerminal && !reopening && !actionInFlight
}

@HiltViewModel
class SupportTicketDetailViewModel @Inject constructor(
    private val repository: SupportRepository,
    private val mediaUploader: SupportMediaUploader,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val ticketId: String =
        savedStateHandle.get<String>(SupportTicketDetailDest.ARG_TICKET_ID).orEmpty()

    private val _uiState = MutableStateFlow(
        SupportTicketDetailUiState(
            isAdmin = savedStateHandle.get<Boolean>(SupportTicketDetailDest.ARG_IS_ADMIN) ?: false,
        ),
    )
    val uiState: StateFlow<SupportTicketDetailUiState> = _uiState.asStateFlow()

    val statusOptions = listOf("open", "in_progress", "waiting_on_user", "done", "reopened")

    init { load() }

    fun load() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(loading = true, error = null)
            when (val r = repository.getTicket(ticketId)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(loading = false, ticket = r.data, error = null)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(loading = false, error = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(loading = false, error = "You appear to be offline.")
            }
        }
    }

    fun onReplyChange(v: String) { _uiState.value = _uiState.value.copy(reply = v) }

    // ---- B10 B-HELPMEDIA #5: staged attachments on the reply ----

    fun addImage(uri: Uri) = stageUpload(uri.toString(), isImage = true) { mediaUploader.uploadImage(uri) }
    fun addVideo(uri: Uri) = stageUpload(null, isImage = false) { mediaUploader.uploadVideo(uri) }
    fun addFile(uri: Uri) = stageUpload(null, isImage = false) { mediaUploader.uploadFile(uri) }

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
            actionError = null,
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
                is ApiResult.Failure -> { drop(id); _uiState.value = _uiState.value.copy(actionError = r.error.message) }
                is ApiResult.NetworkError -> { drop(id); _uiState.value = _uiState.value.copy(actionError = "You appear to be offline.") }
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

    fun sendReply() {
        val s = _uiState.value
        if (!s.canSend) return
        viewModelScope.launch {
            _uiState.value = s.copy(sending = true, actionError = null)
            val resolved = _uiState.value.resolvedMedia
            // The backend requires a non-empty body even on a media-only reply; supply a sensible
            // placeholder so attaching files without typing still posts.
            val body = s.reply.trim().ifBlank { if (resolved.isNotEmpty()) "(attachment)" else s.reply }
            when (val r = repository.addMessage(ticketId, body, media = resolved)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(sending = false, reply = "", media = emptyList(), ticket = r.data)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(sending = false, actionError = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(sending = false, actionError = "You appear to be offline.")
            }
        }
    }

    fun setStatus(status: String) {
        if (!_uiState.value.isAdmin) return
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(actionInFlight = true, actionError = null)
            when (val r = repository.setStatus(ticketId, status)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(actionInFlight = false, ticket = r.data)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(actionInFlight = false, actionError = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(actionInFlight = false, actionError = "You appear to be offline.")
            }
        }
    }

    fun closeTicket(action: String) {
        val s = _uiState.value
        if (s.isAdmin || s.ticket == null || s.ticket.isTerminal || s.closing) return
        viewModelScope.launch {
            _uiState.value = s.copy(closing = true, actionError = null)
            when (val r = repository.closeTicket(ticketId, action)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(closing = false, ticket = r.data)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(closing = false, actionError = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(closing = false, actionError = "You appear to be offline.")
            }
        }
    }

    fun reopenTicket() {
        val s = _uiState.value
        if (s.isAdmin || s.ticket == null || !s.ticket.isTerminal || s.reopening) return
        viewModelScope.launch {
            _uiState.value = s.copy(reopening = true, actionError = null)
            when (val r = repository.reopenTicket(ticketId)) {
                is ApiResult.Success ->
                    _uiState.value = _uiState.value.copy(reopening = false, ticket = r.data)
                is ApiResult.Failure ->
                    _uiState.value = _uiState.value.copy(reopening = false, actionError = r.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = _uiState.value.copy(reopening = false, actionError = "You appear to be offline.")
            }
        }
    }

    fun clearActionError() { _uiState.value = _uiState.value.copy(actionError = null) }
}
