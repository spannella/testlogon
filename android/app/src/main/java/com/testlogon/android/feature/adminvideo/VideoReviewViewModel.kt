package com.testlogon.android.feature.adminvideo

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminvideo.VideoReviewAdminRepository
import com.testlogon.android.data.adminvideo.VideoReviewItemDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B5 - admin video-review queue. List of pending videos with approve/reject per item. Mirrors
 * /admin/video-review (VideoReviewQueuePage.tsx). A backend 403 -> Forbidden.
 */
sealed interface VideoReviewUiState {
    data object Loading : VideoReviewUiState
    data class Content(
        val items: List<VideoReviewItemDto>,
        val totalPending: Int,
        val isRefreshing: Boolean = false,
        val actionInFlightId: String? = null,
        val message: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : VideoReviewUiState
    data object Empty : VideoReviewUiState
    data object Forbidden : VideoReviewUiState
    data class Error(val type: AdminOpsErrorType) : VideoReviewUiState
}

@HiltViewModel
class VideoReviewViewModel @Inject constructor(
    private val repo: VideoReviewAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<VideoReviewUiState>(VideoReviewUiState.Loading)
    val state: StateFlow<VideoReviewUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur is VideoReviewUiState.Content) _state.value = cur.copy(isRefreshing = true, transientError = null)
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = VideoReviewUiState.Loading
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.queue()) {
                is ApiResult.Success -> {
                    val items = r.data.items
                    _state.value = if (items.isEmpty()) {
                        VideoReviewUiState.Empty
                    } else {
                        VideoReviewUiState.Content(items = items, totalPending = r.data.totalPending)
                    }
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun approve(videoId: String, notes: String?) = runAction(videoId, "Approved") { repo.approve(videoId, notes) }

    fun reject(videoId: String, reason: String) = runAction(videoId, "Rejected") { repo.reject(videoId, reason) }

    private fun runAction(videoId: String, successMsg: String, block: suspend () -> ApiResult<*>) {
        val cur = _state.value
        if (cur !is VideoReviewUiState.Content || cur.actionInFlightId != null) return
        _state.value = cur.copy(actionInFlightId = videoId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    val prev = _state.value as? VideoReviewUiState.Content ?: return@launch
                    val remaining = prev.items.filterNot { it.videoId == videoId }
                    _state.value = if (remaining.isEmpty()) {
                        VideoReviewUiState.Empty
                    } else {
                        prev.copy(
                            items = remaining,
                            totalPending = (prev.totalPending - 1).coerceAtLeast(0),
                            actionInFlightId = null,
                            message = successMsg,
                        )
                    }
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        val cur = _state.value as? VideoReviewUiState.Content ?: return
        _state.value = cur.copy(actionInFlightId = null, transientError = type)
    }

    fun clearMessage() {
        val cur = _state.value
        if (cur is VideoReviewUiState.Content) _state.value = cur.copy(message = null, transientError = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = VideoReviewUiState.Forbidden
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? VideoReviewUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, transientError = type)
        } else {
            VideoReviewUiState.Error(type)
        }
    }
}
