package com.testlogon.android.feature.adcreativereview

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adcreativereview.AdCreativeReviewRepository
import com.testlogon.android.data.adcreativereview.PendingCreativeDto
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Web-parity admin creative-review queue. Mirrors /admin/ads/creatives/review. A backend 403 (non-admin)
 * -> Forbidden (non-destructive, offers Back). Approve/reject act on a selected creative; on success the
 * row is removed from the queue optimistically (the web page invalidates + refetches).
 */
sealed interface CreativeReviewUiState {
    data object Loading : CreativeReviewUiState
    data class Content(
        val creatives: List<PendingCreativeDto>,
        val isRefreshing: Boolean = false,
        val actionInFlight: Boolean = false,
        val actionMessage: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : CreativeReviewUiState
    data object Empty : CreativeReviewUiState
    data object Forbidden : CreativeReviewUiState
    data class Error(val type: AdminOpsErrorType) : CreativeReviewUiState
}

@HiltViewModel
class AdCreativeReviewViewModel @Inject constructor(
    private val repo: AdCreativeReviewRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<CreativeReviewUiState>(CreativeReviewUiState.Loading)
    val state: StateFlow<CreativeReviewUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur is CreativeReviewUiState.Content) {
            _state.value = cur.copy(isRefreshing = true, transientError = null)
        }
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = CreativeReviewUiState.Loading
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.listPending()) {
                is ApiResult.Success ->
                    _state.value = if (r.data.isEmpty()) {
                        CreativeReviewUiState.Empty
                    } else {
                        CreativeReviewUiState.Content(creatives = r.data)
                    }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun review(creativeId: String, decision: String, notes: String?) {
        val cur = _state.value as? CreativeReviewUiState.Content ?: return
        if (cur.actionInFlight) return
        _state.value = cur.copy(actionInFlight = true, transientError = null, actionMessage = null)
        viewModelScope.launch {
            when (val r = repo.review(creativeId, decision, notes)) {
                is ApiResult.Success -> {
                    val prev = _state.value as? CreativeReviewUiState.Content ?: return@launch
                    val remaining = prev.creatives.filterNot { it.creativeId == creativeId }
                    _state.value = if (remaining.isEmpty()) {
                        CreativeReviewUiState.Empty
                    } else {
                        prev.copy(
                            creatives = remaining,
                            actionInFlight = false,
                            actionMessage = if (decision == "approve") "Creative approved." else "Creative rejected.",
                        )
                    }
                }
                is ApiResult.Failure -> reduceActionError(
                    if (r.error.status == 403) AdminOpsErrorType.AUTH else adminOpsErrorFor(r.error.status),
                )
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) {
        if (status == 403) {
            _state.value = CreativeReviewUiState.Forbidden
        } else {
            reduceError(isRefresh, adminOpsErrorFor(status))
        }
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? CreativeReviewUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, transientError = type)
        } else {
            CreativeReviewUiState.Error(type)
        }
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        val cur = _state.value as? CreativeReviewUiState.Content ?: return
        _state.value = cur.copy(actionInFlight = false, transientError = type)
    }

    fun clearActionMessage() {
        val cur = _state.value
        if (cur is CreativeReviewUiState.Content) {
            _state.value = cur.copy(actionMessage = null, transientError = null)
        }
    }
}
