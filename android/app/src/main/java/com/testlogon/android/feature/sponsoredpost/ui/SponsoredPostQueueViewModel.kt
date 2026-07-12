package com.testlogon.android.feature.sponsoredpost.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.sponsoredpost.data.SponsoredPostProposal
import com.testlogon.android.feature.sponsoredpost.data.SponsoredPostRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ADV2-408 (F4) - drives the creator APPROVAL QUEUE for advertiser-drafted sponsored posts.
 *
 * A single GET loads the caller's PENDING proposals ([SponsoredPostRepository.inbox], server-filtered to
 * draft_proposed). Only the TARGETED creator sees / may act on them (server-enforced). APPROVE publishes a
 * NORMAL creator-authored post carrying the DISTINCT paid_partnership flag (tippable/likeable/commentable,
 * no forced label); REJECT closes it with no post. Both are NON-idempotent: the acted-on proposal is gated
 * in [acting] (no double-tap) and dropped from the list on success (a 409 already-resolved is treated as
 * resolved and also dropped). NO auto-retry.
 */
@HiltViewModel
class SponsoredPostQueueViewModel @Inject constructor(
    private val repository: SponsoredPostRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<SponsoredPostQueueUiState>(SponsoredPostQueueUiState.Loading)
    val uiState: StateFlow<SponsoredPostQueueUiState> = _uiState.asStateFlow()

    /** proposal ids with an approve/reject in flight (per-row spinner + tap gate). */
    private val _acting = MutableStateFlow<Set<String>>(emptySet())
    val acting: StateFlow<Set<String>> = _acting.asStateFlow()

    init { load() }

    fun load() {
        _uiState.value = SponsoredPostQueueUiState.Loading
        fetch()
    }

    fun onRetry() = load()

    fun refresh() = fetch()

    private fun fetch() {
        viewModelScope.launch {
            _uiState.value = when (val result = repository.inbox()) {
                is ApiResult.Success ->
                    if (result.data.isEmpty()) SponsoredPostQueueUiState.Empty
                    else SponsoredPostQueueUiState.Content(result.data.sortedByDescending { it.createdAt ?: Long.MIN_VALUE })
                is ApiResult.Failure -> SponsoredPostQueueUiState.Error(result.error.message)
                is ApiResult.NetworkError -> SponsoredPostQueueUiState.Error(OFFLINE)
            }
        }
    }

    fun approve(proposalId: String) {
        if (proposalId in _acting.value) return
        _acting.value = _acting.value + proposalId
        viewModelScope.launch {
            when (val result = repository.approve(proposalId)) {
                is ApiResult.Success -> remove(proposalId)
                is ApiResult.Failure -> if (result.error.status == HTTP_CONFLICT) remove(proposalId) else Unit
                is ApiResult.NetworkError -> Unit
            }
            _acting.value = _acting.value - proposalId
        }
    }

    fun reject(proposalId: String) {
        if (proposalId in _acting.value) return
        _acting.value = _acting.value + proposalId
        viewModelScope.launch {
            when (val result = repository.reject(proposalId, "")) {
                is ApiResult.Success -> remove(proposalId)
                is ApiResult.Failure -> if (result.error.status == HTTP_CONFLICT) remove(proposalId) else Unit
                is ApiResult.NetworkError -> Unit
            }
            _acting.value = _acting.value - proposalId
        }
    }

    /** Drop the resolved proposal from the in-memory list; empties out when the last one is acted on. */
    private fun remove(proposalId: String) {
        val current = _uiState.value as? SponsoredPostQueueUiState.Content ?: return
        val remaining = current.proposals.filterNot { it.proposalId == proposalId }
        _uiState.value = if (remaining.isEmpty()) SponsoredPostQueueUiState.Empty
        else SponsoredPostQueueUiState.Content(remaining)
    }

    private companion object {
        const val OFFLINE = "Couldn't reach the server. Pull down to retry."
        const val HTTP_CONFLICT = 409
    }
}

/** ADV2-408 - exhaustive UI state for the creator approval queue. */
sealed interface SponsoredPostQueueUiState {
    data object Loading : SponsoredPostQueueUiState
    data class Content(val proposals: List<SponsoredPostProposal>) : SponsoredPostQueueUiState
    data object Empty : SponsoredPostQueueUiState
    data class Error(val message: String) : SponsoredPostQueueUiState
}
