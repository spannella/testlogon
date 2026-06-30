package com.testlogon.android.feature.boost.manage

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.BoostStatus
import com.testlogon.android.core.model.ads.ContentBoost
import com.testlogon.android.feature.boost.data.BoostRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * Presentation logic for the BOOST DETAIL screen (web parity: ContentBoostDetail.tsx).
 *
 * Loads a single boost by [boostId] (nav arg) via the existing [BoostRepository.getBoost]; offers Cancel +
 * refund ONLY while the boost is active (the server enforces this; the client gates the affordance). Refresh
 * re-reads the boost. READ + a single cancel WRITE; NO polling loop (unlike the per-post create flow which
 * watches a just-created boost). Distinct from BoostViewModel (which is keyed by postId + creates a boost).
 *
 * Dispatcher seam: ioDispatcher defaults to IO and is read inside coroutines so a test can swap it.
 */
@HiltViewModel
class BoostDetailViewModel @Inject constructor(
    private val repository: BoostRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val boostId: String = savedState.get<String>(ARG_BOOST_ID).orEmpty()

    var ioDispatcher: CoroutineDispatcher = Dispatchers.IO

    private val _uiState = MutableStateFlow<BoostDetailUiState>(BoostDetailUiState.Loading)
    val uiState: StateFlow<BoostDetailUiState> = _uiState.asStateFlow()

    init {
        if (boostId.isBlank()) {
            _uiState.value = BoostDetailUiState.Error(
                ApiError(status = ApiError.STATUS_NETWORK, message = "No boost selected."),
            )
        } else {
            load()
        }
    }

    fun load() {
        if (boostId.isBlank()) return
        _uiState.value = BoostDetailUiState.Loading
        viewModelScope.launch {
            when (val r = withContext(ioDispatcher) { repository.getBoost(boostId) }) {
                is ApiResult.Success -> showContent(r.data)
                is ApiResult.Failure -> _uiState.value = BoostDetailUiState.Error(r.error)
                is ApiResult.NetworkError -> _uiState.value = BoostDetailUiState.Error(networkError())
            }
        }
    }

    fun onRetry() = load()

    fun refresh() {
        val content = _uiState.value as? BoostDetailUiState.Content ?: return
        if (content.refreshing || content.cancelling) return
        _uiState.value = content.copy(refreshing = true, actionError = null)
        viewModelScope.launch {
            when (val r = withContext(ioDispatcher) { repository.getBoost(boostId) }) {
                is ApiResult.Success -> showContent(r.data)
                is ApiResult.Failure -> _uiState.update {
                    (it as? BoostDetailUiState.Content)?.copy(refreshing = false, actionError = r.error.message) ?: it
                }
                is ApiResult.NetworkError -> _uiState.update {
                    (it as? BoostDetailUiState.Content)?.copy(refreshing = false, actionError = OFFLINE_FALLBACK) ?: it
                }
            }
        }
    }

    fun cancel() {
        val content = _uiState.value as? BoostDetailUiState.Content ?: return
        if (!content.canCancel || content.cancelling || content.refreshing) return
        _uiState.value = content.copy(cancelling = true, actionError = null)
        viewModelScope.launch {
            when (val r = withContext(ioDispatcher) { repository.cancelBoost(boostId) }) {
                is ApiResult.Success -> {
                    val refund = r.data.refundedCents
                    // Re-read the boost so the status/spend reflect the cancel.
                    when (val reread = withContext(ioDispatcher) { repository.getBoost(boostId) }) {
                        is ApiResult.Success -> showContent(reread.data, refund)
                        else -> _uiState.update {
                            (it as? BoostDetailUiState.Content)?.copy(
                                cancelling = false,
                                canCancel = false,
                                cancelledRefundCents = refund,
                            ) ?: it
                        }
                    }
                }
                is ApiResult.Failure -> _uiState.update {
                    (it as? BoostDetailUiState.Content)?.copy(cancelling = false, actionError = r.error.message) ?: it
                }
                is ApiResult.NetworkError -> _uiState.update {
                    (it as? BoostDetailUiState.Content)?.copy(cancelling = false, actionError = OFFLINE_FALLBACK) ?: it
                }
            }
        }
    }

    private fun showContent(boost: ContentBoost, refund: Long? = null) {
        val prevRefund = (_uiState.value as? BoostDetailUiState.Content)?.cancelledRefundCents
        _uiState.value = BoostDetailUiState.Content(
            boost = boost,
            canCancel = boost.statusEnum == BoostStatus.ACTIVE,
            cancelledRefundCents = refund ?: prevRefund,
        )
    }

    private fun networkError() = ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        const val ARG_BOOST_ID = "boostId"
        private const val OFFLINE_FALLBACK = "Could not reach the server. Try again."
    }
}
