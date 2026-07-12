package com.testlogon.android.feature.admessaging.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.admessaging.data.AdMessageOffer
import com.testlogon.android.feature.admessaging.data.AdMessagingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ADV2-501/507 (F5) — drives the creator APPROVAL QUEUE for advertiser-drafted sponsored MESSAGES.
 *
 * A single GET loads the caller's PENDING offers ([AdMessagingRepository.inbox], server-filtered to
 * pending_creator). Only the TARGETED creator sees / may act on them (server-enforced). APPROVE sends the
 * message to the creator's audience AS the creator (billing the advertiser hybrid + crediting the creator
 * 70% per event, D3 no forced label); REJECT closes it with no send. Both are NON-idempotent: the acted-on
 * offer is gated in [acting] (no double-tap) and dropped from the list on success (a 409 already-resolved
 * is treated as resolved and also dropped). NO auto-retry. On approve, a one-shot [lastSendResult] carries
 * the delivered-count so the screen can confirm the send.
 */
@HiltViewModel
class AdMessageQueueViewModel @Inject constructor(
    private val repository: AdMessagingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<AdMessageQueueUiState>(AdMessageQueueUiState.Loading)
    val uiState: StateFlow<AdMessageQueueUiState> = _uiState.asStateFlow()

    /** offer ids with an approve/reject in flight (per-row spinner + tap gate). */
    private val _acting = MutableStateFlow<Set<String>>(emptySet())
    val acting: StateFlow<Set<String>> = _acting.asStateFlow()

    /** One-shot "sent to N recipients" banner after an approve (null once consumed). */
    private val _lastSendResult = MutableStateFlow<Int?>(null)
    val lastSendResult: StateFlow<Int?> = _lastSendResult.asStateFlow()

    init { load() }

    fun load() {
        _uiState.value = AdMessageQueueUiState.Loading
        fetch()
    }

    fun onRetry() = load()

    fun refresh() = fetch()

    fun consumeSendResult() { _lastSendResult.value = null }

    private fun fetch() {
        viewModelScope.launch {
            _uiState.value = when (val result = repository.inbox()) {
                is ApiResult.Success ->
                    if (result.data.isEmpty()) AdMessageQueueUiState.Empty
                    else AdMessageQueueUiState.Content(result.data.sortedByDescending { it.createdAt ?: Long.MIN_VALUE })
                is ApiResult.Failure -> AdMessageQueueUiState.Error(result.error.message)
                is ApiResult.NetworkError -> AdMessageQueueUiState.Error(OFFLINE)
            }
        }
    }

    fun approve(offerId: String) {
        if (offerId in _acting.value) return
        _acting.value = _acting.value + offerId
        viewModelScope.launch {
            when (val result = repository.approve(offerId)) {
                is ApiResult.Success -> {
                    _lastSendResult.value = result.data.deliveredCount
                    remove(offerId)
                }
                is ApiResult.Failure -> if (result.error.status == HTTP_CONFLICT) remove(offerId) else Unit
                is ApiResult.NetworkError -> Unit
            }
            _acting.value = _acting.value - offerId
        }
    }

    fun reject(offerId: String) {
        if (offerId in _acting.value) return
        _acting.value = _acting.value + offerId
        viewModelScope.launch {
            when (val result = repository.reject(offerId)) {
                is ApiResult.Success -> remove(offerId)
                is ApiResult.Failure -> if (result.error.status == HTTP_CONFLICT) remove(offerId) else Unit
                is ApiResult.NetworkError -> Unit
            }
            _acting.value = _acting.value - offerId
        }
    }

    /** Drop the resolved offer from the in-memory list; empties out when the last one is acted on. */
    private fun remove(offerId: String) {
        val current = _uiState.value as? AdMessageQueueUiState.Content ?: return
        val remaining = current.offers.filterNot { it.offerId == offerId }
        _uiState.value = if (remaining.isEmpty()) AdMessageQueueUiState.Empty
        else AdMessageQueueUiState.Content(remaining)
    }

    private companion object {
        const val OFFLINE = "Couldn't reach the server. Pull down to retry."
        const val HTTP_CONFLICT = 409
    }
}

/** ADV2-507 — exhaustive UI state for the creator sponsored-message approval queue. */
sealed interface AdMessageQueueUiState {
    data object Loading : AdMessageQueueUiState
    data class Content(val offers: List<AdMessageOffer>) : AdMessageQueueUiState
    data object Empty : AdMessageQueueUiState
    data class Error(val message: String) : AdMessageQueueUiState
}
