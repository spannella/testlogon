package com.testlogon.android.feature.stylist

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.stylist.StylistRepository
import com.testlogon.android.navigation.StylistReviewDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [StylistReviewUiState] for a single UI review (web StylistReviewDetailPage). Loads the review
 * by id (from nav args); "Create Ticket" on an issue POSTs to the issue-ticket endpoint then reloads so
 * the issue shows its ticket badge.
 */
@HiltViewModel
class StylistReviewViewModel @Inject constructor(
    private val repository: StylistRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val reviewId: String = savedStateHandle.get<String>(StylistReviewDest.ARG_REVIEW_ID).orEmpty()

    private val _uiState = MutableStateFlow(StylistReviewUiState())
    val uiState: StateFlow<StylistReviewUiState> = _uiState.asStateFlow()

    private val _effects = Channel<StylistEffect>(Channel.BUFFERED)
    val effects: Flow<StylistEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun onCreateTicket(issueId: String) {
        if (_uiState.value.creatingTicketIssueId != null) return
        _uiState.update { it.copy(creatingTicketIssueId = issueId) }
        viewModelScope.launch {
            val r = repository.createIssueTicket(reviewId, issueId)
            _uiState.update { it.copy(creatingTicketIssueId = null) }
            when (r) {
                is ApiResult.Success -> {
                    _effects.send(StylistEffect.ShowMessage(R.string.stylist_ticket_created))
                    load()
                }
                is ApiResult.Failure ->
                    if (r.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = StylistReviewUiState.Phase.SessionExpired) }
                    } else {
                        _effects.send(StylistEffect.ShowMessage(R.string.stylist_ticket_failed))
                    }
                is ApiResult.NetworkError ->
                    _effects.send(StylistEffect.ShowMessage(R.string.stylist_ticket_failed))
            }
        }
    }

    private fun load() {
        if (reviewId.isBlank()) {
            _uiState.update { it.copy(phase = StylistReviewUiState.Phase.Error, errorMessage = "Missing review id") }
            return
        }
        _uiState.update { it.copy(phase = if (it.review == null) StylistReviewUiState.Phase.Loading else it.phase) }
        viewModelScope.launch {
            when (val result = repository.getReview(reviewId)) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(phase = StylistReviewUiState.Phase.Content, review = result.data, errorMessage = null)
                    }
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = StylistReviewUiState.Phase.SessionExpired) }
                    } else {
                        _uiState.update {
                            it.copy(phase = StylistReviewUiState.Phase.Error, errorMessage = result.error.message)
                        }
                    }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(phase = StylistReviewUiState.Phase.Offline, errorMessage = OFFLINE_FALLBACK)
                    }
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Retry."
    }
}
