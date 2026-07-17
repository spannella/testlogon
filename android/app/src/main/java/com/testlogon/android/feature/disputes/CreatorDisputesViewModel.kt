package com.testlogon.android.feature.disputes

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.disputes.CreatorRespondInput
import com.testlogon.android.data.disputes.Dispute
import com.testlogon.android.data.disputes.DisputesRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** DISP-024 — creator "Respond to dispute" inbound-queue state. */
sealed interface CreatorDisputesUiState {
    data object Loading : CreatorDisputesUiState
    data object Empty : CreatorDisputesUiState
    data class Content(val disputes: List<Dispute>) : CreatorDisputesUiState
    data class Failure(val message: UiText) : CreatorDisputesUiState
}

/** DISP-024 — the transient state of the respond composer + one-shot events. */
data class CreatorRespondUiState(
    val submitting: Boolean = false,
    val submittedDisputeId: String? = null,
    val errorMessage: UiText? = null,
)

/**
 * DISP-024 — creator inbound-dispute queue + rebuttal submission. Loads once; [load] re-fetches; a
 * successful [respond] re-fetches so the row advances to `under_review`. Failures map through
 * [BillingErrorMapper] for a sanitized, localizable message.
 */
@HiltViewModel
class CreatorDisputesViewModel @Inject constructor(
    private val repository: DisputesRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _state = MutableStateFlow<CreatorDisputesUiState>(CreatorDisputesUiState.Loading)
    val state: StateFlow<CreatorDisputesUiState> = _state.asStateFlow()

    private val _respond = MutableStateFlow(CreatorRespondUiState())
    val respond: StateFlow<CreatorRespondUiState> = _respond.asStateFlow()

    init {
        load()
    }

    fun load() {
        _state.value = CreatorDisputesUiState.Loading
        viewModelScope.launch {
            _state.value = when (val result = repository.listCreatorDisputes()) {
                is ApiResult.Success ->
                    if (result.data.isEmpty()) CreatorDisputesUiState.Empty
                    else CreatorDisputesUiState.Content(result.data)
                else -> CreatorDisputesUiState.Failure(errorMapper.map(result).message)
            }
        }
    }

    fun respond(disputeId: String, responseText: String) {
        if (responseText.isBlank() || _respond.value.submitting) return
        _respond.update { it.copy(submitting = true, errorMessage = null, submittedDisputeId = null) }
        viewModelScope.launch {
            when (val result = repository.creatorRespond(
                CreatorRespondInput(disputeId = disputeId, responseText = responseText.trim()),
            )) {
                is ApiResult.Success -> {
                    _respond.update { it.copy(submitting = false, submittedDisputeId = disputeId) }
                    load()
                }
                else -> _respond.update {
                    it.copy(submitting = false, errorMessage = errorMapper.map(result).message)
                }
            }
        }
    }

    /** Clear the one-shot success/error after the UI consumes it. */
    fun consumeRespondEvent() {
        _respond.update { CreatorRespondUiState() }
    }
}
