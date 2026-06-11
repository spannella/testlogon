package com.testlogon.android.feature.disputes

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.disputes.Dispute
import com.testlogon.android.data.disputes.DisputesRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-245 — dispute detail state. A 404 maps to a dedicated NotFound (defensive — AND-245 §4.6). */
sealed interface DisputeDetailUiState {
    data object Loading : DisputeDetailUiState
    data class Content(val dispute: Dispute) : DisputeDetailUiState
    data object NotFound : DisputeDetailUiState
    data class Failure(val message: UiText) : DisputeDetailUiState
}

/**
 * AND-245 — dispute detail presentation logic. `disputeId` is read from [SavedStateHandle] so detail
 * survives process death; [load] re-fetches. Failures map through [BillingErrorMapper] (AND-232).
 */
@HiltViewModel
class DisputeDetailViewModel @Inject constructor(
    private val repository: DisputesRepository,
    private val errorMapper: BillingErrorMapper,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val disputeId: String = checkNotNull(savedStateHandle[ARG_DISPUTE_ID]) {
        "DisputeDetailViewModel requires a '$ARG_DISPUTE_ID' nav argument"
    }

    private val _state = MutableStateFlow<DisputeDetailUiState>(DisputeDetailUiState.Loading)
    val state: StateFlow<DisputeDetailUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        _state.value = DisputeDetailUiState.Loading
        viewModelScope.launch {
            _state.value = when (val result = repository.getDispute(disputeId)) {
                is ApiResult.Success -> DisputeDetailUiState.Content(result.data)
                is ApiResult.Failure ->
                    if (result.error.status == 404) DisputeDetailUiState.NotFound
                    else DisputeDetailUiState.Failure(errorMapper.map(result).message)
                is ApiResult.NetworkError -> DisputeDetailUiState.Failure(errorMapper.map(result).message)
            }
        }
    }

    companion object {
        const val ARG_DISPUTE_ID = "disputeId"
    }
}
