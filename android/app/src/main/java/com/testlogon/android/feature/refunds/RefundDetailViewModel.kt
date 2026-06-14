package com.testlogon.android.feature.refunds

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.refunds.RefundRequest
import com.testlogon.android.data.refunds.RefundsRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import com.testlogon.android.feature.billing.error.Recoverability
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-244 — refund detail screen state. */
sealed interface RefundDetailUiState {
    data object Loading : RefundDetailUiState
    data class Content(val refund: RefundRequest) : RefundDetailUiState
    data class Error(val message: UiText, val retryable: Boolean) : RefundDetailUiState
}

/**
 * AND-244 — refund detail presentation logic. Loads `/ui/billing/refund-requests/{id}` on construction;
 * status is re-fetched on [refresh]. Failures map through [BillingErrorMapper] (AND-232); a 404 is a
 * non-retryable "not found".
 */
@HiltViewModel
class RefundDetailViewModel @Inject constructor(
    private val repository: RefundsRepository,
    private val errorMapper: BillingErrorMapper,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val refundId: String = checkNotNull(savedStateHandle[ARG_REFUND_ID]) {
        "RefundDetailViewModel requires a '$ARG_REFUND_ID' nav argument"
    }

    private val _uiState = MutableStateFlow<RefundDetailUiState>(RefundDetailUiState.Loading)
    val uiState: StateFlow<RefundDetailUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun refresh() = load()

    private fun load() {
        _uiState.value = RefundDetailUiState.Loading
        viewModelScope.launch {
            when (val result = repository.getRefund(refundId)) {
                is ApiResult.Success -> _uiState.value = RefundDetailUiState.Content(result.data)
                else -> {
                    val error = errorMapper.map(result)
                    val retryable = error.recoverability == Recoverability.RETRYABLE &&
                        (result as? ApiResult.Failure)?.error?.status != 404
                    _uiState.value = RefundDetailUiState.Error(message = error.message, retryable = retryable)
                }
            }
        }
    }

    companion object {
        const val ARG_REFUND_ID = "refundId"
    }
}
