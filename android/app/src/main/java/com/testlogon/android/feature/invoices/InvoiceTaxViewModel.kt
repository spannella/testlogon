package com.testlogon.android.feature.invoices

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.invoices.InvoiceTax
import com.testlogon.android.data.invoices.InvoicesRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import com.testlogon.android.feature.billing.error.Recoverability
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-249 — read-only invoice tax state. There are no per-rate tax lines in the contract; the breakdown
 * is the flat subtotal/tax/total derived from the invoice's scalar fields.
 */
sealed interface InvoiceTaxUiState {
    data object Loading : InvoiceTaxUiState
    data class Content(val tax: InvoiceTax) : InvoiceTaxUiState
    data class Error(val message: UiText, val retryable: Boolean) : InvoiceTaxUiState
}

/**
 * AND-249 — invoice-tax presentation logic. Keyed by the invoice_number nav arg (via [SavedStateHandle]),
 * loads on construction reusing [InvoicesRepository.getInvoiceTax] (no aggregate / no extra endpoint).
 * Failures map through [BillingErrorMapper] (a 404 is non-retryable, transient is retryable) — matching
 * the [InvoiceDetailViewModel] convention so the screens stay consistent.
 */
@HiltViewModel
class InvoiceTaxViewModel @Inject constructor(
    private val repository: InvoicesRepository,
    private val errorMapper: BillingErrorMapper,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val invoiceNumber: String = checkNotNull(savedStateHandle[ARG_INVOICE_NUMBER]) {
        "InvoiceTaxViewModel requires an '$ARG_INVOICE_NUMBER' nav argument"
    }

    private val _uiState = MutableStateFlow<InvoiceTaxUiState>(InvoiceTaxUiState.Loading)
    val uiState: StateFlow<InvoiceTaxUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    private fun load() {
        _uiState.value = InvoiceTaxUiState.Loading
        viewModelScope.launch {
            when (val result = repository.getInvoiceTax(invoiceNumber)) {
                is ApiResult.Success -> _uiState.value = InvoiceTaxUiState.Content(result.data)
                else -> {
                    val error = errorMapper.map(result)
                    val retryable = error.recoverability == Recoverability.RETRYABLE &&
                        (result as? ApiResult.Failure)?.error?.status != 404
                    _uiState.value = InvoiceTaxUiState.Error(message = error.message, retryable = retryable)
                }
            }
        }
    }

    companion object {
        // Shares the invoice_number nav arg with InvoiceDetailViewModel (the tax view is keyed the same).
        const val ARG_INVOICE_NUMBER = InvoiceDetailViewModel.ARG_INVOICE_NUMBER
    }
}
