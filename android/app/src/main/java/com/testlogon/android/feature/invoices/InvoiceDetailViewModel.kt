package com.testlogon.android.feature.invoices

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.invoices.InvoiceDetail
import com.testlogon.android.data.invoices.InvoicesRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import com.testlogon.android.feature.billing.error.Recoverability
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-243 — invoice detail screen state. */
sealed interface InvoiceDetailUiState {
    data object Loading : InvoiceDetailUiState
    data class Content(val invoice: InvoiceDetail) : InvoiceDetailUiState
    data class Error(val message: UiText, val retryable: Boolean) : InvoiceDetailUiState
}

/** AND-243 — the email-invoice action's own state (kept separate so it never clobbers screen state). */
sealed interface EmailUiState {
    data object Idle : EmailUiState
    data object Sending : EmailUiState

    /** Sent — [emailedTo] is the server-determined recipient (may be blank; the UI omits it then). */
    data class Sent(val emailedTo: String) : EmailUiState
    data class Error(val message: UiText) : EmailUiState
}

/** AND-243 — one-shot effects (Channel-backed so rotation cannot replay them). */
sealed interface InvoiceDetailEvent {
    /** Open the invoice PDF in a browser / Custom Tab at [url] (server-cookie download). */
    data class ViewPdf(val url: String) : InvoiceDetailEvent
}

/**
 * AND-243 — invoice detail presentation logic.
 *
 * Loads `/ui/invoices/{invoice_number}` once on construction (a single init load), exposing
 * Loading/Content/Error. The "Email invoice" action POSTs `/ui/invoices/{n}/email` behind an in-flight
 * guard (a second tap while Sending is swallowed, so no duplicate POST) and reflects the recipient via a
 * separate [emailState]. The "View / download PDF" action emits a one-shot [InvoiceDetailEvent.ViewPdf]
 * with the absolute PDF URL (opened in a Custom Tab so session cookies ride along). Failures map through
 * [BillingErrorMapper] (AND-232), reusing the billing error dictionary/recoverability.
 */
@HiltViewModel
class InvoiceDetailViewModel @Inject constructor(
    private val repository: InvoicesRepository,
    private val errorMapper: BillingErrorMapper,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val invoiceNumber: String = checkNotNull(savedStateHandle[ARG_INVOICE_NUMBER]) {
        "InvoiceDetailViewModel requires an '$ARG_INVOICE_NUMBER' nav argument"
    }

    private val _uiState = MutableStateFlow<InvoiceDetailUiState>(InvoiceDetailUiState.Loading)
    val uiState: StateFlow<InvoiceDetailUiState> = _uiState.asStateFlow()

    private val _emailState = MutableStateFlow<EmailUiState>(EmailUiState.Idle)
    val emailState: StateFlow<EmailUiState> = _emailState.asStateFlow()

    private val _events = Channel<InvoiceDetailEvent>(Channel.BUFFERED)
    val events: Flow<InvoiceDetailEvent> = _events.receiveAsFlow()

    init {
        load()
    }

    fun retry() = load()

    private fun load() {
        _uiState.value = InvoiceDetailUiState.Loading
        viewModelScope.launch {
            when (val result = repository.getInvoice(invoiceNumber)) {
                is ApiResult.Success ->
                    _uiState.value = InvoiceDetailUiState.Content(result.data)
                else -> {
                    val error = errorMapper.map(result)
                    // A 404 is a non-retryable "not found"; everything retryable per the mapper.
                    val retryable = error.recoverability == Recoverability.RETRYABLE &&
                        (result as? ApiResult.Failure)?.error?.status != 404
                    _uiState.value = InvoiceDetailUiState.Error(message = error.message, retryable = retryable)
                }
            }
        }
    }

    /** AND-243 — email a copy of this invoice. In-flight guard prevents duplicate POSTs. */
    fun onEmailClicked() {
        if (_emailState.value is EmailUiState.Sending) return // in-flight guard (no duplicate POST)
        _emailState.value = EmailUiState.Sending
        viewModelScope.launch {
            when (val result = repository.emailInvoice(invoiceNumber)) {
                is ApiResult.Success ->
                    _emailState.value = EmailUiState.Sent(result.data.emailedTo)
                else ->
                    _emailState.value = EmailUiState.Error(errorMapper.map(result).message)
            }
        }
    }

    /** AND-243 — open the invoice PDF in a browser / Custom Tab. */
    fun onViewPdfClicked() {
        viewModelScope.launch {
            _events.send(InvoiceDetailEvent.ViewPdf(repository.pdfUrl(invoiceNumber)))
        }
    }

    /** Reset the email action after a snackbar has been shown (so a later tap starts fresh). */
    fun onEmailFeedbackShown() {
        if (_emailState.value is EmailUiState.Sent || _emailState.value is EmailUiState.Error) {
            _emailState.value = EmailUiState.Idle
        }
    }

    companion object {
        const val ARG_INVOICE_NUMBER = "invoiceNumber"
    }
}
