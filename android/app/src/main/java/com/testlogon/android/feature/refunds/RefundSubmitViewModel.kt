package com.testlogon.android.feature.refunds

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.refunds.RefundsRepository
import com.testlogon.android.data.refunds.SubmitRefundInput
import com.testlogon.android.feature.billing.error.BillingErrorMapper
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
 * AND-244 — refund submit form state. `reason` is free text (10..2000 chars); `amount` is an optional
 * positive integer cents (partial refund). Submit is enabled only when valid (and not in flight).
 */
data class RefundSubmitUiState(
    val reasonText: String = "",
    val amountText: String = "",
    val reasonError: UiText? = null,
    val amountError: UiText? = null,
    val submitEnabled: Boolean = false,
    val isSubmitting: Boolean = false,
)

/** AND-244 — one-shot submit effects (Channel-backed so rotation cannot replay them). */
sealed interface RefundSubmitEvent {
    /** Submission succeeded; [refundId] is the new request id. */
    data class Success(val refundId: String) : RefundSubmitEvent

    /** Submission failed; [message] is a sanitized, resolvable message. */
    data class Failure(val message: UiText) : RefundSubmitEvent
}

/**
 * AND-244 — refund submit presentation logic.
 *
 * Validates client-side before submit (reason 10..2000 chars; optional amount must be a positive integer
 * number of cents — `amount_cents` minimum 1) and POSTs `/ui/billing/refund-requests`. The in-flight
 * guard ([submit] is a no-op while submitting) is the duplicate protection (no documented Idempotency-Key
 * — AND-244 §6). Failures map through [BillingErrorMapper] (AND-232).
 */
@HiltViewModel
class RefundSubmitViewModel @Inject constructor(
    private val repository: RefundsRepository,
    private val errorMapper: BillingErrorMapper,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val transactionEntryId: String = checkNotNull(savedStateHandle[ARG_TRANSACTION_ENTRY_ID]) {
        "RefundSubmitViewModel requires a '$ARG_TRANSACTION_ENTRY_ID' nav argument"
    }

    private val _uiState = MutableStateFlow(RefundSubmitUiState())
    val uiState: StateFlow<RefundSubmitUiState> = _uiState.asStateFlow()

    private val _events = Channel<RefundSubmitEvent>(Channel.BUFFERED)
    val events: Flow<RefundSubmitEvent> = _events.receiveAsFlow()

    fun onReasonChange(value: String) = _uiState.update { recompute(it.copy(reasonText = value)) }

    fun onAmountChange(value: String) = _uiState.update { recompute(it.copy(amountText = value)) }

    /** Submit the refund request. No-op while already submitting (in-flight duplicate guard). */
    fun submit() {
        val state = _uiState.value
        if (state.isSubmitting) return
        val amountCents = parseAmountCents(state.amountText)
        if (!validate(state.reasonText, state.amountText)) {
            _uiState.update { recompute(it) }
            return
        }
        _uiState.update { it.copy(isSubmitting = true, submitEnabled = false) }
        viewModelScope.launch {
            val input = SubmitRefundInput(
                transactionEntryId = transactionEntryId,
                reason = state.reasonText.trim(),
                amountCents = amountCents,
            )
            when (val result = repository.submitRefund(input)) {
                is ApiResult.Success -> {
                    _events.send(RefundSubmitEvent.Success(result.data.id))
                    _uiState.update { it.copy(isSubmitting = false) }
                }
                else -> {
                    _events.send(RefundSubmitEvent.Failure(errorMapper.map(result).message))
                    _uiState.update { recompute(it.copy(isSubmitting = false)) }
                }
            }
        }
    }

    /** Recomputes field errors + the submit-enabled flag from the current text. */
    private fun recompute(state: RefundSubmitUiState): RefundSubmitUiState {
        val reason = state.reasonText.trim()
        val reasonError: UiText? = when {
            reason.isEmpty() -> null // do not nag on an empty/initial field
            reason.length < MIN_REASON -> UiText.Res(R.string.refunds_error_reason_too_short)
            reason.length > MAX_REASON -> UiText.Res(R.string.refunds_error_reason_too_long)
            else -> null
        }
        val amountRaw = state.amountText.trim()
        val amountError: UiText? = when {
            amountRaw.isEmpty() -> null // optional
            parseAmountCents(amountRaw) == null -> UiText.Res(R.string.refunds_error_amount_invalid)
            else -> null
        }
        val reasonValid = reason.length in MIN_REASON..MAX_REASON
        val amountValid = amountRaw.isEmpty() || parseAmountCents(amountRaw) != null
        return state.copy(
            reasonError = reasonError,
            amountError = amountError,
            submitEnabled = reasonValid && amountValid && !state.isSubmitting,
        )
    }

    private fun validate(reason: String, amount: String): Boolean {
        val reasonValid = reason.trim().length in MIN_REASON..MAX_REASON
        val amountTrim = amount.trim()
        val amountValid = amountTrim.isEmpty() || parseAmountCents(amountTrim) != null
        return reasonValid && amountValid
    }

    /** Parses a positive integer cents amount, or null when blank/non-positive/non-integer. */
    private fun parseAmountCents(raw: String): Long? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        val value = trimmed.toLongOrNull() ?: return null
        return value.takeIf { it >= MIN_AMOUNT_CENTS }
    }

    companion object {
        const val ARG_TRANSACTION_ENTRY_ID = "transactionEntryId"
        const val MIN_REASON = 10
        const val MAX_REASON = 2000
        const val MIN_AMOUNT_CENTS = 1L
    }
}
