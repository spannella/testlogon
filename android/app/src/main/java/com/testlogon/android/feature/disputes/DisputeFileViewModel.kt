package com.testlogon.android.feature.disputes

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.disputes.DisputesRepository
import com.testlogon.android.data.disputes.FileDisputeInput
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
 * AND-245 — file (open) a dispute form state. `reason` is free text (>= 10 chars, mirroring the web file
 * form); `amount` is a required positive integer cents (`DisputeFileIn.amount_cents`).
 */
data class DisputeFileUiState(
    val reasonText: String = "",
    val amountText: String = "",
    val reasonError: UiText? = null,
    val amountError: UiText? = null,
    val submitEnabled: Boolean = false,
    val isSubmitting: Boolean = false,
)

/** AND-245 — one-shot file-dispute effects (Channel-backed so rotation cannot replay them). */
sealed interface DisputeFileEvent {
    data class Success(val disputeId: String) : DisputeFileEvent
    data class Failure(val message: UiText) : DisputeFileEvent
}

/**
 * AND-245 — file-dispute presentation logic. Validates client-side (reason >= 10 chars; amount a positive
 * integer cents) and POSTs `/ui/billing/disputes` (DisputeFileIn). The in-flight guard ([submit] is a
 * no-op while submitting) prevents duplicate POSTs. Failures map through [BillingErrorMapper] (AND-232).
 */
@HiltViewModel
class DisputeFileViewModel @Inject constructor(
    private val repository: DisputesRepository,
    private val errorMapper: BillingErrorMapper,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val transactionEntryId: String = checkNotNull(savedStateHandle[ARG_TRANSACTION_ENTRY_ID]) {
        "DisputeFileViewModel requires a '$ARG_TRANSACTION_ENTRY_ID' nav argument"
    }

    private val _uiState = MutableStateFlow(DisputeFileUiState())
    val uiState: StateFlow<DisputeFileUiState> = _uiState.asStateFlow()

    private val _events = Channel<DisputeFileEvent>(Channel.BUFFERED)
    val events: Flow<DisputeFileEvent> = _events.receiveAsFlow()

    fun onReasonChange(value: String) = _uiState.update { recompute(it.copy(reasonText = value)) }

    fun onAmountChange(value: String) = _uiState.update { recompute(it.copy(amountText = value)) }

    /** File the dispute. No-op while already submitting (in-flight duplicate guard). */
    fun submit() {
        val state = _uiState.value
        if (state.isSubmitting) return
        val amountCents = parseAmountCents(state.amountText)
        if (state.reasonText.trim().length < MIN_REASON || amountCents == null) {
            _uiState.update { recompute(it) }
            return
        }
        _uiState.update { it.copy(isSubmitting = true, submitEnabled = false) }
        viewModelScope.launch {
            val input = FileDisputeInput(
                transactionEntryId = transactionEntryId,
                amountCents = amountCents,
                currency = null,
                reason = state.reasonText.trim(),
            )
            when (val result = repository.fileDispute(input)) {
                is ApiResult.Success -> {
                    _events.send(DisputeFileEvent.Success(result.data.id))
                    _uiState.update { it.copy(isSubmitting = false) }
                }
                else -> {
                    _events.send(DisputeFileEvent.Failure(errorMapper.map(result).message))
                    _uiState.update { recompute(it.copy(isSubmitting = false)) }
                }
            }
        }
    }

    private fun recompute(state: DisputeFileUiState): DisputeFileUiState {
        val reason = state.reasonText.trim()
        val reasonError: UiText? = when {
            reason.isEmpty() -> null
            reason.length < MIN_REASON -> UiText.Res(R.string.disputes_error_reason_too_short)
            else -> null
        }
        val amountRaw = state.amountText.trim()
        val amountError: UiText? = when {
            amountRaw.isEmpty() -> null
            parseAmountCents(amountRaw) == null -> UiText.Res(R.string.disputes_error_amount_invalid)
            else -> null
        }
        val valid = reason.length >= MIN_REASON && parseAmountCents(amountRaw) != null
        return state.copy(
            reasonError = reasonError,
            amountError = amountError,
            submitEnabled = valid && !state.isSubmitting,
        )
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
        const val MIN_AMOUNT_CENTS = 1L
    }
}
