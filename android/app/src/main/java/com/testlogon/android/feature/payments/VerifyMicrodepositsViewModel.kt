package com.testlogon.android.feature.payments

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.payments.PaymentRedirectRepository
import com.testlogon.android.data.payments.UsBankVerificationState
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
 * AND-230 — US bank micro-deposit verification UI state. Two cent amounts (1..99 each). The verify POST
 * is the VERIFIED contract (unlike the gated session-creation flows) — it confirms an already-initiated
 * bank setup, so it is NOT routed through the BillingAuthorizer gate. It never sees a card/PAN/bank
 * number, only the user-known deposit amounts.
 */
data class VerifyMicrodepositsUiState(
    val setupIntentId: String,
    val firstCents: String = "",
    val secondCents: String = "",
    val isSubmitting: Boolean = false,
    val error: String? = null,
    val verified: Boolean = false,
) {
    val canSubmit: Boolean
        get() = !isSubmitting && !verified && firstCents.isValidCent() && secondCents.isValidCent()
}

private fun String.isValidCent(): Boolean = toIntOrNull()?.let { it in 1..99 } == true

/** AND-230 — one-shot result so the caller (payment-methods screen) can refresh after success. */
sealed interface VerifyMicrodepositsEvent {
    data class Verified(val setupIntentId: String) : VerifyMicrodepositsEvent
}

@HiltViewModel
class VerifyMicrodepositsViewModel @Inject constructor(
    private val repository: PaymentRedirectRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val setupIntentId: String = savedState[ARG_SETUP_INTENT_ID] ?: ""

    private val _state = MutableStateFlow(VerifyMicrodepositsUiState(setupIntentId = setupIntentId))
    val uiState: StateFlow<VerifyMicrodepositsUiState> = _state.asStateFlow()

    private val _events = Channel<VerifyMicrodepositsEvent>(Channel.BUFFERED)
    val events: Flow<VerifyMicrodepositsEvent> = _events.receiveAsFlow()

    fun onFirstChange(value: String) = _state.update { it.copy(firstCents = sanitize(value), error = null) }

    fun onSecondChange(value: String) = _state.update { it.copy(secondCents = sanitize(value), error = null) }

    fun dismissError() = _state.update { it.copy(error = null) }

    /** Submits the two amounts. Guarded: a no-op unless [VerifyMicrodepositsUiState.canSubmit]. */
    fun submit() {
        val current = _state.value
        if (!current.canSubmit) return
        val first = current.firstCents.toInt()
        val second = current.secondCents.toInt()
        _state.update { it.copy(isSubmitting = true, error = null) }
        viewModelScope.launch {
            when (val result = repository.verifyMicrodeposits(setupIntentId, listOf(first, second))) {
                is ApiResult.Success -> {
                    if (result.data.state == UsBankVerificationState.VERIFIED) {
                        _state.update { it.copy(isSubmitting = false, verified = true) }
                        _events.send(VerifyMicrodepositsEvent.Verified(setupIntentId))
                    } else {
                        // 200 with an unknown status — treat as a generic retryable error, form usable.
                        _state.update { it.copy(isSubmitting = false, error = GENERIC_ERROR) }
                    }
                }
                is ApiResult.Failure ->
                    _state.update { it.copy(isSubmitting = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _state.update { it.copy(isSubmitting = false, error = OFFLINE) }
            }
        }
    }

    /** Digit-only, max 2 chars (cents 1..99). */
    private fun sanitize(value: String): String = value.filter { it.isDigit() }.take(2)

    companion object {
        const val ARG_SETUP_INTENT_ID = "sid"
        private const val OFFLINE = "Couldn't reach the server"
        private const val GENERIC_ERROR = "Couldn't verify those amounts. Please try again."
    }
}
