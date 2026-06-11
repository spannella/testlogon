package com.testlogon.android.feature.payouts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.payouts.DEFAULT_PAYOUT_METHOD
import com.testlogon.android.data.payouts.Payout
import com.testlogon.android.data.payouts.PayoutBalance
import com.testlogon.android.data.payouts.PayoutGate
import com.testlogon.android.data.payouts.PayoutGateEvaluator
import com.testlogon.android.data.payouts.PayoutRequestDraft
import com.testlogon.android.data.payouts.PayoutRequestOutcome
import com.testlogon.android.data.payouts.PayoutSetupRepository
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
 * AND-259 — payout-setup + KYC-gate presentation logic.
 *
 * Loads balance + recent payouts + tier in parallel (fail-closed gate when tier is unavailable),
 * derives a [PayoutGate], validates the amount form client-side against
 * minimum_payout_cents <= amount <= available_cents, and submits via [PayoutSetupRepository.requestPayout]
 * which is GATED through the BillingAuthorizer stub (so no real payout is ever executed —
 * [PayoutRequestOutcome.NotConfigured] is surfaced as "payouts unavailable").
 *
 * The "Verify identity" action navigates to the KYC route (screen-owned); on return [onReturnedFromKyc]
 * calls evaluate() and re-derives the gate. The KYC vendor flow itself is the FLAGGED [com.testlogon.
 * android.data.payouts.KycVerifier] stub and is never launched here.
 */
@HiltViewModel
class PayoutSetupViewModel @Inject constructor(
    private val repo: PayoutSetupRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    data class UiState(
        val isLoading: Boolean = true,
        val gate: PayoutGate = PayoutGate.Unknown,
        val balance: PayoutBalance? = null,
        val recentPayouts: List<Payout> = emptyList(),
        val form: FormState = FormState(),
        val isSubmitting: Boolean = false,
        val evaluating: Boolean = false,
        /** Set on a successful create; the screen shows a confirmation referencing it. */
        val lastCreatedPayoutId: String? = null,
        /** A retryable, non-blocking error message (form values are preserved). */
        val error: UiText? = null,
        /** True when load failed entirely (full-screen retry). */
        val loadFailed: Boolean = false,
    )

    data class FormState(
        val amountText: String = "",
        val method: String = DEFAULT_PAYOUT_METHOD,
        val notes: String = "",
        /** Inline amount-field error (string res), or null. */
        val amountError: UiText? = null,
        val canSubmit: Boolean = false,
    )

    /** One-shot effects (Channel-backed so rotation cannot replay them). */
    sealed interface Effect {
        data object NavigateToKyc : Effect
        data class ShowMessage(val text: UiText) : Effect
    }

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _effects = Channel<Effect>(Channel.BUFFERED)
    val effects: Flow<Effect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        _state.update { it.copy(isLoading = true, loadFailed = false, error = null) }
        viewModelScope.launch {
            when (val result = repo.loadSetup()) {
                is ApiResult.Success -> {
                    val data = result.data
                    val gate = PayoutGateEvaluator.evaluate(data.tierStatus)
                    _state.update {
                        it.copy(
                            isLoading = false,
                            gate = gate,
                            balance = data.balance,
                            recentPayouts = data.recentPayouts,
                            form = it.form.recomputed(data.balance, gate),
                            loadFailed = false,
                        )
                    }
                }
                else -> _state.update {
                    it.copy(isLoading = false, loadFailed = true, error = errorMapper.map(result).message)
                }
            }
        }
    }

    fun retry() = load()

    fun onAmountChanged(text: String) = _state.update {
        it.copy(form = it.form.copy(amountText = text).recomputed(it.balance, it.gate))
    }

    fun onMethodSelected(method: String) = _state.update {
        it.copy(form = it.form.copy(method = method))
    }

    fun onNotesChanged(notes: String) = _state.update {
        it.copy(form = it.form.copy(notes = notes.take(MAX_NOTES)))
    }

    fun onVerifyIdentity() {
        viewModelScope.launch { _effects.send(Effect.NavigateToKyc) }
    }

    /** FR-5: refresh tier after returning from the (scaffolded) KYC flow and re-derive the gate. */
    fun onReturnedFromKyc() {
        if (_state.value.evaluating) return
        _state.update { it.copy(evaluating = true) }
        viewModelScope.launch {
            when (val result = repo.refreshTier()) {
                is ApiResult.Success -> {
                    val gate = PayoutGateEvaluator.evaluate(result.data)
                    _state.update {
                        it.copy(evaluating = false, gate = gate, form = it.form.recomputed(it.balance, gate))
                    }
                }
                else -> _state.update {
                    it.copy(evaluating = false, error = errorMapper.map(result).message)
                }
            }
        }
    }

    /** FR-3/FR-8: submit a payout request. Defensive gate guard + double-submit guard. */
    fun submit() {
        val s = _state.value
        if (s.gate !is PayoutGate.Allowed) return // defensive: never request when not allowed
        if (s.isSubmitting) return // double-submit guard
        val amount = s.form.parsedAmountCents()
        if (amount == null || !s.form.canSubmit) return // local validation blocks submit

        _state.update { it.copy(isSubmitting = true, error = null, lastCreatedPayoutId = null) }
        viewModelScope.launch {
            val outcome = repo.requestPayout(
                PayoutRequestDraft(amountCents = amount, method = s.form.method, notes = s.form.notes),
                currency = s.balance?.currency ?: "USD",
            )
            when (outcome) {
                is PayoutRequestOutcome.Created -> _state.update {
                    it.copy(isSubmitting = false, lastCreatedPayoutId = outcome.result.payoutId)
                }
                is PayoutRequestOutcome.Error -> _state.update {
                    it.copy(isSubmitting = false, error = errorMapper.map(outcome.result).message)
                }
                PayoutRequestOutcome.Cancelled -> _state.update { it.copy(isSubmitting = false) }
                is PayoutRequestOutcome.Declined -> _state.update {
                    it.copy(isSubmitting = false, error = UiText.Res(R.string.payout_request_declined))
                }
                // STOP-AND-FLAG: BillingAuthorizer stub -> no real payout was executed.
                PayoutRequestOutcome.NotConfigured -> _state.update {
                    it.copy(isSubmitting = false, error = UiText.Res(R.string.payout_request_unavailable))
                }
            }
        }
    }

    fun dismissError() = _state.update { it.copy(error = null) }

    fun consumeConfirmation() = _state.update { it.copy(lastCreatedPayoutId = null) }

    // ---- form helpers ----

    private fun FormState.parsedAmountCents(): Long? {
        val major = amountText.trim().replace(",", "").toDoubleOrNull() ?: return null
        if (major <= 0.0) return null
        return Math.round(major * 100.0)
    }

    private fun FormState.recomputed(balance: PayoutBalance?, gate: PayoutGate): FormState {
        if (gate !is PayoutGate.Allowed || balance == null) {
            return copy(amountError = null, canSubmit = false)
        }
        if (amountText.isBlank()) return copy(amountError = null, canSubmit = false)
        val cents = parsedAmountCents()
        val error: UiText? = when {
            cents == null -> UiText.Res(R.string.payout_amount_invalid)
            cents < balance.minimumPayoutCents -> UiText.Res(R.string.payout_amount_below_min)
            cents > balance.availableCents -> UiText.Res(R.string.payout_amount_above_available)
            else -> null
        }
        return copy(amountError = error, canSubmit = error == null)
    }

    companion object {
        const val MAX_NOTES = 500
    }
}
