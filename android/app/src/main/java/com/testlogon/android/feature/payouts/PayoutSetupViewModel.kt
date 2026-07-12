package com.testlogon.android.feature.payouts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.payouts.AddPayoutMethodInput
import com.testlogon.android.data.payouts.ConnectAccount
import com.testlogon.android.data.payouts.DEFAULT_PAYOUT_METHOD
import com.testlogon.android.data.payouts.Payout
import com.testlogon.android.data.payouts.PayoutBalance
import com.testlogon.android.data.payouts.PayoutGate
import com.testlogon.android.data.payouts.PayoutGateEvaluator
import com.testlogon.android.data.payouts.PayoutMethod
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
 * AND-259 / PAY-13 — payout-setup + KYC-gate + ROUTABLE payout-method management presentation logic.
 *
 * Loads balance + recent payouts + tier (fail-closed gate) AND the routable payout methods + Connect
 * account status. Derives a [PayoutGate], validates the amount form client-side, and submits via
 * [PayoutSetupRepository.requestPayout] (gated through the BillingAuthorizer stub — no real payout).
 *
 * PAY-13: the user can ADD a routable destination (bank routing+account -> tokenized server-side, only
 * last-4 kept; PayPal email; Stripe Connect via an onboarding button), set a default, see each method's
 * verification STATUS, and trigger the PAY-12 verification seam ("Verify"). A payout can only target a
 * VERIFIED method — the backend request_payout enforces this; the UI surfaces the status honestly.
 */
@HiltViewModel
class PayoutSetupViewModel @Inject constructor(
    private val repo: PayoutSetupRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    /** PAY-13 — the destination type the add-method form is collecting. */
    enum class MethodChoice { BANK, PAYPAL, CONNECT }

    data class UiState(
        val isLoading: Boolean = true,
        val gate: PayoutGate = PayoutGate.Unknown,
        val balance: PayoutBalance? = null,
        val recentPayouts: List<Payout> = emptyList(),
        val form: FormState = FormState(),
        val isSubmitting: Boolean = false,
        val evaluating: Boolean = false,
        // ---- PAY-13: routable methods ----
        val methods: List<PayoutMethod> = emptyList(),
        val methodsLoading: Boolean = false,
        val connect: ConnectAccount? = null,
        /** Non-null when the add-method form is expanded. */
        val addForm: AddMethodForm? = null,
        val addSubmitting: Boolean = false,
        /** The method currently running a verify/default/delete action (spinner + disable). */
        val busyMethodId: String? = null,
        val connectBusy: Boolean = false,
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
        val amountError: UiText? = null,
        val canSubmit: Boolean = false,
    )

    /** PAY-13 — the add-routable-method form. Bank number/routing are WRITE-ONLY (tokenized server-side). */
    data class AddMethodForm(
        val choice: MethodChoice = MethodChoice.BANK,
        val routingNumber: String = "",
        val accountNumber: String = "",
        val wire: Boolean = false,
        val paypalEmail: String = "",
        val nickname: String = "",
        val setAsDefault: Boolean = false,
    ) {
        /** Client-side gate for the submit button (server re-validates). */
        val canSubmit: Boolean
            get() = when (choice) {
                MethodChoice.BANK -> routingNumber.length in 4..9 && accountNumber.length in 4..17
                MethodChoice.PAYPAL -> paypalEmail.contains("@") && paypalEmail.length in 3..254
                // Connect is added via the onboarding button, not this Submit.
                MethodChoice.CONNECT -> false
            }

        fun toInput(): AddPayoutMethodInput? = when (choice) {
            MethodChoice.BANK -> AddPayoutMethodInput.Bank(
                routingNumber = routingNumber,
                accountNumber = accountNumber,
                wire = wire,
                nickname = nickname,
                setAsDefault = setAsDefault,
            )
            MethodChoice.PAYPAL -> AddPayoutMethodInput.Paypal(
                email = paypalEmail,
                nickname = nickname,
                setAsDefault = setAsDefault,
            )
            MethodChoice.CONNECT -> null
        }
    }

    /** One-shot effects (Channel-backed so rotation cannot replay them). */
    sealed interface Effect {
        data object NavigateToKyc : Effect
        data class ShowMessage(val text: UiText) : Effect

        /** PAY-13 — open a real Stripe Connect onboarding URL (only when keyed; mock self-completes). */
        data class OpenUrl(val url: String) : Effect
    }

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _effects = Channel<Effect>(Channel.BUFFERED)
    val effects: Flow<Effect> = _effects.receiveAsFlow()

    init {
        load()
        loadMethods()
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

    fun retry() {
        load()
        loadMethods()
    }

    // ---- PAY-13: routable payout methods ----

    /** Load the routable methods + Connect account status. Non-blocking (never fails the screen). */
    fun loadMethods() {
        _state.update { it.copy(methodsLoading = true) }
        viewModelScope.launch {
            val methodsResult = repo.loadMethods()
            val methods = (methodsResult as? ApiResult.Success)?.data.orEmpty()
            val connect = (repo.getConnect() as? ApiResult.Success)?.data
            _state.update { it.copy(methodsLoading = false, methods = methods, connect = connect) }
            if (methodsResult !is ApiResult.Success) {
                _state.update { it.copy(error = errorMapper.map(methodsResult).message) }
            }
        }
    }

    fun onAddMethodClicked() = _state.update {
        it.copy(addForm = it.addForm ?: AddMethodForm())
    }

    fun onCancelAddMethod() = _state.update { it.copy(addForm = null) }

    fun onAddChoiceSelected(choice: MethodChoice) = _state.update {
        it.copy(addForm = (it.addForm ?: AddMethodForm()).copy(choice = choice))
    }

    fun onAddFieldChanged(transform: (AddMethodForm) -> AddMethodForm) = _state.update {
        it.copy(addForm = (it.addForm ?: AddMethodForm()).let(transform))
    }

    /** Submit the bank/PayPal add-method form. Bank number/routing are tokenized server-side (SEC-004). */
    fun submitAddMethod() {
        val s = _state.value
        val form = s.addForm ?: return
        val input = form.toInput() ?: return
        if (!form.canSubmit || s.addSubmitting) return
        _state.update { it.copy(addSubmitting = true, error = null) }
        viewModelScope.launch {
            when (val result = repo.addMethod(input)) {
                is ApiResult.Success -> {
                    _state.update { it.copy(addSubmitting = false, addForm = null) }
                    _effects.send(Effect.ShowMessage(UiText.Res(R.string.payout_method_added)))
                    loadMethods()
                }
                else -> _state.update {
                    it.copy(addSubmitting = false, error = errorMapper.map(result).message)
                }
            }
        }
    }

    /** PAY-12 — verify a method so a payout may target it. */
    fun verifyMethod(methodId: String) {
        if (_state.value.busyMethodId != null) return
        _state.update { it.copy(busyMethodId = methodId, error = null) }
        viewModelScope.launch {
            when (val result = repo.verifyMethod(methodId)) {
                is ApiResult.Success -> {
                    _state.update { it.copy(busyMethodId = null, methods = it.methods.upsert(result.data)) }
                    _effects.send(Effect.ShowMessage(UiText.Res(R.string.payout_method_verify_done)))
                }
                else -> _state.update {
                    it.copy(busyMethodId = null, error = errorMapper.map(result).message)
                }
            }
        }
    }

    fun setDefaultMethod(methodId: String) {
        if (_state.value.busyMethodId != null) return
        _state.update { it.copy(busyMethodId = methodId, error = null) }
        viewModelScope.launch {
            when (val result = repo.setDefaultMethod(methodId)) {
                is ApiResult.Success -> {
                    _state.update { it.copy(busyMethodId = null) }
                    loadMethods()
                }
                else -> _state.update {
                    it.copy(busyMethodId = null, error = errorMapper.map(result).message)
                }
            }
        }
    }

    fun deleteMethod(methodId: String) {
        if (_state.value.busyMethodId != null) return
        _state.update { it.copy(busyMethodId = methodId, error = null) }
        viewModelScope.launch {
            when (val result = repo.deleteMethod(methodId)) {
                is ApiResult.Success -> {
                    _state.update {
                        it.copy(
                            busyMethodId = null,
                            methods = it.methods.filterNot { m -> m.methodId == methodId },
                        )
                    }
                }
                else -> _state.update {
                    it.copy(busyMethodId = null, error = errorMapper.map(result).message)
                }
            }
        }
    }

    /**
     * PAY-11 — Stripe Connect onboarding. Creates (or reuses) the Connect account, requests an
     * onboarding link, opens the real URL when keyed, then registers a routable stripe_connect method.
     * Under the mock the onboarding self-completes and the method is immediately verifiable.
     */
    fun startConnectOnboarding(setAsDefault: Boolean) {
        if (_state.value.connectBusy) return
        _state.update { it.copy(connectBusy = true, error = null) }
        viewModelScope.launch {
            val account = repo.createConnectAccount()
            if (account !is ApiResult.Success) {
                _state.update { it.copy(connectBusy = false, error = errorMapper.map(account).message) }
                return@launch
            }
            when (val link = repo.createConnectOnboardingLink()) {
                is ApiResult.Success -> {
                    if (link.data.needsBrowser) {
                        _effects.send(Effect.OpenUrl(link.data.onboardingUrl))
                    }
                    // Register a routable stripe_connect method targeting this Connect account.
                    val add = repo.addMethod(
                        AddPayoutMethodInput.Connect(
                            connectAccountId = account.data.connectAccountId,
                            nickname = "Stripe Connect",
                            setAsDefault = setAsDefault,
                        ),
                    )
                    _state.update { it.copy(connectBusy = false, addForm = null) }
                    if (add is ApiResult.Success) {
                        _effects.send(Effect.ShowMessage(UiText.Res(R.string.payout_method_added)))
                    } else {
                        _state.update { it.copy(error = errorMapper.map(add).message) }
                    }
                    loadMethods()
                }
                else -> _state.update {
                    it.copy(connectBusy = false, error = errorMapper.map(link).message)
                }
            }
        }
    }

    private fun List<PayoutMethod>.upsert(updated: PayoutMethod): List<PayoutMethod> {
        val idx = indexOfFirst { it.methodId == updated.methodId }
        return if (idx >= 0) toMutableList().also { it[idx] = updated } else this + updated
    }

    // ---- amount form (unchanged) ----

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
