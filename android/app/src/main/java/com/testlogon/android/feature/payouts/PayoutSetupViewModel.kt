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
import com.testlogon.android.data.payouts.TinType
import com.testlogon.android.data.payouts.W9Submission
import com.testlogon.android.data.payouts.WithdrawGate
import com.testlogon.android.data.payouts.WithdrawGateEvaluator
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
 * AND-259 / PAY-13 / PAY-22 - payout-setup + PRE-WITHDRAWAL gate + ROUTABLE payout-method management.
 *
 * PAY-22: the authoritative withdraw gate is [WithdrawGate] - a withdrawal is BLOCKED until BOTH the
 * caller KYC is APPROVED (existing kyc_cases flow) AND a certified W-9 is on file (ui/payouts/tax-info).
 * The form is only shown/enabled when the gate is [WithdrawGate.Allowed]; otherwise the screen routes
 * the user to the KYC flow ([WithdrawGate.NeedsKyc]) or shows the W-9 form ([WithdrawGate.NeedsTaxInfo]).
 * The backend mirrors this (403 kyc_required / tax_info_required), so a gate race on submit re-resolves
 * the gate. The legacy AND-259 tier [gate] is still surfaced in state for compatibility but no longer
 * gates the withdraw form.
 */
@HiltViewModel
class PayoutSetupViewModel @Inject constructor(
    private val repo: PayoutSetupRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    /** PAY-13 - the destination type the add-method form is collecting. */
    enum class MethodChoice { BANK, PAYPAL, CONNECT }

    data class UiState(
        val isLoading: Boolean = true,
        val gate: PayoutGate = PayoutGate.Unknown,
        // PAY-22 - the authoritative pre-withdrawal gate (KYC approved + certified W-9 on file).
        val withdrawGate: WithdrawGate = WithdrawGate.Loading,
        val balance: PayoutBalance? = null,
        val recentPayouts: List<Payout> = emptyList(),
        val form: FormState = FormState(),
        val isSubmitting: Boolean = false,
        val evaluating: Boolean = false,
        // PAY-22 - the W-9 collection form (shown when the gate is NeedsTaxInfo).
        val w9Form: W9FormState = W9FormState(),
        val w9Submitting: Boolean = false,
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
        // PAY-52: the VERIFIED PAY-B destination the withdraw targets. A payout cannot be submitted
        // without one (mirrors request_payout's server-side verified-method guard).
        val selectedMethodId: String? = null,
        val notes: String = "",
        val amountError: UiText? = null,
        val canSubmit: Boolean = false,
    )

    /**
     * PAY-22 - the transient W-9 collection form. The raw [tin] lives ONLY here (never persisted); it is
     * sent once over TLS and cleared on success. The backend tokenizes+masks it to last-4.
     */
    data class W9FormState(
        val legalName: String = "",
        val tinType: TinType = TinType.SSN,
        val tin: String = "",
        val addressLine1: String = "",
        val city: String = "",
        val state: String = "",
        val zipCode: String = "",
        val certified: Boolean = false,
        val error: UiText? = null,
    ) {
        val tinDigits: String get() = tin.filter { it.isDigit() }

        /** Client-side gate for the W-9 submit button (server re-validates). SSN + EIN are both 9 digits. */
        val canSubmit: Boolean
            get() = legalName.isNotBlank() &&
                tinDigits.length == 9 &&
                addressLine1.isNotBlank() &&
                city.isNotBlank() &&
                state.trim().length == 2 &&
                zipCode.trim().length in 5..10 &&
                certified

        fun toSubmission(): W9Submission = W9Submission(
            legalName = legalName,
            tin = tin,
            tinType = tinType,
            addressLine1 = addressLine1,
            city = city,
            state = state,
            zipCode = zipCode,
            certified = certified,
        )
    }

    /** PAY-13 - the add-routable-method form. Bank number/routing are WRITE-ONLY (tokenized server-side). */
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

        /** PAY-13 - open a real Stripe Connect onboarding URL (only when keyed; mock self-completes). */
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
        _state.update {
            it.copy(isLoading = true, loadFailed = false, error = null, withdrawGate = WithdrawGate.Loading)
        }
        viewModelScope.launch {
            when (val result = repo.loadSetup()) {
                is ApiResult.Success -> {
                    val data = result.data
                    // Legacy tier gate (kept for compatibility; no longer gates the withdraw form).
                    val tierGate = PayoutGateEvaluator.evaluate(data.tierStatus)
                    _state.update {
                        it.copy(
                            isLoading = false,
                            gate = tierGate,
                            balance = data.balance,
                            recentPayouts = data.recentPayouts,
                            loadFailed = false,
                        )
                    }
                    // PAY-22 - resolve the authoritative KYC + W-9 gate.
                    resolveGate()
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

    // ---- PAY-22: pre-withdrawal gate (KYC + W-9) ----

    /** Re-resolve the KYC + W-9 gate (called on load, after a W-9 submit, and on KYC return). */
    fun refreshGate() {
        viewModelScope.launch { resolveGate() }
    }

    private suspend fun resolveGate() {
        when (val result = repo.loadWithdrawGate()) {
            is ApiResult.Success -> {
                val gate = WithdrawGateEvaluator.evaluate(result.data)
                _state.update { it.copy(withdrawGate = gate, form = it.form.recomputed(it.balance, gate)) }
            }
            else -> _state.update {
                it.copy(
                    withdrawGate = WithdrawGate.Unresolved,
                    form = it.form.recomputed(it.balance, WithdrawGate.Unresolved),
                )
            }
        }
    }

    // ---- PAY-22: W-9 collection form ----

    fun onW9FieldChanged(transform: (W9FormState) -> W9FormState) = _state.update {
        it.copy(w9Form = transform(it.w9Form).copy(error = null))
    }

    /** Submit the W-9. On success the raw TIN is cleared from memory and the gate is re-resolved. */
    fun submitW9() {
        val s = _state.value
        val form = s.w9Form
        if (!form.canSubmit || s.w9Submitting) return
        _state.update { it.copy(w9Submitting = true, error = null) }
        viewModelScope.launch {
            when (val result = repo.submitTaxInfo(form.toSubmission())) {
                is ApiResult.Success -> {
                    // Clear the raw TIN immediately; re-resolve the (now-satisfied) tax leg.
                    _state.update { it.copy(w9Submitting = false, w9Form = W9FormState()) }
                    _effects.send(Effect.ShowMessage(UiText.Res(R.string.payout_tax_saved)))
                    resolveGate()
                }
                else -> _state.update {
                    it.copy(
                        w9Submitting = false,
                        w9Form = it.w9Form.copy(error = errorMapper.map(result).message),
                    )
                }
            }
        }
    }

    // ---- PAY-13: routable payout methods ----

    /** Load the routable methods + Connect account status. Non-blocking (never fails the screen). */
    fun loadMethods() {
        _state.update { it.copy(methodsLoading = true) }
        viewModelScope.launch {
            val methodsResult = repo.loadMethods()
            val methods = (methodsResult as? ApiResult.Success)?.data.orEmpty()
            val connect = (repo.getConnect() as? ApiResult.Success)?.data
            _state.update { st ->
                // PAY-52: auto-select a verified destination for the withdraw form — the current
                // selection if still verified, else the default verified method, else the first.
                val verified = methods.filter { it.status.isVerified }
                val selected = st.form.selectedMethodId
                    ?.takeIf { id -> verified.any { it.methodId == id } }
                    ?: verified.firstOrNull { it.isDefault }?.methodId
                    ?: verified.firstOrNull()?.methodId
                val method = methods.firstOrNull { it.methodId == selected }?.type?.wire
                    ?: st.form.method
                st.copy(
                    methodsLoading = false,
                    methods = methods,
                    connect = connect,
                    form = st.form.copy(selectedMethodId = selected, method = method)
                        .recomputed(st.balance, st.withdrawGate),
                )
            }
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

    /** PAY-12 - verify a method so a payout may target it. */
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
     * PAY-11 - Stripe Connect onboarding. Creates (or reuses) the Connect account, requests an
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

    // ---- amount form ----

    fun onAmountChanged(text: String) = _state.update {
        it.copy(form = it.form.copy(amountText = text).recomputed(it.balance, it.withdrawGate))
    }

    /**
     * PAY-52: select the VERIFIED destination the withdraw targets. [methodId] is the PAY-B method id;
     * the free-string [method] is derived from that method's type (for display + as a server fallback).
     */
    fun onMethodSelected(methodId: String) = _state.update {
        val method = it.methods.firstOrNull { m -> m.methodId == methodId }?.type?.wire
            ?: it.form.method
        it.copy(form = it.form.copy(selectedMethodId = methodId, method = method).recomputed(it.balance, it.withdrawGate))
    }

    fun onNotesChanged(notes: String) = _state.update {
        it.copy(form = it.form.copy(notes = notes.take(MAX_NOTES)))
    }

    /** PAY-22 - route the user to the existing KYC verification flow. */
    fun onVerifyIdentity() {
        viewModelScope.launch { _effects.send(Effect.NavigateToKyc) }
    }

    /** Refresh the gate after returning from the KYC flow (KYC may now be approved). */
    fun onReturnedFromKyc() {
        if (_state.value.evaluating) return
        _state.update { it.copy(evaluating = true) }
        viewModelScope.launch {
            resolveGate()
            _state.update { it.copy(evaluating = false) }
        }
    }

    /**
     * PAY-52: submit a REAL payout request. Defensive gate + double-submit guards; a VERIFIED
     * destination is required. A backend gate race (403 kyc_required/tax_info_required) re-resolves the
     * gate; every other failure (insufficient balance, invalid/unverified method, duplicate-pending,
     * transport) surfaces the mapped message. On success the amount is cleared + the balance/methods are
     * reloaded so the shown available balance reflects the real debit.
     */
    fun submit() {
        val s = _state.value
        if (!s.withdrawGate.canWithdraw) return // defensive: never request when the gate is not open
        if (s.isSubmitting) return // double-submit guard
        val amount = s.form.parsedAmountCents()
        val methodId = s.form.selectedMethodId
        if (amount == null || methodId == null || !s.form.canSubmit) return // local validation blocks submit

        _state.update { it.copy(isSubmitting = true, error = null, lastCreatedPayoutId = null) }
        viewModelScope.launch {
            val outcome = repo.requestPayout(
                PayoutRequestDraft(
                    amountCents = amount,
                    method = s.form.method,
                    methodId = methodId,
                    notes = s.form.notes,
                ),
                currency = s.balance?.currency ?: "USD",
            )
            when (outcome) {
                is PayoutRequestOutcome.Created -> {
                    _state.update {
                        it.copy(
                            isSubmitting = false,
                            lastCreatedPayoutId = outcome.result.payoutId,
                            form = it.form.copy(amountText = "", notes = "", amountError = null, canSubmit = false),
                        )
                    }
                    // Reload the balance so the available/held figures reflect the just-made debit.
                    load()
                }
                is PayoutRequestOutcome.Error -> {
                    // A backend gate race (403 kyc_required / tax_info_required) -> re-resolve the gate.
                    val code = (outcome.result as? ApiResult.Failure)?.error?.code
                    if (code == KYC_REQUIRED || code == TAX_INFO_REQUIRED) {
                        _state.update { it.copy(isSubmitting = false) }
                        resolveGate()
                    } else {
                        _state.update {
                            it.copy(isSubmitting = false, error = errorMapper.map(outcome.result).message)
                        }
                    }
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

    private fun FormState.recomputed(balance: PayoutBalance?, gate: WithdrawGate): FormState {
        if (!gate.canWithdraw || balance == null) {
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
        // PAY-52: a verified destination must be chosen before the request can be submitted.
        return copy(amountError = error, canSubmit = error == null && selectedMethodId != null)
    }

    companion object {
        const val MAX_NOTES = 500
        const val KYC_REQUIRED = "kyc_required"
        const val TAX_INFO_REQUIRED = "tax_info_required"
    }
}
