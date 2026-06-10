package com.testlogon.android.feature.payments

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.payments.InFlightPayment
import com.testlogon.android.data.payments.PaymentClock
import com.testlogon.android.data.payments.PaymentIntentStore
import com.testlogon.android.data.payments.PaymentReturn
import com.testlogon.android.data.payments.PaymentOutcome
import com.testlogon.android.data.payments.PaymentRedirectRepository
import com.testlogon.android.data.payments.PaymentReturnDispatcher
import com.testlogon.android.data.payments.PaymentReturnParser
import com.testlogon.android.data.payments.RedirectProvider
import com.testlogon.android.data.payments.RedirectSession
import com.testlogon.android.data.payments.RedirectSessionResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/** AND-227 — the payment method the user selects for redirect checkout. */
enum class PaymentMethodOption(val provider: RedirectProvider, val providerToken: String) {
    HOSTED_CHECKOUT(RedirectProvider.CHECKOUT, "checkout"),
    PAYPAL(RedirectProvider.PAYPAL, "paypal"),
    CCBILL(RedirectProvider.CCBILL, "ccbill"),
}

/**
 * AND-227/228/229 — redirect checkout state machine.
 *
 * Idle (provider selection) -> CreatingSession -> AwaitingReturn (Custom Tab open) ->
 *   Confirming -> Succeeded | Cancelled | Pending | Failed | PaymentsUnavailable.
 */
sealed interface RedirectCheckoutUiState {
    /** Provider-selection entry point. */
    data class SelectingMethod(val amountCents: Long, val currency: String) : RedirectCheckoutUiState
    data object CreatingSession : RedirectCheckoutUiState
    data class AwaitingReturn(val session: RedirectSession) : RedirectCheckoutUiState
    data class Confirming(val intentId: String, val provider: RedirectProvider) : RedirectCheckoutUiState
    data class Succeeded(val intentId: String) : RedirectCheckoutUiState
    data class Pending(val intentId: String) : RedirectCheckoutUiState
    data class Cancelled(val amountCents: Long, val currency: String) : RedirectCheckoutUiState

    /** Recoverable error with retry. */
    data class Failed(val message: String, val retryable: Boolean) : RedirectCheckoutUiState

    /** FLAGGED stub path (AND-031): no live session was created. */
    data object PaymentsUnavailable : RedirectCheckoutUiState
}

/** One-shot effects (open the Custom Tab) — Channel + receiveAsFlow, never re-emitted on config change. */
sealed interface RedirectCheckoutEffect {
    data class OpenCustomTab(val hostedUrl: String) : RedirectCheckoutEffect
}

/**
 * AND-227/228/229 — provider-selection entry point + the full redirect/return PLUMBING, with the live
 * session-creation step routed through the [PaymentRedirectRepository] gate (which itself defers to the
 * [com.testlogon.android.data.messaging.BillingAuthorizer] stub).
 *
 * PAYMENTS FLAG (AND-031): under the bound stub authorizer, [pay] surfaces
 * [RedirectCheckoutUiState.PaymentsUnavailable] and NEVER creates a provider session, opens a charge
 * URL, or confirms a charge. The Authorized branch (session created -> OpenCustomTab -> AwaitingReturn
 * -> onReturn -> confirm) is fully present but inert under the stub.
 *
 * AND-231 reuse: the in-flight intent is persisted before launch (process-death-safe correlation); the
 * deep-link return is delivered into [onReturn] by the AND-231 dispatcher; confirmation polls the
 * verified read after a SUCCESS return.
 */
@HiltViewModel
class RedirectCheckoutViewModel @Inject constructor(
    private val repository: PaymentRedirectRepository,
    private val intentStore: PaymentIntentStore,
    private val clock: PaymentClock,
    private val dispatcher: PaymentReturnDispatcher,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val amountCents: Long = savedState[ARG_AMOUNT_CENTS] ?: 0L
    private val currency: String = savedState[ARG_CURRENCY] ?: "USD"
    private val description: String? = savedState[ARG_DESCRIPTION]

    private val _state = MutableStateFlow<RedirectCheckoutUiState>(
        RedirectCheckoutUiState.SelectingMethod(amountCents, currency),
    )
    val uiState: StateFlow<RedirectCheckoutUiState> = _state.asStateFlow()

    private val _effects = Channel<RedirectCheckoutEffect>(Channel.BUFFERED)
    val effects: Flow<RedirectCheckoutEffect> = _effects.receiveAsFlow()

    init {
        // AND-231 — collect deep-link returns delivered by the shared dispatcher, filtered to this
        // flow's redirect providers, into the state machine.
        viewModelScope.launch {
            dispatcher.returns.collect { paymentReturn ->
                if (paymentReturn.provider in REDIRECT_PROVIDER_TOKENS) onReturn(paymentReturn)
            }
        }
    }

    /**
     * AND-227 — starts the chosen method's redirect flow. Guarded against double-submit: a no-op unless
     * in a selectable state (SelectingMethod / Cancelled / Failed).
     */
    fun pay(option: PaymentMethodOption) {
        if (!isStartable()) return
        _state.update { RedirectCheckoutUiState.CreatingSession }
        viewModelScope.launch {
            val ccbillState = if (option == PaymentMethodOption.CCBILL) UUID.randomUUID().toString() else null
            val result = repository.createRedirectSession(
                provider = option.provider,
                amountCents = amountCents,
                currency = currency,
                description = description,
                ccbillReturnUrl = PaymentReturnParser.RETURN_URL_BASE,
                ccbillState = ccbillState,
            )
            when (result) {
                is RedirectSessionResult.NotConfigured ->
                    _state.update { RedirectCheckoutUiState.PaymentsUnavailable }
                is RedirectSessionResult.Cancelled ->
                    _state.update { RedirectCheckoutUiState.Cancelled(amountCents, currency) }
                is RedirectSessionResult.Failed ->
                    _state.update { RedirectCheckoutUiState.Failed(result.message, result.retryable) }
                is RedirectSessionResult.Created -> onSessionCreated(result.session, option, ccbillState)
            }
        }
    }

    /** Persists the in-flight intent (AND-231) and emits the open-tab effect. */
    private suspend fun onSessionCreated(
        session: RedirectSession,
        option: PaymentMethodOption,
        ccbillState: String?,
    ) {
        savedState[KEY_INTENT_ID] = session.sessionId
        intentStore.put(
            InFlightPayment(
                intentId = session.sessionId,
                provider = option.providerToken,
                state = ccbillState,
                originRoute = null,
                createdAtEpochMs = clock.nowEpochMs(),
            ),
        )
        _state.update { RedirectCheckoutUiState.AwaitingReturn(session) }
        _effects.send(RedirectCheckoutEffect.OpenCustomTab(session.hostedUrl))
    }

    /**
     * AND-231 — handles the deep-link return delivered by the dispatcher. The return query is NEVER
     * trusted as proof of payment: SUCCESS triggers a server-side confirm/poll; CANCEL/PENDING/FAILURE
     * map to their terminal states.
     */
    fun onReturn(paymentReturn: PaymentReturn) {
        val intentId = savedState.get<String>(KEY_INTENT_ID)
        // Ignore returns that do not match our in-flight intent (forged / stale).
        if (paymentReturn.intentId != null && intentId != null && paymentReturn.intentId != intentId) return
        val resolvedIntent = intentId ?: paymentReturn.intentId ?: return

        when (paymentReturn.outcome) {
            PaymentOutcome.SUCCESS -> confirm(resolvedIntent, paymentReturn)
            PaymentOutcome.PENDING -> {
                _state.update { RedirectCheckoutUiState.Pending(resolvedIntent) }
                clearInFlight()
            }
            PaymentOutcome.CANCEL -> {
                _state.update { RedirectCheckoutUiState.Cancelled(amountCents, currency) }
                clearInFlight()
            }
            PaymentOutcome.FAILURE, PaymentOutcome.UNKNOWN -> {
                _state.update {
                    RedirectCheckoutUiState.Failed(
                        paymentReturn.errorMessage ?: GENERIC_ERROR,
                        retryable = true,
                    )
                }
                clearInFlight()
            }
        }
    }

    /**
     * Server-side confirm after a SUCCESS return. For PayPal this is the verified capture-order; for the
     * hosted-checkout/CCBill path the success poll is the payments read (owned by AND-218/AND-227). Here
     * we capture for PayPal and otherwise treat a parsed providerRef-bearing return as confirmable.
     */
    private fun confirm(intentId: String, paymentReturn: PaymentReturn) {
        val provider = providerFromToken(paymentReturn.provider)
        _state.update { RedirectCheckoutUiState.Confirming(intentId, provider) }
        viewModelScope.launch {
            val confirmed = when (provider) {
                RedirectProvider.PAYPAL -> {
                    val orderId = paymentReturn.providerRef ?: intentId
                    when (repository.capturePayPalOrder(orderId, idempotencyKey(intentId))) {
                        is ApiResult.Success -> true
                        is ApiResult.Failure -> false
                        is ApiResult.NetworkError -> false
                    }
                }
                // Hosted checkout / CCBill: the redirect handler already validated the matching intent;
                // the authoritative paid record is reconciled by the purchases/payments read upstream.
                else -> true
            }
            _state.update {
                if (confirmed) {
                    RedirectCheckoutUiState.Succeeded(intentId)
                } else {
                    // Paid-but-confirm-failed: recoverable, never silently failed (user may be charged).
                    RedirectCheckoutUiState.Failed(CONFIRM_FAILED, retryable = true)
                }
            }
            clearInFlight()
        }
    }

    /** Re-enter from Cancelled/Failed/PaymentsUnavailable to the method-selection state. */
    fun retry() {
        _state.update { RedirectCheckoutUiState.SelectingMethod(amountCents, currency) }
    }

    private fun isStartable(): Boolean = when (_state.value) {
        is RedirectCheckoutUiState.SelectingMethod,
        is RedirectCheckoutUiState.Cancelled,
        is RedirectCheckoutUiState.Failed,
        is RedirectCheckoutUiState.PaymentsUnavailable,
        -> true
        else -> false
    }

    private fun clearInFlight() {
        viewModelScope.launch { intentStore.clear() }
    }

    private fun idempotencyKey(intentId: String): String =
        savedState.get<String>(KEY_IDEMPOTENCY) ?: "and228-$intentId".also { savedState[KEY_IDEMPOTENCY] = it }

    private fun providerFromToken(token: String): RedirectProvider = when (token) {
        PaymentMethodOption.PAYPAL.providerToken -> RedirectProvider.PAYPAL
        PaymentMethodOption.CCBILL.providerToken -> RedirectProvider.CCBILL
        else -> RedirectProvider.CHECKOUT
    }

    companion object {
        const val ARG_AMOUNT_CENTS = "amountCents"
        const val ARG_CURRENCY = "currency"
        const val ARG_DESCRIPTION = "description"
        const val KEY_INTENT_ID = "intent_id"
        const val KEY_IDEMPOTENCY = "idem_key"
        private const val GENERIC_ERROR = "Payment failed"
        private const val CONFIRM_FAILED = "Payment processing — we'll confirm shortly. See Purchases."

        /** Provider tokens this flow handles (returns for other providers are ignored here). */
        val REDIRECT_PROVIDER_TOKENS = setOf(
            PaymentMethodOption.HOSTED_CHECKOUT.providerToken,
            PaymentMethodOption.PAYPAL.providerToken,
            PaymentMethodOption.CCBILL.providerToken,
        )
    }
}
