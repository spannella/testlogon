package com.testlogon.android.feature.checkout

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.checkout.CheckoutRepository
import com.testlogon.android.data.checkout.CheckoutSession
import com.testlogon.android.data.checkout.CheckoutSessionRequest
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
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

/** AND-213 — order-review screen state. */
sealed interface OrderReviewUiState {
    data object Loading : OrderReviewUiState
    data class Ready(val session: CheckoutSession) : OrderReviewUiState
    data object EmptyCart : OrderReviewUiState
    data class Error(val message: String, val retryable: Boolean) : OrderReviewUiState
}

/**
 * AND-213 / AND-031 — the payment-attempt outcome surfaced from "Place order".
 *
 * STOP-AND-FLAG (payments, AND-031): the real charge needs a payment_method_id from a payment-method
 * picker that does not exist yet. [BillingAuthorizer] is the stub that returns NotConfigured and NEVER
 * fakes a charge or calls a charge endpoint, so "Place order" surfaces PaymentsUnavailable.
 */
sealed interface CheckoutEvent {
    data object PaymentsUnavailable : CheckoutEvent
    data class PaymentFailed(val message: String) : CheckoutEvent
}

/**
 * AND-213 — checkout-session presentation logic.
 *
 * Reads cartId/total/currency from nav args (SavedStateHandle), guards the empty cart, then creates a
 * checkout session (POST ui/checkout/session). The idempotency key is generated once and persisted to
 * SavedStateHandle so re-entry / process-death restore reuses it (best-effort dedupe). "Place order"
 * routes the payment step through [BillingAuthorizer]; the stub returns NotConfigured ->
 * PaymentsUnavailable. No charge endpoint is ever called from this ViewModel.
 */
@HiltViewModel
class CheckoutSessionViewModel @Inject constructor(
    private val checkoutRepository: CheckoutRepository,
    private val cartRepository: CartRepository,
    private val billingAuthorizer: BillingAuthorizer,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val cartId: String? = savedState[ARG_CART_ID]
    private val totalCents: Long = savedState[ARG_TOTAL_CENTS] ?: 0L
    private val currency: String = savedState[ARG_CURRENCY] ?: "USD"

    private val idempotencyKey: String =
        savedState[KEY_IDEMPOTENCY] ?: UUID.randomUUID().toString()
            .also { savedState[KEY_IDEMPOTENCY] = it }

    private val _state = MutableStateFlow<OrderReviewUiState>(OrderReviewUiState.Loading)
    val state: StateFlow<OrderReviewUiState> = _state.asStateFlow()

    private val _placing = MutableStateFlow(false)
    val placing: StateFlow<Boolean> = _placing.asStateFlow()

    private val _events = Channel<CheckoutEvent>(Channel.BUFFERED)
    val events: Flow<CheckoutEvent> = _events.receiveAsFlow()

    init {
        start()
    }

    fun start() {
        // Empty-cart guard: a session with no items would be a wasted/orphan order.
        if (totalCents <= 0L) {
            _state.update { OrderReviewUiState.EmptyCart }
            return
        }
        _state.update { OrderReviewUiState.Loading }
        viewModelScope.launch {
            val request = CheckoutSessionRequest(
                cartId = cartId,
                idempotencyKey = idempotencyKey,
                totalCents = totalCents,
                currency = currency,
            )
            _state.value = when (val r = checkoutRepository.createSession(request)) {
                is ApiResult.Success -> OrderReviewUiState.Ready(r.data)
                is ApiResult.Failure -> OrderReviewUiState.Error(r.error.message, retryable = true)
                is ApiResult.NetworkError -> OrderReviewUiState.Error(OFFLINE_MESSAGE, retryable = true)
            }
        }
    }

    fun retry() = start()

    /**
     * AND-213 / AND-031 — attempts payment for the created session via the billing stub. The stub
     * returns NotConfigured, so this surfaces PaymentsUnavailable and never charges. When AND-031 wires
     * a real authorizer, the Authorized branch will carry the payment_method_id to a billing call.
     */
    fun placeOrder() {
        val ready = _state.value as? OrderReviewUiState.Ready ?: return
        if (_placing.value) return
        _placing.update { true }
        viewModelScope.launch {
            val result = billingAuthorizer.authorize(
                amountMinorUnits = ready.session.totalCents,
                currency = ready.session.currency,
            )
            when (result) {
                is BillingResult.NotConfigured -> _events.send(CheckoutEvent.PaymentsUnavailable)
                is BillingResult.Cancelled -> Unit
                is BillingResult.Declined -> _events.send(CheckoutEvent.PaymentFailed(result.reason))
                is BillingResult.Failed ->
                    _events.send(CheckoutEvent.PaymentFailed(result.cause.message ?: GENERIC_PAYMENT_ERROR))
                // The stub never returns Authorized. The real charge call is owned by AND-227/AND-031;
                // this ViewModel must NOT call a charge endpoint, so Authorized is intentionally inert.
                is BillingResult.Authorized -> _events.send(CheckoutEvent.PaymentsUnavailable)
            }
            _placing.update { false }
        }
    }

    companion object {
        const val ARG_CART_ID = "cartId"
        const val ARG_TOTAL_CENTS = "totalCents"
        const val ARG_CURRENCY = "currency"
        const val KEY_IDEMPOTENCY = "idem_key"
        private const val OFFLINE_MESSAGE = "You're offline"
        private const val GENERIC_PAYMENT_ERROR = "Payment failed"
    }
}
