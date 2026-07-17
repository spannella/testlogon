package com.testlogon.android.feature.checkout

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.checkout.CheckoutLineItem
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

    /** ECOMX-40 (B3) — "Place order" tapped with no shipping address selected. */
    data object AddressRequired : CheckoutEvent

    /** FIX (ecom residual #1) — the purchase completed; [txnId] routes to order confirmation. */
    data class PurchaseComplete(val txnId: String?, val orderId: String) : CheckoutEvent
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
    private val adAttribution: com.testlogon.android.data.ads.AdClickAttributionStore,
    private val billingAuthorizer: BillingAuthorizer,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val cartId: String? = savedState[ARG_CART_ID]
    private val totalCents: Long = savedState[ARG_TOTAL_CENTS] ?: 0L
    private val currency: String = savedState[ARG_CURRENCY] ?: "USD"

    // ECOMX-40 (B3): the shipping address chosen in the address step; required before
    // "Place order" is enabled and threaded into the charge. Persisted to SavedStateHandle
    // so process-death restore keeps the selection.
    private val _selectedAddressId = MutableStateFlow<String?>(savedState[KEY_ADDRESS_ID])
    val selectedAddressId: StateFlow<String?> = _selectedAddressId.asStateFlow()

    /** ECOMX-40: called by the route when the address step returns a chosen address_id. */
    fun onAddressSelected(addressId: String?) {
        if (addressId.isNullOrBlank() || addressId == _selectedAddressId.value) return
        _selectedAddressId.value = addressId
        savedState[KEY_ADDRESS_ID] = addressId
    }

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
                is ApiResult.Success -> OrderReviewUiState.Ready(enrichFromCart(r.data))
                is ApiResult.Failure -> OrderReviewUiState.Error(r.error.message, retryable = true)
                is ApiResult.NetworkError -> OrderReviewUiState.Error(OFFLINE_MESSAGE, retryable = true)
            }
        }
    }

    /**
     * The checkout-session response carries line items WITHOUT product names (only sku + amounts), so
     * the screen would otherwise show raw skus and no prices. The cart has the real names + unit/line
     * prices — merge them in. Falls back to the session's own items if the cart can't be read.
     */
    private suspend fun enrichFromCart(session: CheckoutSession): CheckoutSession {
        val items = (cartRepository.loadCart() as? ApiResult.Success)?.data?.items
        if (items.isNullOrEmpty()) return session
        return session.copy(
            lineItems = items.map {
                CheckoutLineItem(
                    sku = it.sku,
                    name = it.name,
                    quantity = it.quantity,
                    unitPriceCents = it.unitPriceCents,
                    lineTotalCents = it.lineTotalCents,
                )
            },
        )
    }

    fun retry() = start()

    /**
     * FIX (ecom residual #1) — completes the purchase via the reliable cart-purchase endpoint
     * (POST ui/shoppingcart/carts/{cart_id}/purchase, X-Idempotency-Key). This actually creates the
     * order, decrements stock and credits the seller. Previously "Place order" routed through the
     * never-authorizing [BillingAuthorizer] stub, so no in-app purchase could ever complete.
     */
    fun placeOrder() {
        _state.value as? OrderReviewUiState.Ready ?: return
        val cart = cartId
        if (cart.isNullOrBlank()) {
            viewModelScope.launch { _events.send(CheckoutEvent.PaymentFailed(GENERIC_PAYMENT_ERROR)) }
            return
        }
        // ECOMX-40 (B3): a shipping address is required before we can charge + ship.
        val addressId = _selectedAddressId.value
        if (addressId.isNullOrBlank()) {
            viewModelScope.launch { _events.send(CheckoutEvent.AddressRequired) }
            return
        }
        if (_placing.value) return
        _placing.update { true }
        viewModelScope.launch {
            // ADV-405: attach the session last-click ad_click_id so checkout converts the ad (ADV-403).
            // ECOMX-40 (B3): pass the chosen address so the charge includes shipping+tax and the
            // seller ships to it.
            when (val r = cartRepository.purchase(
                cart, idempotencyKey,
                adClickId = adAttribution.peek(),
                addressId = addressId,
            )) {
                is ApiResult.Success ->
                    _events.send(CheckoutEvent.PurchaseComplete(r.data.purchaseTxnId, r.data.orderId))
                is ApiResult.Failure -> _events.send(CheckoutEvent.PaymentFailed(r.error.message))
                is ApiResult.NetworkError -> _events.send(CheckoutEvent.PaymentFailed(OFFLINE_MESSAGE))
            }
            _placing.update { false }
        }
    }

    companion object {
        const val ARG_CART_ID = "cartId"
        const val ARG_TOTAL_CENTS = "totalCents"
        const val ARG_CURRENCY = "currency"
        const val KEY_IDEMPOTENCY = "idem_key"
        const val KEY_ADDRESS_ID = "checkout_address_id"
        private const val OFFLINE_MESSAGE = "You're offline"
        private const val GENERIC_PAYMENT_ERROR = "Payment failed"
    }
}
