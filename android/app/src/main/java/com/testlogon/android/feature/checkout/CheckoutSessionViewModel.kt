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
import com.testlogon.android.data.custody.CustodyAssets
import com.testlogon.android.data.custody.CustodyReader
import com.testlogon.android.data.fees.FeeQuote
import com.testlogon.android.data.fees.FeesRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject
import kotlin.math.roundToLong

/** AND-213 order-review screen state. */
sealed interface OrderReviewUiState {
    data object Loading : OrderReviewUiState
    data class Ready(val session: CheckoutSession) : OrderReviewUiState
    data object EmptyCart : OrderReviewUiState
    data class Error(val message: String, val retryable: Boolean) : OrderReviewUiState
}

/**
 * FE-152 - one selectable crypto asset row in the pay-with-crypto picker: symbol, human name and the
 * custody balance in BOTH whole units (display) and integer base units (the insufficient compare
 * against a quote total_native).
 */
data class CryptoAssetOption(
    val symbol: String,
    val name: String,
    val decimals: Int,
    val balanceWhole: Double,
    val balanceBaseUnits: Long,
) {
    val balanceText: String
        get() = if (balanceWhole == balanceWhole.toLong().toDouble()) balanceWhole.toLong().toString()
        else balanceWhole.toString()
}

/**
 * FE-152 - the "Pay with crypto balance" sub-state layered onto the order-review screen. Additive: the
 * existing fiat "Place order" path is untouched. available is false once the quote endpoint 404s
 * (degrade-on-404). assets is the fundable custody balance set; quote is the live rate-locked quote
 * for selectedSymbol; secondsRemaining drives the countdown chip; insufficient disables pay with a
 * message; error carries a quote/pay error (e.g. expired -> re-quote).
 */
data class CryptoPayUiState(
    val available: Boolean = true,
    val assets: List<CryptoAssetOption> = emptyList(),
    val selectedSymbol: String? = null,
    val quoting: Boolean = false,
    val quote: FeeQuote? = null,
    val secondsRemaining: Long = 0L,
    val insufficient: Boolean = false,
    val paying: Boolean = false,
    val error: String? = null,
) {
    val selectedAsset: CryptoAssetOption? get() = assets.firstOrNull { it.symbol == selectedSymbol }

    val canPay: Boolean
        get() = available && quote != null && secondsRemaining > 0L && !insufficient && !quoting && !paying
}

/** AND-213 / AND-031 - the payment-attempt outcome surfaced from "Place order". */
sealed interface CheckoutEvent {
    data object PaymentsUnavailable : CheckoutEvent
    data class PaymentFailed(val message: String) : CheckoutEvent
    data object AddressRequired : CheckoutEvent
    data class PurchaseComplete(val txnId: String?, val orderId: String) : CheckoutEvent
}

/** AND-213 - checkout-session presentation logic (+ FE-152 pay-with-crypto). */
@HiltViewModel
class CheckoutSessionViewModel @Inject constructor(
    private val checkoutRepository: CheckoutRepository,
    private val cartRepository: CartRepository,
    private val adAttribution: com.testlogon.android.data.ads.AdClickAttributionStore,
    private val billingAuthorizer: com.testlogon.android.data.messaging.BillingAuthorizer,
    private val feesRepository: FeesRepository,
    private val custodyReader: CustodyReader,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val cartId: String? = savedState[ARG_CART_ID]
    private val totalCents: Long = savedState[ARG_TOTAL_CENTS] ?: 0L
    private val currency: String = savedState[ARG_CURRENCY] ?: "USD"

    private val _selectedAddressId = MutableStateFlow<String?>(savedState[KEY_ADDRESS_ID])
    val selectedAddressId: StateFlow<String?> = _selectedAddressId.asStateFlow()

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

    private val _crypto = MutableStateFlow(CryptoPayUiState())
    val crypto: StateFlow<CryptoPayUiState> = _crypto.asStateFlow()
    private var countdownJob: Job? = null

    private val _events = Channel<CheckoutEvent>(Channel.BUFFERED)
    val events: Flow<CheckoutEvent> = _events.receiveAsFlow()

    init {
        start()
    }

    fun start() {
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
        loadCryptoBalances()
    }

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

    fun placeOrder() {
        _state.value as? OrderReviewUiState.Ready ?: return
        val cart = cartId
        if (cart.isNullOrBlank()) {
            viewModelScope.launch { _events.send(CheckoutEvent.PaymentFailed(GENERIC_PAYMENT_ERROR)) }
            return
        }
        val addressId = _selectedAddressId.value
        if (addressId.isNullOrBlank()) {
            viewModelScope.launch { _events.send(CheckoutEvent.AddressRequired) }
            return
        }
        if (_placing.value) return
        _placing.update { true }
        viewModelScope.launch {
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

    // ---------------- FE-152: pay-with-crypto ----------------

    private fun loadCryptoBalances() {
        viewModelScope.launch {
            val balances = (custodyReader.getBalance() as? ApiResult.Success)?.data ?: return@launch
            val options = balances.rows
                .filter { it.known && it.amount > 0.0 }
                .mapNotNull { row ->
                    val asset = CustodyAssets.findAsset(row.symbol) ?: return@mapNotNull null
                    CryptoAssetOption(
                        symbol = asset.symbol,
                        name = asset.name,
                        decimals = asset.decimals,
                        balanceWhole = row.amount,
                        balanceBaseUnits = wholeToBaseUnits(row.amount, asset.decimals),
                    )
                }
            _crypto.update { it.copy(assets = options) }
        }
    }

    fun onCryptoAssetSelected(symbol: String) {
        if (symbol == _crypto.value.selectedSymbol && _crypto.value.quote != null) return
        _crypto.update { it.copy(selectedSymbol = symbol, quote = null, error = null, insufficient = false) }
        requestQuote(symbol)
    }

    private fun requestQuote(symbol: String) {
        countdownJob?.cancel()
        _crypto.update { it.copy(quoting = true, error = null) }
        viewModelScope.launch {
            when (val r = feesRepository.quoteFee(amountCents = totalCents, payWith = symbol)) {
                is ApiResult.Success -> {
                    val q = r.data
                    if (q == null) {
                        _crypto.update { it.copy(quoting = false, available = false, quote = null) }
                    } else {
                        applyQuote(symbol, q)
                    }
                }
                is ApiResult.Failure ->
                    _crypto.update { it.copy(quoting = false, quote = null, error = r.error.message) }
                is ApiResult.NetworkError ->
                    _crypto.update { it.copy(quoting = false, quote = null, error = OFFLINE_MESSAGE) }
            }
        }
    }

    private fun applyQuote(symbol: String, quote: FeeQuote) {
        val bal = _crypto.value.assets.firstOrNull { it.symbol == symbol }?.balanceBaseUnits ?: 0L
        val insufficient = CheckoutCryptoMath.insufficientForQuote(bal, quote.totalNative)
        _crypto.update {
            it.copy(
                quoting = false,
                available = true,
                quote = quote,
                insufficient = insufficient,
                secondsRemaining = CheckoutCryptoMath.quoteExpirySeconds(quote.expiresAt, nowMs()),
                error = null,
            )
        }
        startCountdown(symbol, quote)
    }

    private fun startCountdown(symbol: String, quote: FeeQuote) {
        countdownJob?.cancel()
        countdownJob = viewModelScope.launch {
            while (isActive) {
                val remaining = CheckoutCryptoMath.quoteExpirySeconds(quote.expiresAt, nowMs())
                _crypto.update { it.copy(secondsRemaining = remaining) }
                if (remaining <= 0L) {
                    requestQuote(symbol)
                    return@launch
                }
                delay(1000L)
            }
        }
    }

    fun payWithCrypto() {
        val cState = _crypto.value
        val quote = cState.quote ?: return
        val orderId = (_state.value as? OrderReviewUiState.Ready)?.session?.orderId ?: return
        val addressId = _selectedAddressId.value
        if (addressId.isNullOrBlank()) {
            viewModelScope.launch { _events.send(CheckoutEvent.AddressRequired) }
            return
        }
        if (!cState.canPay) return
        _crypto.update { it.copy(paying = true, error = null) }
        viewModelScope.launch {
            when (val r = feesRepository.payCheckoutOrder(orderId, quote)) {
                is ApiResult.Success -> {
                    _crypto.update { it.copy(paying = false) }
                    _events.send(CheckoutEvent.PurchaseComplete(r.data.txnId, r.data.orderId ?: orderId))
                }
                is ApiResult.Failure -> {
                    _crypto.update { it.copy(paying = false) }
                    if (r.error.status == 409 || r.error.code == "quote_expired") {
                        requestQuote(quote.payWith)
                    } else {
                        _events.send(CheckoutEvent.PaymentFailed(r.error.message))
                    }
                }
                is ApiResult.NetworkError -> {
                    _crypto.update { it.copy(paying = false) }
                    _events.send(CheckoutEvent.PaymentFailed(OFFLINE_MESSAGE))
                }
            }
        }
    }

    override fun onCleared() {
        countdownJob?.cancel()
        super.onCleared()
    }

    private fun nowMs(): Long = System.currentTimeMillis()

    companion object {
        const val ARG_CART_ID = "cartId"
        const val ARG_TOTAL_CENTS = "totalCents"
        const val ARG_CURRENCY = "currency"
        const val KEY_IDEMPOTENCY = "idem_key"
        const val KEY_ADDRESS_ID = "checkout_address_id"
        private const val OFFLINE_MESSAGE = "You are offline"
        private const val GENERIC_PAYMENT_ERROR = "Payment failed"

        internal fun wholeToBaseUnits(whole: Double, decimals: Int): Long {
            if (whole <= 0.0) return 0L
            var scale = 1.0
            repeat(if (decimals < 0) 0 else decimals) { scale *= 10.0 }
            val v = (whole * scale).roundToLong()
            return if (v < 0L) 0L else v
        }
    }
}
