package com.testlogon.android.feature.purchases

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.entitlements.LibraryEntitlement
import com.testlogon.android.data.entitlements.OrderEntitlementsRepository
import com.testlogon.android.data.purchases.PurchaseDetail
import com.testlogon.android.data.purchases.PurchaseEvent
import com.testlogon.android.data.purchases.PurchaseReceipt
import com.testlogon.android.data.purchases.PurchasesRepository
import com.testlogon.android.data.tracking.TrackingRepository
import com.testlogon.android.feature.tracking.TrackingUiState
import com.testlogon.android.feature.tracking.TrackingViewModel
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
 * AND-220 — order (transaction) detail state. Reachable from the purchase-history list (AND-219); the
 * nav arg name is kept as `orderId` but the value is a txn_id. Content carries the mapped [PurchaseDetail]
 * (header/status/dates/amount), the resolved cart line [items] (from metadata.cart_id via the existing
 * AND-206/210 [CartRepository] — no new endpoint), and the embedded AND-215 [tracking] state. Tracking is
 * isolated: a tracking failure renders an inline tracking error but never fails the whole screen.
 *
 * AND-218-extras — Content additionally carries the transaction [events] timeline and the [receipt]
 * link. Both are best-effort: a 404 / any failure degrades to an empty list / null so the section is
 * simply hidden, never failing the whole screen.
 */
sealed interface OrderDetailUiState {
    data object Loading : OrderDetailUiState
    data class Content(
        val order: PurchaseDetail,
        val items: List<CartItem>,
        val tracking: TrackingUiState,
        // ECOMX-43 (B5): digital goods granted by this order, accessible/openable in-app.
        val entitlements: List<LibraryEntitlement> = emptyList(),
        // AND-218-extras: transaction event timeline (newest-first); empty -> section hidden.
        val events: List<PurchaseEvent> = emptyList(),
        // AND-218-extras: receipt link; null -> section hidden. isOpenable gates the open/download CTA.
        val receipt: PurchaseReceipt? = null,
        // ECOMX-42 (B6): true while a "confirm delivery" call is in flight.
        val confirming: Boolean = false,
    ) : OrderDetailUiState
    data class Error(val message: String, val retryable: Boolean) : OrderDetailUiState
}

/** ECOMX-42 (B6) — one-shot order-detail effects (snackbars). */
sealed interface OrderDetailEvent {
    data object DeliveryConfirmed : OrderDetailEvent
    data class ActionFailed(val message: String) : OrderDetailEvent
}

@HiltViewModel
class OrderDetailViewModel @Inject constructor(
    private val purchasesRepository: PurchasesRepository,
    private val cartRepository: CartRepository,
    private val trackingRepository: TrackingRepository, // AND-215, reused (no duplication)
    private val entitlementsRepository: OrderEntitlementsRepository, // ECOMX-43 (B5)
    savedState: SavedStateHandle,
) : ViewModel() {

    // Nav arg name kept as the standalone tracking route's arg for reuse; value is a txn_id.
    private val txnId: String = savedState[ARG_TXN_ID] ?: ""

    private val _state = MutableStateFlow<OrderDetailUiState>(OrderDetailUiState.Loading)
    val state: StateFlow<OrderDetailUiState> = _state.asStateFlow()

    private val _events = Channel<OrderDetailEvent>(Channel.BUFFERED)
    val events: Flow<OrderDetailEvent> = _events.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        if (txnId.isBlank()) {
            _state.value = OrderDetailUiState.Error(GENERIC_ERROR, retryable = false)
            return
        }
        _state.update { OrderDetailUiState.Loading }
        viewModelScope.launch {
            when (val detail = purchasesRepository.detail(txnId)) {
                is ApiResult.Success -> {
                    val order = detail.data
                    val items = resolveItems(order)
                    val tracking = resolveTracking(order)
                    val entitlements = resolveEntitlements(order)
                    val timeline = resolveEvents()
                    val receipt = resolveReceipt()
                    _state.value = OrderDetailUiState.Content(
                        order = order,
                        items = items,
                        tracking = tracking,
                        entitlements = entitlements,
                        events = timeline,
                        receipt = receipt,
                    )
                }
                is ApiResult.Failure ->
                    _state.value = OrderDetailUiState.Error(
                        message = detail.error.message,
                        // 404/422 (bad/unknown txn) is terminal; other server errors are retryable.
                        retryable = detail.error.status != 404 && detail.error.status != 422,
                    )
                is ApiResult.NetworkError ->
                    _state.value = OrderDetailUiState.Error(OFFLINE, retryable = true)
            }
        }
    }

    fun retry() = load()

    /**
     * ECOMX-42 (B6) — buyer confirms delivery. Drives the order + txn to COMPLETED, then reloads so the
     * status flips and (if a return window applies) the surfaces update. Guarded against double-tap.
     */
    fun confirmReceived() {
        val content = _state.value as? OrderDetailUiState.Content ?: return
        if (content.confirming) return
        _state.update { (it as? OrderDetailUiState.Content)?.copy(confirming = true) ?: it }
        viewModelScope.launch {
            when (val r = purchasesRepository.confirmReceived(txnId)) {
                is ApiResult.Success -> {
                    _events.send(OrderDetailEvent.DeliveryConfirmed)
                    load()
                }
                is ApiResult.Failure -> {
                    _state.update { (it as? OrderDetailUiState.Content)?.copy(confirming = false) ?: it }
                    _events.send(OrderDetailEvent.ActionFailed(r.error.message))
                }
                is ApiResult.NetworkError -> {
                    _state.update { (it as? OrderDetailUiState.Content)?.copy(confirming = false) ?: it }
                    _events.send(OrderDetailEvent.ActionFailed(OFFLINE))
                }
            }
        }
    }

    /** ECOMX-43 (B5) — the digital goods granted by this order (best-effort; never fails the screen).
     *  The txn's external_ref carries the commerce order_id, which entitlements are attributed to. */
    private suspend fun resolveEntitlements(order: PurchaseDetail): List<LibraryEntitlement> {
        val orderId = order.externalRef?.takeIf { it.isNotBlank() } ?: return emptyList()
        return when (val r = entitlementsRepository.libraryForOrder(orderId)) {
            is ApiResult.Success -> r.data
            is ApiResult.Failure, is ApiResult.NetworkError -> emptyList()
        }
    }

    /** Resolves cart line items from metadata.cart_id; empty when absent / on a cart-fetch failure. */
    private suspend fun resolveItems(order: PurchaseDetail): List<CartItem> {
        val cartId = order.cartId ?: return emptyList()
        return when (val r = cartRepository.itemsForCart(cartId)) {
            is ApiResult.Success -> r.data
            // Items are best-effort; a failure must not fail the detail screen.
            is ApiResult.Failure, is ApiResult.NetworkError -> emptyList()
        }
    }

    /**
     * AND-218-extras — the transaction event timeline. Best-effort: a 404 (no events) / any failure
     * degrades to an empty list so the section is hidden and never fails the whole screen.
     */
    private suspend fun resolveEvents(): List<PurchaseEvent> =
        when (val r = purchasesRepository.events(txnId)) {
            is ApiResult.Success -> r.data
            is ApiResult.Failure, is ApiResult.NetworkError -> emptyList()
        }

    /**
     * AND-218-extras — the receipt link. Best-effort: a 404 (no receipt) / any failure degrades to null
     * so the section is hidden and never fails the whole screen.
     */
    private suspend fun resolveReceipt(): PurchaseReceipt? =
        when (val r = purchasesRepository.receipt(txnId)) {
            is ApiResult.Success -> r.data
            is ApiResult.Failure, is ApiResult.NetworkError -> null
        }

    /**
     * Resolves the embedded AND-215 tracking state. When the order shows no shipment at all there is
     * nothing to track -> NotShipped. Otherwise GET tracking and reduce via the AND-215 pure reducer so
     * the embedded TrackingSection renders identically to the standalone route.
     *
     * ECOMX selldash-E3: the gate now keys off [PurchaseDetail.hasShipmentEvidence] (the E1 order-header
     * fulfilment/order status), NOT the always-empty legacy `shipping` sub-object. The `.../tracking`
     * endpoint (E1 / ECOMX-E3) aggregates the buyer's OWN ship-group tracking, so once the order shipped
     * the buyer sees the real carrier/number/status/timeline the seller entered — without a ship_group_id.
     */
    private suspend fun resolveTracking(order: PurchaseDetail): TrackingUiState {
        if (!order.hasShipmentEvidence) return TrackingUiState.NotShipped
        return TrackingViewModel.reduce(trackingRepository.tracking(txnId))
    }

    companion object {
        // Reuse the standalone tracking route's nav-arg name so one destination contract serves both.
        const val ARG_TXN_ID = TrackingViewModel.ARG_TXN_ID
        private const val GENERIC_ERROR = "Couldn't load order."
        private const val OFFLINE = "You're offline"
    }
}
