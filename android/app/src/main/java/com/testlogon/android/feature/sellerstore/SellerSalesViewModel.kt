package com.testlogon.android.feature.sellerstore

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.sellerstore.SellerSale
import com.testlogon.android.data.sellerstore.SellerSaleDetail
import com.testlogon.android.data.sellerstore.SellerSalesRepository
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
 * ECOM-SELLER (G1-G4) — the seller's "Sales / Orders received". Lists the authenticated seller's own
 * ship groups via `/ui/seller/sales` (NON-admin, scoped to their catalog items); opening one loads its
 * detail (buyer + buyer shipping address + this seller's real line items + server-authoritative
 * allowed_transitions) and drives fulfilment (transition, e.g. mark-shipped) scoped to the ship group.
 *
 * The `shop_item_sold` alert deep-links here with a `sale=` id; [openSale] auto-opens that detail.
 */
data class SellerSalesUiState(
    val loading: Boolean = true,
    val error: String? = null,
    val sales: List<SellerSale> = emptyList(),
    val detail: SellerSaleDetail? = null,
    val detailLoading: Boolean = false,
    val actionBusy: Boolean = false,
)

sealed interface SellerSalesEvent {
    data class Message(val text: String) : SellerSalesEvent
}

@HiltViewModel
class SellerSalesViewModel @Inject constructor(
    private val repository: SellerSalesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SellerSalesUiState())
    val uiState: StateFlow<SellerSalesUiState> = _uiState.asStateFlow()

    private val _events = Channel<SellerSalesEvent>(Channel.BUFFERED)
    val events: Flow<SellerSalesEvent> = _events.receiveAsFlow()

    init {
        refresh()
    }

    fun refresh() {
        _uiState.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            when (val r = repository.sales(cursor = null)) {
                is ApiResult.Success -> _uiState.update { it.copy(loading = false, sales = r.data.sales) }
                is ApiResult.Failure -> _uiState.update { it.copy(loading = false, error = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(loading = false, error = OFFLINE) }
            }
        }
    }

    /** Opens a sale detail (also used by the shop_item_sold alert deep-link). */
    fun openSale(shipGroupId: String) {
        _uiState.update { it.copy(detailLoading = true, detail = null) }
        viewModelScope.launch { loadDetail(shipGroupId) }
    }

    fun closeDetail() = _uiState.update { it.copy(detail = null, detailLoading = false) }

    private suspend fun loadDetail(shipGroupId: String) {
        when (val r = repository.detail(shipGroupId)) {
            is ApiResult.Success -> _uiState.update { it.copy(detailLoading = false, detail = r.data) }
            is ApiResult.Failure -> { _uiState.update { it.copy(detailLoading = false) }; _events.send(SellerSalesEvent.Message(r.error.message)) }
            is ApiResult.NetworkError -> { _uiState.update { it.copy(detailLoading = false) }; _events.send(SellerSalesEvent.Message(OFFLINE)) }
        }
    }

    /** Advances the open ship group to [target] (fulfil / mark-shipped), then refreshes list + detail. */
    fun transition(target: String, trackingNumber: String? = null, carrier: String? = null) {
        val shipGroupId = _uiState.value.detail?.shipGroupId ?: return
        if (_uiState.value.actionBusy) return
        _uiState.update { it.copy(actionBusy = true) }
        viewModelScope.launch {
            val r = repository.transition(
                shipGroupId = shipGroupId,
                targetStatus = target,
                reason = "Seller advanced to $target",
                trackingNumber = trackingNumber,
                carrier = carrier,
            )
            when (r) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(actionBusy = false, detail = r.data) }
                    _events.send(SellerSalesEvent.Message(if (target == SHIPPED) MARKED_SHIPPED else TRANSITIONED))
                    refresh()
                }
                is ApiResult.Failure -> failAction(r.error.message)
                is ApiResult.NetworkError -> failAction(OFFLINE)
            }
        }
    }

    private suspend fun failAction(message: String) {
        _uiState.update { it.copy(actionBusy = false) }
        _events.send(SellerSalesEvent.Message(message))
    }

    companion object {
        const val SHIPPED = "shipped"
        private const val OFFLINE = "You're offline"
        private const val TRANSITIONED = "Sale updated"
        private const val MARKED_SHIPPED = "Marked as shipped"
    }
}
