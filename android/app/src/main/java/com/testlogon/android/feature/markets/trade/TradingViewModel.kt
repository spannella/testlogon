package com.testlogon.android.feature.markets.trade

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.navigation.SymbolDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives the order ticket + this-session working orders for one symbol. Places limit orders via
 * [TradingRepository], tracks the resulting working orders locally (no server list), and refreshes
 * the margin account (wallet/margin/position) after each fill-changing action.
 */
@HiltViewModel
class TradingViewModel @Inject constructor(
    private val repository: TradingRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val symbolId: Int = savedStateHandle.get<Int>(SymbolDetailDest.ARG_SYMBOL_ID) ?: 0

    private val _uiState = MutableStateFlow(TradingUiState())
    val uiState: StateFlow<TradingUiState> = _uiState.asStateFlow()

    private var seq = 0

    init { refreshAccount() }

    fun setSide(side: OrderSide) = _uiState.update { it.copy(side = side) }
    fun setPrice(text: String) = _uiState.update { it.copy(priceText = text.filter { c -> c.isDigit() }.take(12)) }
    fun setQty(text: String) = _uiState.update { it.copy(qtyText = text.filter { c -> c.isDigit() }.take(9)) }

    /** Prefill the price (click-to-trade from the book/chart). */
    fun prefillPrice(price: Long, side: OrderSide? = null) = _uiState.update {
        it.copy(priceText = price.toString(), side = side ?: it.side)
    }

    fun refreshAccount() {
        viewModelScope.launch {
            when (val r = repository.marginAccount()) {
                is ApiResult.Success -> _uiState.update { it.copy(account = r.data) }
                else -> Unit
            }
        }
    }

    fun place() {
        val s = _uiState.value
        val price = s.priceLong ?: return
        val qty = s.qtyLong ?: return
        if (price <= 0 || qty <= 0) return
        // clordid: <=20 chars, unique per placement.
        val clordid = "t${System.currentTimeMillis()}${seq++ % 100}"
        _uiState.update { it.copy(placing = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.placeOrder(symbolId, s.side, price, qty, clordid)) {
                is ApiResult.Success -> {
                    val ack = r.data
                    if (ack.accepted) {
                        val filled = ack.fills.sumOf { f -> f.qty }
                        val wo = WorkingOrder(ack.clordid, s.side, price, qty - filled, ack.orderId)
                        _uiState.update { st ->
                            st.copy(
                                placing = false,
                                message = "Placed #${ack.orderId ?: "?"}" + if (filled > 0) " · filled $filled" else "",
                                messageIsError = false,
                                qtyText = "",
                                workingOrders = if (qty - filled > 0) st.workingOrders + wo else st.workingOrders,
                            )
                        }
                        refreshAccount()
                    } else {
                        _uiState.update { it.copy(placing = false, message = ack.message ?: "Order rejected", messageIsError = true) }
                    }
                }
                is ApiResult.Failure -> _uiState.update { it.copy(placing = false, message = r.error.message, messageIsError = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(placing = false, message = "Network error", messageIsError = true) }
            }
        }
    }

    fun cancel(clordid: String) {
        viewModelScope.launch {
            when (val r = repository.cancelOrder(clordid)) {
                is ApiResult.Success -> if (r.data.accepted) {
                    _uiState.update { st ->
                        st.copy(
                            workingOrders = st.workingOrders.filterNot { it.clordid == clordid },
                            message = "Cancelled ${r.data.cancelledQty}",
                            messageIsError = false,
                        )
                    }
                    refreshAccount()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(message = r.error.message, messageIsError = true) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(message = "Network error", messageIsError = true) }
            }
        }
    }
}
