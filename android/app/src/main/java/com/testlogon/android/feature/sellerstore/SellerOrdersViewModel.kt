package com.testlogon.android.feature.sellerstore

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.sellerstore.SellerOrder
import com.testlogon.android.data.sellerstore.SellerOrderDetail
import com.testlogon.android.data.sellerstore.SellerOrdersRepository
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
 * ECOM (seller store) — orders-received. Lists orders by lifecycle status; opening one loads its detail
 * (line items + server-authoritative allowed_transitions) and drives fulfilment (transition) / cancel.
 */
data class SellerOrdersUiState(
    val status: String = DEFAULT_STATUS,
    val loading: Boolean = true,
    val error: String? = null,
    val orders: List<SellerOrder> = emptyList(),
    val detail: SellerOrderDetail? = null,
    val detailLoading: Boolean = false,
    val actionBusy: Boolean = false,
) {
    companion object {
        const val DEFAULT_STATUS = "approved"
        /** Lifecycle statuses a seller filters orders by (mirrors OrderLifecycleStatus). */
        val STATUSES = listOf(
            "approved", "allocated", "picking", "packed", "shipped",
            "completed", "created", "held", "backorder", "cancelled", "returned",
        )
    }
}

sealed interface SellerOrdersEvent {
    data class Message(val text: String) : SellerOrdersEvent
}

@HiltViewModel
class SellerOrdersViewModel @Inject constructor(
    private val repository: SellerOrdersRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SellerOrdersUiState())
    val uiState: StateFlow<SellerOrdersUiState> = _uiState.asStateFlow()

    private val _events = Channel<SellerOrdersEvent>(Channel.BUFFERED)
    val events: Flow<SellerOrdersEvent> = _events.receiveAsFlow()

    init {
        refresh()
    }

    fun setStatus(status: String) {
        if (status == _uiState.value.status) return
        _uiState.update { it.copy(status = status) }
        refresh()
    }

    fun refresh() {
        _uiState.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            when (val r = repository.orders(_uiState.value.status, cursor = null)) {
                is ApiResult.Success -> _uiState.update { it.copy(loading = false, orders = r.data.orders) }
                is ApiResult.Failure -> _uiState.update { it.copy(loading = false, error = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(loading = false, error = OFFLINE) }
            }
        }
    }

    fun openOrder(orderId: String) {
        _uiState.update { it.copy(detailLoading = true, detail = null) }
        viewModelScope.launch { loadDetail(orderId) }
    }

    fun closeDetail() = _uiState.update { it.copy(detail = null, detailLoading = false) }

    private suspend fun loadDetail(orderId: String) {
        when (val r = repository.detail(orderId)) {
            is ApiResult.Success -> _uiState.update { it.copy(detailLoading = false, detail = r.data) }
            is ApiResult.Failure -> { _uiState.update { it.copy(detailLoading = false) }; _events.send(SellerOrdersEvent.Message(r.error.message)) }
            is ApiResult.NetworkError -> { _uiState.update { it.copy(detailLoading = false) }; _events.send(SellerOrdersEvent.Message(OFFLINE)) }
        }
    }

    /** Advances the open order to [target] (fulfil / mark-shipped), then refreshes detail + list. */
    fun transition(target: String) {
        val orderId = _uiState.value.detail?.orderId ?: return
        if (_uiState.value.actionBusy) return
        _uiState.update { it.copy(actionBusy = true) }
        viewModelScope.launch {
            when (val r = repository.transition(orderId, target, reason = "Seller advanced to $target")) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(actionBusy = false) }
                    _events.send(SellerOrdersEvent.Message(TRANSITIONED))
                    loadDetail(orderId)
                    refresh()
                }
                is ApiResult.Failure -> failAction(r.error.message)
                is ApiResult.NetworkError -> failAction(OFFLINE)
            }
        }
    }

    fun cancel() {
        val orderId = _uiState.value.detail?.orderId ?: return
        if (_uiState.value.actionBusy) return
        _uiState.update { it.copy(actionBusy = true) }
        viewModelScope.launch {
            when (val r = repository.cancel(orderId, reason = "Seller cancelled", refund = false)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(actionBusy = false) }
                    _events.send(SellerOrdersEvent.Message(CANCELLED))
                    loadDetail(orderId)
                    refresh()
                }
                is ApiResult.Failure -> failAction(r.error.message)
                is ApiResult.NetworkError -> failAction(OFFLINE)
            }
        }
    }

    private suspend fun failAction(message: String) {
        _uiState.update { it.copy(actionBusy = false) }
        _events.send(SellerOrdersEvent.Message(message))
    }

    companion object {
        private const val OFFLINE = "You're offline"
        private const val TRANSITIONED = "Order updated"
        private const val CANCELLED = "Order cancelled"
    }
}
