package com.testlogon.android.feature.billing

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.billing.BillingRepository
import com.testlogon.android.data.billing.PaymentMethod
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

/** AND-224 — the payment-methods list load outcome. */
sealed interface PaymentMethodsLoadState {
    data object Loading : PaymentMethodsLoadState
    data class Loaded(val methods: List<PaymentMethod>) : PaymentMethodsLoadState
    data class Error(val message: String, val retryable: Boolean) : PaymentMethodsLoadState
}

/**
 * AND-224 — the fully-derived payment-methods screen state. [rowInFlight] holds the ids with an active
 * mutation (per-row spinner + non-interactive); [isRefreshing] drives pull-to-refresh.
 */
data class PaymentMethodsUiState(
    val load: PaymentMethodsLoadState = PaymentMethodsLoadState.Loading,
    val rowInFlight: Set<String> = emptySet(),
    val isRefreshing: Boolean = false,
) {
    val methods: List<PaymentMethod> get() = (load as? PaymentMethodsLoadState.Loaded)?.methods.orEmpty()
    val isEmpty: Boolean get() = load is PaymentMethodsLoadState.Loaded && methods.isEmpty()
}

/** AND-224 — one-shot effects (snackbars). Delivered over a Channel so rotation cannot replay them. */
sealed interface PaymentMethodsEvent {
    data object Removed : PaymentMethodsEvent
    data object DefaultSet : PaymentMethodsEvent
    data class Failure(val message: String) : PaymentMethodsEvent
}

/**
 * AND-224 — payment-methods management presentation logic.
 *
 * Loads saved methods (default-first, priority asc), and exposes remove + set-default, each of which
 * locks only its row, calls the backend, and reconciles to the re-fetched authoritative list (the
 * mutations return only OkResp). The "Add payment method" CTA is owned by the screen (routes to the
 * AND-226 add-card flow). One-shot failures ride a Channel; the list re-fetch is the source of truth.
 */
@HiltViewModel
class PaymentMethodsViewModel @Inject constructor(
    private val repository: BillingRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(PaymentMethodsUiState())
    val uiState: StateFlow<PaymentMethodsUiState> = _state.asStateFlow()

    private val _events = Channel<PaymentMethodsEvent>(Channel.BUFFERED)
    val events: Flow<PaymentMethodsEvent> = _events.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        _state.update { it.copy(load = PaymentMethodsLoadState.Loading) }
        viewModelScope.launch {
            _state.update { it.copy(load = repository.getPaymentMethods().toLoadState()) }
        }
    }

    fun retry() = load()

    fun refresh() {
        if (_state.value.isRefreshing) return
        _state.update { it.copy(isRefreshing = true) }
        viewModelScope.launch {
            val result = repository.getPaymentMethods()
            _state.update {
                // Keep the existing list on a refresh failure (non-blocking); only replace on success.
                val newLoad = when (result) {
                    is ApiResult.Success -> PaymentMethodsLoadState.Loaded(result.data)
                    else -> if (it.load is PaymentMethodsLoadState.Loaded) it.load else result.toLoadState()
                }
                it.copy(load = newLoad, isRefreshing = false)
            }
            if (result !is ApiResult.Success) {
                _events.send(PaymentMethodsEvent.Failure(result.messageOrOffline()))
            }
        }
    }

    /** AND-224 — set [id] as default; row-locked, reconciled to the re-fetched list. */
    fun setDefault(id: String) =
        runMutation(id, PaymentMethodsEvent.DefaultSet) { repository.setDefaultPaymentMethod(id) }

    /** AND-224 — remove [id]; row-locked, reconciled to the re-fetched list. */
    fun remove(id: String) =
        runMutation(id, PaymentMethodsEvent.Removed) { repository.removePaymentMethod(id) }

    private fun runMutation(
        id: String,
        success: PaymentMethodsEvent,
        block: suspend () -> ApiResult<List<PaymentMethod>>,
    ) {
        if (id in _state.value.rowInFlight) return
        _state.update { it.copy(rowInFlight = it.rowInFlight + id) }
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    _state.update {
                        it.copy(load = PaymentMethodsLoadState.Loaded(r.data), rowInFlight = it.rowInFlight - id)
                    }
                    _events.send(success)
                }
                is ApiResult.Failure -> failRow(id, r.error.message)
                is ApiResult.NetworkError -> failRow(id, OFFLINE_MESSAGE)
            }
        }
    }

    private suspend fun failRow(id: String, message: String) {
        _state.update { it.copy(rowInFlight = it.rowInFlight - id) }
        _events.send(PaymentMethodsEvent.Failure(message))
    }

    private fun ApiResult<List<PaymentMethod>>.toLoadState(): PaymentMethodsLoadState = when (this) {
        is ApiResult.Success -> PaymentMethodsLoadState.Loaded(data)
        is ApiResult.Failure -> PaymentMethodsLoadState.Error(error.message, retryable = true)
        is ApiResult.NetworkError -> PaymentMethodsLoadState.Error(OFFLINE_MESSAGE, retryable = true)
    }

    private fun ApiResult<List<PaymentMethod>>.messageOrOffline(): String = when (this) {
        is ApiResult.Success -> ""
        is ApiResult.Failure -> error.message
        is ApiResult.NetworkError -> OFFLINE_MESSAGE
    }

    companion object {
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}
