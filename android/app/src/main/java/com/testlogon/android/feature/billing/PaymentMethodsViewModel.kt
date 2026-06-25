package com.testlogon.android.feature.billing

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.billing.BillingRepository
import com.testlogon.android.data.billing.PaymentMethod
import com.testlogon.android.feature.billing.error.BillingError
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

/** AND-224 — the payment-methods list load outcome. */
sealed interface PaymentMethodsLoadState {
    data object Loading : PaymentMethodsLoadState
    data class Loaded(val methods: List<PaymentMethod>) : PaymentMethodsLoadState

    /** AND-232 — the failure carries a mapped [BillingError] (localizable message + retryable flag). */
    data class Error(val error: BillingError) : PaymentMethodsLoadState {
        val message: UiText get() = error.message
        val retryable: Boolean get() = error.retryable
    }
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

    /** AND-232 — failure snackbar carries a mapped, localizable [BillingError] message. */
    data class Failure(val error: BillingError) : PaymentMethodsEvent {
        val message: UiText get() = error.message
    }
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
    private val errorMapper: BillingErrorMapper,
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
                _events.send(PaymentMethodsEvent.Failure(errorMapper.map(result)))
            }
        }
    }

    /** AND-224 — set [id] as default; row-locked, reconciled to the re-fetched list. */
    fun setDefault(id: String) =
        runMutation(id, PaymentMethodsEvent.DefaultSet) { repository.setDefaultPaymentMethod(id) }

    /**
     * AND-224 / #15 — remove [id]; row-locked, reconciled to the re-fetched list. The repository
     * DELETE + re-fetch returns one [ApiResult]: on success we adopt the authoritative list; on a
     * failure (which masks whether the DELETE itself succeeded) we DROP the row locally instead of
     * leaving the screen stale/erroring, so the Wallet renders the remaining methods immediately
     * without a restart. We never flip the loaded list into a permanent Error state on a mutation.
     */
    fun remove(id: String) {
        if (id in _state.value.rowInFlight) return
        _state.update { it.copy(rowInFlight = it.rowInFlight + id) }
        viewModelScope.launch {
            when (val r = repository.removePaymentMethod(id)) {
                is ApiResult.Success -> {
                    _state.update {
                        it.copy(load = PaymentMethodsLoadState.Loaded(r.data), rowInFlight = it.rowInFlight - id)
                    }
                    _events.send(PaymentMethodsEvent.Removed)
                }
                else -> {
                    // Self-heal: drop the row from whatever list we are currently showing so a failed
                    // post-delete re-fetch can never leave a stale row or a permanent error screen.
                    _state.update {
                        val pruned = (it.load as? PaymentMethodsLoadState.Loaded)
                            ?.let { l -> PaymentMethodsLoadState.Loaded(l.methods.filterNot { m -> m.id == id }) }
                            ?: it.load
                        it.copy(load = pruned, rowInFlight = it.rowInFlight - id)
                    }
                    _events.send(PaymentMethodsEvent.Failure(errorMapper.map(r)))
                }
            }
        }
    }

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
                else -> failRow(id, errorMapper.map(r))
            }
        }
    }

    private suspend fun failRow(id: String, error: BillingError) {
        _state.update { it.copy(rowInFlight = it.rowInFlight - id) }
        _events.send(PaymentMethodsEvent.Failure(error))
    }

    private fun ApiResult<List<PaymentMethod>>.toLoadState(): PaymentMethodsLoadState = when (this) {
        is ApiResult.Success -> PaymentMethodsLoadState.Loaded(data)
        else -> PaymentMethodsLoadState.Error(errorMapper.map(this))
    }
}
