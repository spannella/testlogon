package com.testlogon.android.feature.cart

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.cart.FullCart
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-211 — the cart-load outcome (the authoritative cart, before search is applied). */
sealed interface CartLoadState {
    data object Loading : CartLoadState
    data class Loaded(val cart: FullCart) : CartLoadState
    data class Error(val message: String, val retryable: Boolean) : CartLoadState
}

/** AND-211 — per-row mutation status (drives the in-flight indicator + control disabling). */
data class RowMutation(val sku: String)

/**
 * AND-211 / AND-212 — the fully-derived cart screen state: the load outcome, the in-flight row (if
 * any), and the search query + filtered view. The screen renders from this single object.
 */
data class CartUiState(
    val load: CartLoadState = CartLoadState.Loading,
    val mutatingSku: String? = null,
    val query: String = "",
    val filtered: FilteredCart = FilteredCart.EMPTY,
) {
    val cart: FullCart? get() = (load as? CartLoadState.Loaded)?.cart
    val isEmpty: Boolean get() = cart?.isEmpty == true
    val isMutating: Boolean get() = mutatingSku != null
}

/** AND-211 — one-shot effects (snackbars). Delivered over a Channel so rotation cannot replay them. */
sealed interface CartEvent {
    data class MutationFailed(val message: String) : CartEvent
}

/**
 * AND-211 / AND-212 — cart screen presentation logic.
 *
 * Loads the active cart (resolve-or-create -> items + total) and exposes the three mutating operations
 * (set quantity, remove line) plus a within-cart search (AND-212). Quantity edits are OPTIMISTIC: the
 * row updates immediately and is marked in-flight, then reconciled to the server cart on success or
 * rolled back on failure. Mutations re-fetch items + total internally (the PATCH/DELETE bodies are not
 * the cart) and are never auto-retried. One-shot failures ride a Channel; the search query is mirrored
 * to SavedStateHandle so it survives process death.
 */
@HiltViewModel
class CartViewModel @Inject constructor(
    private val repository: CartRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _load = MutableStateFlow<CartLoadState>(CartLoadState.Loading)
    private val _mutatingSku = MutableStateFlow<String?>(null)
    private val _query = MutableStateFlow(savedState[KEY_QUERY] ?: "")

    private val _events = Channel<CartEvent>(Channel.BUFFERED)
    val events: Flow<CartEvent> = _events.receiveAsFlow()

    @OptIn(FlowPreview::class)
    private val debouncedQuery = _query
        .debounce { if (it.isEmpty()) 0L else DEBOUNCE_MS }
        .distinctUntilChanged()

    val uiState: StateFlow<CartUiState> =
        combine(_load, _mutatingSku, _query, debouncedQuery) { load, mutating, raw, dq ->
            val items = (load as? CartLoadState.Loaded)?.cart?.items ?: emptyList<CartItem>()
            CartUiState(
                load = load,
                mutatingSku = mutating,
                query = raw,
                filtered = CartSearch.filter(items, dq),
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), CartUiState())

    init {
        load()
    }

    fun load() {
        _load.update { CartLoadState.Loading }
        viewModelScope.launch {
            _load.value = repository.loadCart().toLoadState()
        }
    }

    fun retry() = load()

    /** AND-212 — mirrors the raw query immediately; the filter derivation keys off the debounced value. */
    fun onQueryChange(value: String) {
        _query.value = value
        savedState[KEY_QUERY] = value
    }

    fun onClearQuery() = onQueryChange("")

    /**
     * AND-211 — sets [sku] to [newQuantity]. The `-` control floors at 1 (use [onRemove] to delete).
     * Optimistic: applies the new quantity locally + marks the row in-flight, then reconciles or rolls
     * back. Re-entry while a row is in flight is a no-op (one request per row).
     */
    fun onQuantityChange(sku: String, newQuantity: Int) {
        if (newQuantity < 1) return
        val loaded = _load.value as? CartLoadState.Loaded ?: return
        if (_mutatingSku.value != null) return
        if (loaded.cart.items.none { it.sku == sku }) return

        val rollback = loaded.cart
        _load.value = CartLoadState.Loaded(rollback.optimisticSetQuantity(sku, newQuantity))
        _mutatingSku.value = sku
        viewModelScope.launch {
            when (val r = repository.setQuantity(sku, newQuantity)) {
                is ApiResult.Success -> _load.value = CartLoadState.Loaded(r.data)
                is ApiResult.Failure -> rollbackWith(rollback, r.error.message)
                is ApiResult.NetworkError -> rollbackWith(rollback, OFFLINE_MESSAGE)
            }
            _mutatingSku.value = null
        }
    }

    /** AND-211 — removes [sku] optimistically, reconciling (possibly to Empty) or rolling back. */
    fun onRemove(sku: String) {
        val loaded = _load.value as? CartLoadState.Loaded ?: return
        if (_mutatingSku.value != null) return
        if (loaded.cart.items.none { it.sku == sku }) return

        val rollback = loaded.cart
        _load.value = CartLoadState.Loaded(rollback.optimisticRemove(sku))
        _mutatingSku.value = sku
        viewModelScope.launch {
            when (val r = repository.removeLine(sku)) {
                is ApiResult.Success -> _load.value = CartLoadState.Loaded(r.data)
                is ApiResult.Failure -> rollbackWith(rollback, r.error.message)
                is ApiResult.NetworkError -> rollbackWith(rollback, OFFLINE_MESSAGE)
            }
            _mutatingSku.value = null
        }
    }

    private suspend fun rollbackWith(rollback: FullCart, message: String) {
        _load.value = CartLoadState.Loaded(rollback)
        _events.send(CartEvent.MutationFailed(message))
    }

    private fun ApiResult<FullCart>.toLoadState(): CartLoadState = when (this) {
        is ApiResult.Success -> CartLoadState.Loaded(data)
        is ApiResult.Failure -> CartLoadState.Error(error.message, retryable = true)
        is ApiResult.NetworkError -> CartLoadState.Error(OFFLINE_MESSAGE, retryable = true)
    }

    companion object {
        const val KEY_QUERY = "cart_query"
        private const val DEBOUNCE_MS = 200L
        private const val STOP_TIMEOUT_MS = 5_000L
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}

// ---- Optimistic helpers (pure; recompute the affected line + derived total) ----

internal fun FullCart.optimisticSetQuantity(sku: String, quantity: Int): FullCart {
    val newItems = items.map { item ->
        if (item.sku == sku) {
            item.copy(quantity = quantity, lineTotalCents = item.unitPriceCents * quantity)
        } else {
            item
        }
    }
    return copy(items = newItems, totalCents = newItems.sumOf { it.lineTotalCents })
}

internal fun FullCart.optimisticRemove(sku: String): FullCart {
    val newItems = items.filterNot { it.sku == sku }
    return copy(items = newItems, totalCents = newItems.sumOf { it.lineTotalCents })
}
