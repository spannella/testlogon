package com.testlogon.android.feature.wishlist

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.wishlist.WishlistItem
import com.testlogon.android.data.wishlist.WishlistRepository
import com.testlogon.android.data.wishlist.toCatalogItem
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** ECOM - the Wishlist screen's load state; the item list itself streams from the shared repository. */
sealed interface WishlistUiState {
    data object Loading : WishlistUiState
    data class Content(val items: List<WishlistItem>) : WishlistUiState
    data class Error(val message: String) : WishlistUiState
}

/** ECOM - one-shot Wishlist effects. */
sealed interface WishlistEvent {
    data class RemoveFailed(val message: String) : WishlistEvent

    // PAR-22 - move-to-cart outcome (add-first, remove-after-success). Success carries the item name
    // (or a generic fallback resolved in the UI) for the confirmation snackbar.
    data class MovedToCart(val itemName: String?) : WishlistEvent
    data class MoveToCartFailed(val message: String) : WishlistEvent
}

/**
 * ECOM - presentation logic for the Wishlist screen (SHOP hub). Reads the shared [WishlistRepository]
 * list (so a heart toggle anywhere reflects here) and force-refreshes on init. Remove is optimistic in
 * the repository; a failure reverts and surfaces a snackbar.
 *
 * PAR-22 - move-to-cart reuses [CartRepository.addToCart] (not money-gated: list-or-create then add).
 * The flow is add-first, remove-after-success: on a successful add we remove the wishlist entry; on a
 * failed add we keep the entry and surface an error. A per-item in-flight guard prevents double taps.
 */
@HiltViewModel
class WishlistViewModel @Inject constructor(
    private val repository: WishlistRepository,
    private val cartRepository: CartRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<WishlistUiState>(WishlistUiState.Loading)
    val uiState: StateFlow<WishlistUiState> = _uiState.asStateFlow()

    private val _events = Channel<WishlistEvent>(Channel.BUFFERED)
    val events: Flow<WishlistEvent> = _events.receiveAsFlow()

    /** PAR-22 - keys of items currently being moved to the cart (per-row in-flight guard). */
    private val _movingKeys = MutableStateFlow<Set<String>>(emptySet())
    val movingKeys: StateFlow<Set<String>> = _movingKeys.asStateFlow()

    init {
        // Reflect the shared list immediately + on every subsequent change.
        repository.items
            .onEach { items ->
                _uiState.update { current ->
                    if (current is WishlistUiState.Error) current else WishlistUiState.Content(items)
                }
            }
            .launchIn(viewModelScope)
        refresh()
    }

    fun refresh() {
        if (_uiState.value !is WishlistUiState.Content) _uiState.update { WishlistUiState.Loading }
        viewModelScope.launch {
            when (val r = repository.refresh()) {
                is ApiResult.Success -> _uiState.update { WishlistUiState.Content(r.data) }
                is ApiResult.Failure ->
                    if (_uiState.value !is WishlistUiState.Content) {
                        _uiState.update { WishlistUiState.Error(r.error.message) }
                    }
                is ApiResult.NetworkError ->
                    if (_uiState.value !is WishlistUiState.Content) {
                        _uiState.update { WishlistUiState.Error(OFFLINE_MESSAGE) }
                    }
            }
        }
    }

    fun remove(item: WishlistItem) {
        viewModelScope.launch {
            when (val r = repository.remove(item.categoryId, item.itemId)) {
                is ApiResult.Success -> Unit
                is ApiResult.Failure -> _events.send(WishlistEvent.RemoveFailed(r.error.message))
                is ApiResult.NetworkError -> _events.send(WishlistEvent.RemoveFailed(OFFLINE_MESSAGE))
            }
        }
    }

    /**
     * PAR-22 - move [item] to the cart: add first, then remove from the wishlist only if the add
     * succeeded. On a failed add the item stays and a failure event is emitted. Guarded per-row so a
     * double tap is a no-op while the first is in flight.
     */
    fun moveToCart(item: WishlistItem) {
        if (item.key in _movingKeys.value) return
        _movingKeys.update { it + item.key }
        viewModelScope.launch {
            try {
                when (val added = cartRepository.addToCart(item.toCatalogItem())) {
                    is ApiResult.Success -> {
                        // Add succeeded -> best-effort remove from the wishlist. A remove failure still
                        // reports the move as successful (the item IS in the cart); the list refresh /
                        // shared flow will reconcile.
                        repository.remove(item.categoryId, item.itemId)
                        _events.send(WishlistEvent.MovedToCart(item.name))
                    }
                    is ApiResult.Failure ->
                        _events.send(WishlistEvent.MoveToCartFailed(added.error.message))
                    is ApiResult.NetworkError ->
                        _events.send(WishlistEvent.MoveToCartFailed(OFFLINE_MESSAGE))
                }
            } finally {
                _movingKeys.update { it - item.key }
            }
        }
    }

    companion object {
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}
