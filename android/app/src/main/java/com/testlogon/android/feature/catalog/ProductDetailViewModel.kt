package com.testlogon.android.feature.catalog

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository
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

/** AND-206 — category-layer state for the product detail screen. */
sealed interface ProductDetailUiState {
    data object Loading : ProductDetailUiState
    data class Ready(val item: CatalogItem) : ProductDetailUiState

    /** Item id absent from the category list — a client-side condition, never an HTTP 404. */
    data object NotFound : ProductDetailUiState
    data class Error(val message: String, val retryable: Boolean) : ProductDetailUiState
}

/** AND-206 — transient add-to-cart status; not persisted (one-shot results ride [ProductDetailEvent]). */
enum class AddToCartStatus { Idle, InFlight }

/** AND-206 — one-shot product detail effects (snackbars / cart-badge refresh). */
sealed interface ProductDetailEvent {
    /** The add succeeded; carries the created line item (no cart count — read separately). */
    data class AddedToCart(val item: CartItem) : ProductDetailEvent
    data class AddToCartFailed(val message: String) : ProductDetailEvent
}

/**
 * AND-206 / AND-208 — product detail presentation logic.
 *
 * Reads categoryId/itemId from [SavedStateHandle] (nav args; survive process death), resolves the item
 * via [CatalogRepository.getItem] (list-then-find — there is no single-item GET), and performs the
 * two-step add-to-cart via [CartRepository] (create/reuse cart then POST the line item). Add results are
 * delivered as one-shot [ProductDetailEvent]s over a Channel so rotation cannot replay a snackbar; the
 * add POST is guarded against double-tap and is never auto-retried. Mirrors the AchievementsViewModel
 * Channel+receiveAsFlow convention.
 */
@HiltViewModel
class ProductDetailViewModel @Inject constructor(
    private val catalogRepository: CatalogRepository,
    private val cartRepository: CartRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val categoryId: String = checkNotNull(savedState[ARG_CATEGORY_ID]) { "missing $ARG_CATEGORY_ID nav arg" }
    val itemId: String = checkNotNull(savedState[ARG_ITEM_ID]) { "missing $ARG_ITEM_ID nav arg" }

    private val _uiState = MutableStateFlow<ProductDetailUiState>(ProductDetailUiState.Loading)
    val uiState: StateFlow<ProductDetailUiState> = _uiState.asStateFlow()

    private val _addState = MutableStateFlow(AddToCartStatus.Idle)
    val addState: StateFlow<AddToCartStatus> = _addState.asStateFlow()

    private val _events = Channel<ProductDetailEvent>(Channel.BUFFERED)
    val events: Flow<ProductDetailEvent> = _events.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        _uiState.update { ProductDetailUiState.Loading }
        viewModelScope.launch {
            _uiState.value = when (val r = catalogRepository.getItem(categoryId, itemId)) {
                is ApiResult.Success -> ProductDetailUiState.Ready(r.data)
                is ApiResult.Failure ->
                    if (r.error.status == CatalogRepository.STATUS_ITEM_NOT_FOUND) {
                        ProductDetailUiState.NotFound
                    } else {
                        ProductDetailUiState.Error(r.error.message, retryable = true)
                    }
                is ApiResult.NetworkError ->
                    ProductDetailUiState.Error(OFFLINE_MESSAGE, retryable = true)
            }
        }
    }

    fun retry() = load()

    /** Adds the current item to the cart. No-op unless Ready and not already in flight (double-tap guard). */
    fun addToCart(quantity: Int = 1) {
        val current = _uiState.value
        if (current !is ProductDetailUiState.Ready) return
        if (_addState.value == AddToCartStatus.InFlight) return
        _addState.update { AddToCartStatus.InFlight }
        viewModelScope.launch {
            when (val r = cartRepository.addToCart(current.item, quantity)) {
                is ApiResult.Success -> _events.send(ProductDetailEvent.AddedToCart(r.data))
                is ApiResult.Failure -> _events.send(ProductDetailEvent.AddToCartFailed(r.error.message))
                is ApiResult.NetworkError -> _events.send(ProductDetailEvent.AddToCartFailed(OFFLINE_MESSAGE))
            }
            _addState.update { AddToCartStatus.Idle }
        }
    }

    companion object {
        const val ARG_CATEGORY_ID = "categoryId"
        const val ARG_ITEM_ID = "itemId"
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}

/** AND-206 — derived availability for the detail screen (matches the web stock_status gating). */
val CatalogItem.isOutOfStock: Boolean
    get() = stockStatus == "out_of_stock" || (stockStatus != "unlimited" && (stockCount ?: 0) <= 0)
