package com.testlogon.android.feature.broadcast.viewer.shop

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.livecommerce.LiveCommerceRepository
import com.testlogon.android.data.livecommerce.PinnedProduct
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/**
 * LIVECOM L5 — presentation logic for the viewer "Shop this stream" overlay. Lists the products the host
 * pinned to the live session and completes an IN-STREAM purchase without leaving the stream: the buy
 * threads the [broadcast session id] + the host so the backend attributes the order to the stream/host and
 * fires the commission split (affiliate: host commission + seller net + platform; own: host keeps the
 * pool). The host id is the pinning host ([PinnedProduct.pinnedBy]).
 *
 * Resolves the broadcast session id from the viewer route's "sessionId" arg.
 */
@HiltViewModel
class ShopThisStreamViewModel @Inject constructor(
    private val liveCommerceRepository: LiveCommerceRepository,
    private val cartRepository: CartRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    private val _uiState = MutableStateFlow(ShopThisStreamUiState())
    val uiState: StateFlow<ShopThisStreamUiState> = _uiState.asStateFlow()

    init {
        if (sessionId.isNotBlank()) load()
    }

    fun load() {
        _uiState.update { it.copy(loading = true) }
        viewModelScope.launch {
            when (val r = liveCommerceRepository.streamProducts(sessionId)) {
                is ApiResult.Success -> _uiState.update { it.copy(loading = false, products = r.data, error = null) }
                is ApiResult.Failure -> _uiState.update { it.copy(loading = false, error = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(loading = false, error = OFFLINE) }
            }
        }
    }

    fun onToggleExpanded() = _uiState.update { it.copy(expanded = !it.expanded) }

    /** Opens the in-stream buy confirm sheet for [product]. */
    fun onSelect(product: PinnedProduct) = _uiState.update { it.copy(pendingBuy = product, purchaseMessage = null) }

    fun onDismissBuy() = _uiState.update { it.copy(pendingBuy = null) }

    /** Completes the in-stream purchase for the pending product (attributed to the stream + host). */
    fun confirmBuy() {
        val product = _uiState.value.pendingBuy ?: return
        if (_uiState.value.buyingProductId != null) return
        _uiState.update { it.copy(buyingProductId = product.productId, error = null) }
        viewModelScope.launch {
            val result = cartRepository.buyNowInStream(
                productId = product.productId,
                categoryId = product.categoryId,
                name = product.name,
                unitPriceCents = product.priceCents,
                imageUrl = product.imageUrl,
                broadcastSessionId = sessionId,
                hostId = product.pinnedBy.takeIf { it.isNotBlank() },
                idempotencyKey = UUID.randomUUID().toString(),
            )
            when (result) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(
                            buyingProductId = null,
                            pendingBuy = null,
                            purchaseMessage = "Purchased ${product.name} — order ${result.data.orderId.take(8)}",
                        )
                    }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(buyingProductId = null, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(buyingProductId = null, error = OFFLINE) }
            }
        }
    }

    fun consumeMessage() = _uiState.update { it.copy(purchaseMessage = null, error = null) }

    companion object {
        const val ARG_SESSION_ID = "sessionId"
        private const val OFFLINE = "You're offline"
    }
}

/** LIVECOM L5 — viewer shop-this-stream view-state. */
data class ShopThisStreamUiState(
    val loading: Boolean = false,
    val expanded: Boolean = false,
    val products: List<PinnedProduct> = emptyList(),
    val pendingBuy: PinnedProduct? = null,
    val buyingProductId: String? = null,
    val purchaseMessage: String? = null,
    val error: String? = null,
)
