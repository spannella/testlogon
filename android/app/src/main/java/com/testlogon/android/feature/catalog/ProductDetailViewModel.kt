package com.testlogon.android.feature.catalog

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository
import com.testlogon.android.data.catalog.CatalogReview
import com.testlogon.android.data.feed.CurrentUserRepository
import com.testlogon.android.data.wishlist.WishlistRepository
import com.testlogon.android.data.wishlist.wishlistKey
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
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

    /** ECOM — review / wishlist snackbar effects. */
    data object ReviewSubmitted : ProductDetailEvent
    data class ReviewSubmitFailed(val message: String) : ProductDetailEvent
    data object ReviewDeleted : ProductDetailEvent
    data class WishlistFailed(val message: String) : ProductDetailEvent
}

/** ECOM (reviews) — state for the reviews section on the product-detail screen. */
sealed interface ReviewsUiState {
    data object Loading : ReviewsUiState
    data class Ready(
        val reviews: List<CatalogReview>,
        val averageRating: Double?,
        val count: Int,
        /** user_sub of the signed-in user, for the delete-own gate (null until resolved). */
        val currentUserSub: String?,
    ) : ReviewsUiState
    data class Error(val message: String) : ReviewsUiState
}

/** ECOM (reviews) — transient submit status for the compose row. */
enum class ReviewSubmitStatus { Idle, InFlight }

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
    private val wishlistRepository: WishlistRepository,
    private val currentUserRepository: CurrentUserRepository,
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

    // ── Reviews ──
    private val _reviewsState = MutableStateFlow<ReviewsUiState>(ReviewsUiState.Loading)
    val reviewsState: StateFlow<ReviewsUiState> = _reviewsState.asStateFlow()

    private val _reviewSubmitState = MutableStateFlow(ReviewSubmitStatus.Idle)
    val reviewSubmitState: StateFlow<ReviewSubmitStatus> = _reviewSubmitState.asStateFlow()

    private var currentUserSub: String? = null

    // ── Wishlist heart ──
    private val itemKey = wishlistKey(categoryId, itemId)

    /** Filled/outlined heart, derived from the shared wishlist saved-set. */
    val isSaved: StateFlow<Boolean> = wishlistRepository.saved
        .map { it.contains(itemKey) }
        .stateIn(viewModelScope, SharingStarted.Eagerly, false)

    private val _wishlistInFlight = MutableStateFlow(false)
    val wishlistInFlight: StateFlow<Boolean> = _wishlistInFlight.asStateFlow()

    init {
        load()
        loadReviews()
        viewModelScope.launch { wishlistRepository.ensureLoaded() }
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

    // ── Reviews ──────────────────────────────────────────────────────────────

    /** Loads the review list (and resolves the current user_sub for the delete-own gate). */
    fun loadReviews() {
        _reviewsState.update { ReviewsUiState.Loading }
        viewModelScope.launch {
            if (currentUserSub == null) {
                (currentUserRepository.currentUserSub() as? ApiResult.Success)?.let { currentUserSub = it.data }
            }
            _reviewsState.value = when (val r = catalogRepository.reviews(itemId)) {
                is ApiResult.Success -> {
                    val reviews = r.data.reviews
                    ReviewsUiState.Ready(
                        reviews = reviews,
                        averageRating = reviews.map { it.rating }.average().takeIf { reviews.isNotEmpty() },
                        count = reviews.size,
                        currentUserSub = currentUserSub,
                    )
                }
                is ApiResult.Failure -> ReviewsUiState.Error(r.error.message)
                is ApiResult.NetworkError -> ReviewsUiState.Error(OFFLINE_MESSAGE)
            }
        }
    }

    fun retryReviews() = loadReviews()

    /** Posts a review (rating 1..5). No-op while a submit is already in flight (double-tap guard). */
    fun submitReview(rating: Int, title: String, body: String) {
        if (rating !in 1..5) return
        if (_reviewSubmitState.value == ReviewSubmitStatus.InFlight) return
        _reviewSubmitState.update { ReviewSubmitStatus.InFlight }
        viewModelScope.launch {
            val r = catalogRepository.addReview(
                itemId = itemId,
                rating = rating,
                title = title,
                body = body,
                reviewer = currentUserSub,
            )
            when (r) {
                is ApiResult.Success -> {
                    _events.send(ProductDetailEvent.ReviewSubmitted)
                    loadReviews()
                }
                is ApiResult.Failure -> _events.send(ProductDetailEvent.ReviewSubmitFailed(r.error.message))
                is ApiResult.NetworkError -> _events.send(ProductDetailEvent.ReviewSubmitFailed(OFFLINE_MESSAGE))
            }
            _reviewSubmitState.update { ReviewSubmitStatus.Idle }
        }
    }

    /** Deletes one of the user's own reviews (the UI only offers delete on owned rows). */
    fun deleteReview(reviewId: String) {
        viewModelScope.launch {
            when (val r = catalogRepository.deleteReview(itemId, reviewId)) {
                is ApiResult.Success -> {
                    _events.send(ProductDetailEvent.ReviewDeleted)
                    loadReviews()
                }
                is ApiResult.Failure -> _events.send(ProductDetailEvent.ReviewSubmitFailed(r.error.message))
                is ApiResult.NetworkError -> _events.send(ProductDetailEvent.ReviewSubmitFailed(OFFLINE_MESSAGE))
            }
        }
    }

    // ── Wishlist ─────────────────────────────────────────────────────────────

    /** Toggles this item in the wishlist. Optimistic; a failure surfaces a snackbar. */
    fun toggleWishlist() {
        if (_wishlistInFlight.value) return
        _wishlistInFlight.update { true }
        viewModelScope.launch {
            when (val r = wishlistRepository.toggle(categoryId, itemId)) {
                is ApiResult.Success -> Unit
                is ApiResult.Failure -> _events.send(ProductDetailEvent.WishlistFailed(r.error.message))
                is ApiResult.NetworkError -> _events.send(ProductDetailEvent.WishlistFailed(OFFLINE_MESSAGE))
            }
            _wishlistInFlight.update { false }
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
