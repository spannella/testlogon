package com.testlogon.android.feature.broadcast.host.livecommerce

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository
import com.testlogon.android.data.feed.CurrentUserRepository
import com.testlogon.android.data.livecommerce.LiveCommerceRepository
import com.testlogon.android.data.livecommerce.PinnedProduct
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * LIVECOM L5 — presentation logic for the host "Feature/Pin product" control on the broadcast HOST
 * screen. The host either picks from THEIR OWN catalog items (default list) OR searches ANY product and
 * pins it as an AFFILIATE — the backend derives is_affiliate from ownership so the host cannot mislabel a
 * foreign product. Shows the pinned "shop this stream" list with an unpin affordance.
 *
 * Resolves the broadcast [sessionId] from the SavedStateHandle "sessionId" arg (shares the host route's
 * NavBackStackEntry, so no extra nav wiring is needed — same pattern as the host ad-break section).
 */
@HiltViewModel
class LiveCommerceHostViewModel @Inject constructor(
    private val liveCommerceRepository: LiveCommerceRepository,
    private val catalogRepository: CatalogRepository,
    private val currentUserRepository: CurrentUserRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    private val _uiState = MutableStateFlow(LiveCommerceHostUiState())
    val uiState: StateFlow<LiveCommerceHostUiState> = _uiState.asStateFlow()

    private var userSub: String? = null

    init {
        if (sessionId.isNotBlank()) {
            loadPinned()
            loadMyItems()
        } else {
            _uiState.update { it.copy(loading = false, error = "No broadcast session.") }
        }
    }

    /** Loads the pinned "shop this stream" set for this session. */
    fun loadPinned() {
        viewModelScope.launch {
            when (val r = liveCommerceRepository.streamProducts(sessionId)) {
                is ApiResult.Success -> _uiState.update { it.copy(loading = false, pinned = r.data, error = null) }
                is ApiResult.Failure -> _uiState.update { it.copy(loading = false, error = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(loading = false, error = OFFLINE) }
            }
        }
    }

    /** Loads the host's OWN catalog items (creator_id == me), shown when the search box is empty. */
    private fun loadMyItems() {
        viewModelScope.launch {
            if (userSub == null) {
                (currentUserRepository.currentUserSub() as? ApiResult.Success)?.let { userSub = it.data }
            }
            val sub = userSub ?: return@launch
            val cats = (catalogRepository.categories() as? ApiResult.Success)?.data?.categories.orEmpty()
                .filter { it.creatorId == sub }
                .take(MAX_OWN_CATEGORIES)
            val items = mutableListOf<CatalogItem>()
            for (c in cats) {
                val page = catalogRepository.categoryItems(c.categoryId, cursor = null) as? ApiResult.Success ?: continue
                items += page.data.items
                if (items.size >= MAX_CANDIDATES) break
            }
            _uiState.update { it.copy(myItems = items.take(MAX_CANDIDATES)) }
        }
    }

    fun onQueryChange(q: String) {
        _uiState.update { it.copy(query = q) }
        if (q.isBlank()) {
            _uiState.update { it.copy(searchResults = emptyList(), searching = false) }
        }
    }

    /** Searches ANY product to pin as an affiliate (blank query falls back to the host's own items). */
    fun search() {
        val q = _uiState.value.query.trim()
        if (q.isBlank()) return
        _uiState.update { it.copy(searching = true) }
        viewModelScope.launch {
            when (val r = catalogRepository.search(q, cursor = null)) {
                is ApiResult.Success ->
                    _uiState.update { it.copy(searching = false, searchResults = r.data.items.take(MAX_CANDIDATES)) }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(searching = false, error = r.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(searching = false, error = OFFLINE) }
            }
        }
    }

    /** Pins a catalog item (own OR affiliate-any) to the live session; is_affiliate is derived server-side. */
    fun pin(item: CatalogItem) {
        if (_uiState.value.busyProductId != null) return
        _uiState.update { it.copy(busyProductId = item.itemId, error = null) }
        viewModelScope.launch {
            when (val r = liveCommerceRepository.pinProduct(sessionId, item.itemId, item.categoryId)) {
                is ApiResult.Success -> { _uiState.update { it.copy(busyProductId = null) }; loadPinned() }
                is ApiResult.Failure -> _uiState.update { it.copy(busyProductId = null, error = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(busyProductId = null, error = OFFLINE) }
            }
        }
    }

    /** Unpins a product from the live session. */
    fun unpin(productId: String) {
        if (_uiState.value.busyProductId != null) return
        _uiState.update { it.copy(busyProductId = productId, error = null) }
        viewModelScope.launch {
            when (val r = liveCommerceRepository.unpinProduct(sessionId, productId)) {
                is ApiResult.Success -> { _uiState.update { it.copy(busyProductId = null) }; loadPinned() }
                is ApiResult.Failure -> _uiState.update { it.copy(busyProductId = null, error = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(busyProductId = null, error = OFFLINE) }
            }
        }
    }

    fun consumeError() = _uiState.update { it.copy(error = null) }

    companion object {
        const val ARG_SESSION_ID = "sessionId"
        private const val OFFLINE = "You're offline"
        private const val MAX_OWN_CATEGORIES = 10
        private const val MAX_CANDIDATES = 50
    }
}

/** LIVECOM L5 — host feature-product control view-state. */
data class LiveCommerceHostUiState(
    val loading: Boolean = true,
    val pinned: List<PinnedProduct> = emptyList(),
    val query: String = "",
    val searching: Boolean = false,
    val searchResults: List<CatalogItem> = emptyList(),
    val myItems: List<CatalogItem> = emptyList(),
    val busyProductId: String? = null,
    val error: String? = null,
) {
    /** Candidates to pin: search results when a query is present, else the host's own items. */
    val candidates: List<CatalogItem> get() = if (query.isBlank()) myItems else searchResults
    val pinnedIds: Set<String> get() = pinned.map { it.productId }.toSet()
}
