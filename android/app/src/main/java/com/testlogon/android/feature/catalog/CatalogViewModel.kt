package com.testlogon.android.feature.catalog

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.ads.AdClickAttributionStore
import com.testlogon.android.data.ads.AdEvent
import com.testlogon.android.data.ads.AdTrackRepository
import com.testlogon.android.data.catalog.CatalogApi
import com.testlogon.android.data.catalog.CatalogCategory
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository
import com.testlogon.android.data.shopads.ShopAdsRepository
import com.testlogon.android.data.shopads.SponsoredProduct
import com.testlogon.android.data.wishlist.WishlistRepository
import com.testlogon.android.data.wishlist.wishlistKey
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-205 — category-layer state for the catalog browse screen. The item grid uses Paging's own
 * LoadState; this state only models the category strip + selection.
 */
sealed interface CatalogUiState {
    data object Loading : CatalogUiState
    data class Ready(
        val categories: List<CatalogCategory>,
        val selectedId: String,
    ) : CatalogUiState
    data object Empty : CatalogUiState
    data class Error(val message: String, val retryable: Boolean) : CatalogUiState
}

/**
 * AND-205 — catalog / category browse presentation logic.
 *
 * Loads all categories once on init, default-selects the first, and exposes a cursor-paged item stream
 * that switches when the selected category changes (re-anchors at page 1 via [flatMapLatest]). The
 * selected category id is persisted to [SavedStateHandle] so it survives process death.
 *
 * ADV x ECOM (B2) — additionally serves STANDALONE product-linked SPONSORED units for the shop_browse
 * surface (re-fetched when the selected category changes) + fires their impression/click beacons and
 * stashes the ad_click_id (CPA) via the SHARED AdTrackRepository / AdClickAttributionStore money-path.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class CatalogViewModel @Inject constructor(
    private val repository: CatalogRepository,
    private val wishlistRepository: WishlistRepository,
    private val shopAdsRepository: ShopAdsRepository,
    private val adTracker: AdTrackRepository,
    private val adAttribution: AdClickAttributionStore,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val selectedCategoryId = savedState.getStateFlow<String?>(KEY_SELECTED, null)

    private val _uiState = MutableStateFlow<CatalogUiState>(CatalogUiState.Loading)
    val uiState: StateFlow<CatalogUiState> = _uiState.asStateFlow()

    /** ADV x ECOM (B2) — the sponsored product units to inject atop the current category's grid. */
    private val _sponsored = MutableStateFlow<List<SponsoredProduct>>(emptyList())
    val sponsored: StateFlow<List<SponsoredProduct>> = _sponsored.asStateFlow()

    /** Impression dedupe — fire at most once per served unit per session. */
    private val impressedUnits = java.util.Collections.synchronizedSet(mutableSetOf<String>())

    /** Shared wishlist saved-set (`category#item` keys) — lights the heart on catalog cells. */
    val savedKeys: StateFlow<Set<String>> = wishlistRepository.saved

    /** Paged item stream that re-creates the Pager when the selected category changes. */
    val items: Flow<PagingData<CatalogItem>> =
        selectedCategoryId
            .filterNotNull()
            .flatMapLatest { id ->
                Pager(
                    config = PagingConfig(
                        pageSize = CatalogApi.PAGE_SIZE,
                        initialLoadSize = CatalogApi.PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { CatalogItemsPagingSource(repository, id) },
                ).flow
            }
            .cachedIn(viewModelScope)

    init {
        loadCategories()
        viewModelScope.launch { wishlistRepository.ensureLoaded() }
        // ADV x ECOM (B2): (re)serve sponsored products whenever the browsed category changes.
        viewModelScope.launch {
            selectedCategoryId.filterNotNull().distinctUntilChanged().collect { categoryId ->
                loadSponsored(categoryId)
            }
        }
    }

    /** Toggles a catalog item in the wishlist (heart on the cell). Optimistic; errors are silent here. */
    fun toggleWishlist(item: CatalogItem) {
        viewModelScope.launch { wishlistRepository.toggle(item.categoryId, item.itemId) }
    }

    /** Whether [item] is currently in the wishlist (derived from [savedKeys]). */
    fun isSaved(keys: Set<String>, item: CatalogItem): Boolean =
        keys.contains(wishlistKey(item.categoryId, item.itemId))

    /** ADV x ECOM (B2) — best-effort serve of shop_browse sponsored units for [categoryId]. */
    private fun loadSponsored(categoryId: String) {
        viewModelScope.launch {
            _sponsored.value = shopAdsRepository.serveShopSponsored(
                surface = ShopAdsRepository.SURFACE_BROWSE,
                categoryId = categoryId,
                limit = SPONSORED_LIMIT,
            )
        }
    }

    /**
     * ADV x ECOM (B2) — fire an IMPRESSION the first time a sponsored product card is shown (deduped per
     * unit). Best-effort — a failed beacon never disturbs the shop.
     */
    fun onSponsoredImpression(product: SponsoredProduct) {
        val key = product.adClickId ?: product.unitId
        if (!impressedUnits.add(key)) return
        viewModelScope.launch { adTracker.track(AdEvent.IMPRESSION, product.tracking) }
    }

    /**
     * ADV x ECOM (B2) — on tap-through: fire the CLICK beacon (advertiser CPC, funds-guarded, idempotent,
     * standalone -> platform 100%) AND stash the ad_click_id so a resulting cart purchase attributes CPA
     * (the checkout reads the last-click back). Best-effort. Navigation is the screen's concern.
     */
    fun onSponsoredClick(product: SponsoredProduct) {
        adAttribution.record(product.adClickId)
        viewModelScope.launch { adTracker.track(AdEvent.CLICK, product.tracking) }
    }

    fun loadCategories() {
        _uiState.update { CatalogUiState.Loading }
        viewModelScope.launch {
            when (val r = repository.categories()) {
                is ApiResult.Success -> {
                    val categories = r.data.categories
                    if (categories.isEmpty()) {
                        _uiState.update { CatalogUiState.Empty }
                    } else {
                        // Restore a persisted selection if it is still present, else default to the first.
                        val persisted = selectedCategoryId.value
                        val selected = categories.firstOrNull { it.categoryId == persisted }?.categoryId
                            ?: categories.first().categoryId
                        if (savedState.get<String?>(KEY_SELECTED) != selected) {
                            savedState[KEY_SELECTED] = selected
                        }
                        _uiState.update { CatalogUiState.Ready(categories = categories, selectedId = selected) }
                    }
                }
                is ApiResult.Failure ->
                    _uiState.update { CatalogUiState.Error(r.error.message, retryable = true) }
                is ApiResult.NetworkError ->
                    _uiState.update { CatalogUiState.Error(OFFLINE_MESSAGE, retryable = true) }
            }
        }
    }

    /** Selects a category: persists the id (drives the paging stream) and updates the Ready state. */
    fun selectCategory(categoryId: String) {
        if (savedState.get<String?>(KEY_SELECTED) == categoryId) return
        savedState[KEY_SELECTED] = categoryId
        _uiState.update { current ->
            if (current is CatalogUiState.Ready) current.copy(selectedId = categoryId) else current
        }
    }

    fun retryCategories() = loadCategories()

    companion object {
        const val KEY_SELECTED = "catalog_selected_category_id"
        private const val PREFETCH_DISTANCE = 6
        private const val SPONSORED_LIMIT = 2
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}
