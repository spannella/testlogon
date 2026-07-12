package com.testlogon.android.feature.catalog

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.ads.AdClickAttributionStore
import com.testlogon.android.data.ads.AdEvent
import com.testlogon.android.data.ads.AdTrackRepository
import com.testlogon.android.data.catalog.CatalogApi
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository
import com.testlogon.android.data.shopads.ShopAdsRepository
import com.testlogon.android.data.shopads.SponsoredProduct
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-207 / AND-208 — catalog search presentation logic.
 *
 * The query string is held in [SavedStateHandle] (survives process death) and mirrored into [query] for
 * the field. The paged result stream debounces 300 ms via the catalog-package [debounceCompat], trims,
 * de-duplicates, and gates on a 2-char minimum (below it, an empty page — no network) so chatter against
 * the flaky dev host is cut. [flatMapLatest] cancels the in-flight Pager when the query changes so stale
 * results never overwrite newer ones; [cachedIn] keeps loaded pages across config change.
 *
 * ADV x ECOM (B2) — additionally serves STANDALONE product-linked SPONSORED units for the shop_search
 * surface with the current query as context, and fires their impression/click beacons + stashes the
 * ad_click_id (CPA) via the SHARED AdTrackRepository / AdClickAttributionStore money-path.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class CatalogSearchViewModel @Inject constructor(
    private val repository: CatalogRepository,
    private val shopAdsRepository: ShopAdsRepository,
    private val adTracker: AdTrackRepository,
    private val adAttribution: AdClickAttributionStore,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _query = MutableStateFlow(savedState.get<String>(KEY_QUERY).orEmpty())
    val query: StateFlow<String> = _query.asStateFlow()

    /** ADV x ECOM (B2) — sponsored product units for the current search query. */
    private val _sponsored = MutableStateFlow<List<SponsoredProduct>>(emptyList())
    val sponsored: StateFlow<List<SponsoredProduct>> = _sponsored.asStateFlow()

    private val impressedUnits = java.util.Collections.synchronizedSet(mutableSetOf<String>())

    val results: Flow<PagingData<CatalogItem>> =
        _query
            .map { it.trim() }
            .debounceCompat(DEBOUNCE_MS)
            .distinctUntilChanged()
            .flatMapLatest { q ->
                if (q.length < MIN_QUERY_LENGTH) {
                    flowOf(PagingData.empty<CatalogItem>())
                } else {
                    Pager(
                        config = PagingConfig(
                            pageSize = CatalogApi.PAGE_SIZE,
                            initialLoadSize = CatalogApi.PAGE_SIZE,
                            prefetchDistance = PREFETCH_DISTANCE,
                            enablePlaceholders = false,
                        ),
                        pagingSourceFactory = { CatalogSearchPagingSource(repository, q) },
                    ).flow
                }
            }
            .cachedIn(viewModelScope)

    init {
        // ADV x ECOM (B2): (re)serve sponsored products for the debounced query.
        viewModelScope.launch {
            _query.map { it.trim() }.debounceCompat(DEBOUNCE_MS).distinctUntilChanged().collect { q ->
                _sponsored.value = if (q.length < MIN_QUERY_LENGTH) {
                    emptyList()
                } else {
                    shopAdsRepository.serveShopSponsored(
                        surface = ShopAdsRepository.SURFACE_SEARCH,
                        query = q,
                        limit = SPONSORED_LIMIT,
                    )
                }
            }
        }
    }

    fun onQueryChange(text: String) {
        _query.value = text
        savedState[KEY_QUERY] = text
    }

    fun onClear() = onQueryChange("")

    /** ADV x ECOM (B2) — fire an IMPRESSION the first time a sponsored search unit shows (deduped). */
    fun onSponsoredImpression(product: SponsoredProduct) {
        val key = product.adClickId ?: product.unitId
        if (!impressedUnits.add(key)) return
        viewModelScope.launch { adTracker.track(AdEvent.IMPRESSION, product.tracking) }
    }

    /** ADV x ECOM (B2) — tap-through: CPC click + stash ad_click_id (CPA). Navigation is the screen's. */
    fun onSponsoredClick(product: SponsoredProduct) {
        adAttribution.record(product.adClickId)
        viewModelScope.launch { adTracker.track(AdEvent.CLICK, product.tracking) }
    }

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LENGTH = 2
        private const val PREFETCH_DISTANCE = 6
        private const val SPONSORED_LIMIT = 2
        private const val KEY_QUERY = "catalog_search_query"
    }
}

/** AND-207 — the search screen's high-level phase, derived from the query + paging load-state. */
sealed interface CatalogSearchUiState {
    /** Query blank / below the minimum length — neutral "type to search" prompt, no request. */
    data object Idle : CatalogSearchUiState
    data object Loading : CatalogSearchUiState
    data class Content(val query: String) : CatalogSearchUiState
    data class Empty(val query: String) : CatalogSearchUiState
    data class Error(val message: String, val retryable: Boolean) : CatalogSearchUiState
}

/**
 * AND-207 — pure derivation of [CatalogSearchUiState] from the trimmed [query], the paging
 * refresh-load-state ([refreshLoading]/[refreshError] + [errorMessage]/[retryable]), and [itemCount].
 * Extracted so the state machine is unit-testable without Compose.
 */
fun searchUiState(
    query: String,
    refreshLoading: Boolean,
    refreshError: Boolean,
    errorMessage: String?,
    retryable: Boolean,
    itemCount: Int,
): CatalogSearchUiState {
    val trimmed = query.trim()
    return when {
        trimmed.length < CatalogSearchViewModel.MIN_QUERY_LENGTH -> CatalogSearchUiState.Idle
        refreshError && itemCount == 0 ->
            CatalogSearchUiState.Error(errorMessage ?: "", retryable = retryable)
        refreshLoading && itemCount == 0 -> CatalogSearchUiState.Loading
        itemCount == 0 -> CatalogSearchUiState.Empty(trimmed)
        else -> CatalogSearchUiState.Content(trimmed)
    }
}
