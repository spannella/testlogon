package com.testlogon.android.feature.tokens

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.ads.AdClickAttributionStore
import com.testlogon.android.data.ads.AdEvent
import com.testlogon.android.data.ads.AdTrackRepository
import com.testlogon.android.data.shopads.ShopAdsRepository
import com.testlogon.android.data.shopads.SponsoredProduct
import com.testlogon.android.data.tokens.Token
import com.testlogon.android.data.tokens.TokensRepository
import com.testlogon.android.feature.ads.SlotEntry
import com.testlogon.android.feature.ads.interleaveSponsored
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Which slice of the token list is shown. */
enum class TokenListTab { MARKET, ISSUED }

data class TokensMarketUiState(
    val phase: Phase = Phase.Loading,
    val tab: TokenListTab = TokenListTab.MARKET,
    val market: List<Token> = emptyList(),
    val issued: List<Token> = emptyList(),
    /**
     * FE-161 — served SPONSORED units interleaved into the MARKET tab's list. Empty when the serve
     * 404s / is unfilled (degrade-on-404: the organic market list is unchanged).
     */
    val sponsored: List<SponsoredProduct> = emptyList(),
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }

    val rows: List<Token> get() = if (tab == TokenListTab.MARKET) market else issued

    /**
     * FE-161 — the MARKET tab as an ordered list of organic token rows with SPONSORED slots
     * interleaved every ~5 items (capped 2). The ISSUED tab never carries ads. When [sponsored] is
     * empty the result is exactly the organic rows (organic rendering unchanged).
     */
    val marketSlots: List<SlotEntry<Token, SponsoredProduct>>
        get() = if (tab == TokenListTab.MARKET) {
            interleaveSponsored(
                items = market,
                sponsored = sponsored,
                everyN = SPONSORED_EVERY_N,
                startAt = SPONSORED_EVERY_N,
                max = SPONSORED_MAX,
                key = { _, ad -> "sponsored_" + ad.unitId },
            )
        } else {
            issued.map { SlotEntry.Organic(it) }
        }

    companion object {
        const val SPONSORED_EVERY_N = 5
        const val SPONSORED_MAX = 2
    }
}

/**
 * Drives the token market/browse list. Loads both the LISTED market (browse) and the caller's ISSUED
 * tokens; both degrade to empty on 404 so the screen shows an honest "pending backend" empty state
 * rather than an error when the endpoints are undeployed.
 *
 * FE-161 (EPIC G) — additionally serves STANDALONE product-linked SPONSORED units for the token
 * DISCOVERY (market) surface and interleaves them into the organic market list as clearly-labeled
 * sponsored slots. Impression fires when a slot is first shown; a tap fires the CLICK beacon + stashes
 * the ad_click_id for CPA — all through the SHARED /ui/ads/track money-path (AdTrackRepository /
 * AdClickAttributionStore). Best-effort: any serve/track failure never disturbs the organic list.
 */
@HiltViewModel
class TokensMarketViewModel @Inject constructor(
    private val repository: TokensRepository,
    private val shopAdsRepository: ShopAdsRepository,
    private val adTracker: AdTrackRepository,
    private val adAttribution: AdClickAttributionStore,
) : ViewModel() {

    private val _uiState = MutableStateFlow(TokensMarketUiState())
    val uiState: StateFlow<TokensMarketUiState> = _uiState.asStateFlow()

    /** Impression dedupe — fire at most once per served unit per session. */
    private val impressedUnits = java.util.Collections.synchronizedSet(mutableSetOf<String>())

    init {
        load()
    }

    fun onRetry() = load()

    fun selectTab(tab: TokenListTab) = _uiState.update { it.copy(tab = tab) }

    fun load() {
        _uiState.update { it.copy(phase = TokensMarketUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            val market = repository.market()
            val issued = repository.issued()
            // A transport failure (offline) on EITHER read -> Error with retry; HTTP 404s already
            // degraded to empty inside the repository.
            val netError = (market as? ApiResult.NetworkError) ?: (issued as? ApiResult.NetworkError)
            if (netError != null) {
                _uiState.update {
                    it.copy(
                        phase = TokensMarketUiState.Phase.Error,
                        errorMessage = "No connection. Check your network and retry.",
                    )
                }
                return@launch
            }
            _uiState.update {
                it.copy(
                    phase = TokensMarketUiState.Phase.Content,
                    market = (market as? ApiResult.Success)?.data.orEmpty(),
                    issued = (issued as? ApiResult.Success)?.data.orEmpty(),
                    errorMessage = null,
                )
            }
            loadSponsored()
        }
    }

    /**
     * FE-161 — best-effort serve of sponsored units for the token-discovery surface. Re-labels the
     * tracking surface to "token_discovery" so impression/click beacons record THIS surface. Any
     * failure folds to an empty list inside the repository -> no slots -> organic list unchanged.
     */
    private fun loadSponsored() {
        viewModelScope.launch {
            val served = shopAdsRepository.serveShopSponsored(
                surface = ShopAdsRepository.SURFACE_BROWSE,
                limit = SPONSORED_LIMIT,
            )
            // Round-trip the client-facing discovery surface onto the track payload.
            val relabeled = served.map { p ->
                p.copy(tracking = p.tracking.copy(surface = SURFACE_TOKEN_DISCOVERY))
            }
            _uiState.update { it.copy(sponsored = relabeled) }
        }
    }

    /**
     * FE-161 — fire an IMPRESSION the first time a sponsored slot is shown (deduped per unit).
     * Best-effort — a failed beacon never disturbs the list.
     */
    fun onSponsoredImpression(product: SponsoredProduct) {
        val key = product.adClickId ?: product.unitId
        if (!impressedUnits.add(key)) return
        viewModelScope.launch { adTracker.track(AdEvent.IMPRESSION, product.tracking) }
    }

    /**
     * FE-161 — on tap: fire the CLICK beacon (advertiser CPC, funds-guarded, idempotent, standalone ->
     * platform 100%) AND stash the ad_click_id for CPA attribution. Best-effort; opening the cta_url is
     * the screen's concern (LocalUriHandler).
     */
    fun onSponsoredClick(product: SponsoredProduct) {
        adAttribution.record(product.adClickId)
        viewModelScope.launch { adTracker.track(AdEvent.CLICK, product.tracking) }
    }

    companion object {
        private const val SPONSORED_LIMIT = 3
        const val SURFACE_TOKEN_DISCOVERY = "token_discovery"
    }
}
