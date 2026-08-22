package com.testlogon.android.feature.invest

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bailout.BailoutRepository
import com.testlogon.android.data.custody.CustodyRepository
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.data.strategies.StrategiesRepository
import com.testlogon.android.data.tokens.TokensRepository
import com.testlogon.android.navigation.BailoutBoardDest
import com.testlogon.android.navigation.CustodyDest
import com.testlogon.android.navigation.MarketsDest
import com.testlogon.android.navigation.StrategyDetailDest
import com.testlogon.android.navigation.StrategyMarketDest
import com.testlogon.android.navigation.SymbolDetailDest
import com.testlogon.android.navigation.TokenDetailDest
import com.testlogon.android.navigation.TokensMarketDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * The state of ONE invest section. [items] is the FULL (unfiltered) ranked list; the ViewModel
 * exposes the search-filtered view via [InvestUiState.visibleItems]. [pending] is the honest
 * degrade-on-404 flag: the endpoint isn't wired yet (or empty), so the section shows a "pending
 * backend" note rather than looking broken.
 */
data class InvestSectionState(
    val kind: InvestKind,
    val items: List<InvestItem> = emptyList(),
    val pending: Boolean = false,
    val seeAllRoute: String = "",
)

data class InvestUiState(
    val phase: Phase = Phase.Loading,
    val query: String = "",
    val markets: InvestSectionState = InvestSectionState(InvestKind.MARKET, seeAllRoute = MarketsDest.ROUTE),
    val tokens: InvestSectionState = InvestSectionState(InvestKind.TOKEN, seeAllRoute = TokensMarketDest.ROUTE),
    val strategies: InvestSectionState = InvestSectionState(InvestKind.STRATEGY, seeAllRoute = StrategyMarketDest.ROUTE),
    val staking: InvestSectionState = InvestSectionState(InvestKind.STAKING, seeAllRoute = CustodyDest.ROUTE),
    val opportunities: InvestSectionState = InvestSectionState(InvestKind.OPPORTUNITY, seeAllRoute = BailoutBoardDest.ROUTE),
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }

    private val allSections: List<InvestSectionState>
        get() = listOf(markets, tokens, strategies, staking, opportunities)

    /** The section's items filtered by the live [query] (ordering preserved from the ranked list). */
    fun visibleItems(section: InvestSectionState): List<InvestItem> =
        InvestMath.filter(section.items, query)

    /** Total products across all sections (unfiltered) — hub header count. */
    val totalCount: Int get() = InvestMath.totalCount(allSections.map { it.items })

    /** Total products matching the live query across all sections. */
    val matchCount: Int get() = allSections.sumOf { visibleItems(it).size }

    /** True when a non-blank query matches nothing anywhere (honest "no results" state). */
    val noSearchResults: Boolean
        get() = query.isNotBlank() && matchCount == 0 && totalCount > 0
}

/**
 * Drives the unified INVEST hub. Injects the EXISTING per-product repositories (markets, creator
 * tokens, strategy funds, staking, and opportunities: IPO token auctions + bailout rescue auctions +
 * peer stake/auction discovery) and aggregates them CLIENT-SIDE into one screen.
 *
 * Each section degrades INDEPENDENTLY: a 404 (endpoint not wired yet) folds to an honest "pending"
 * empty state for THAT section only, so the hub works NOW for whatever is already live. Only a real
 * transport failure surfaces as a retryable whole-screen error.
 */
@HiltViewModel
class InvestViewModel @Inject constructor(
    private val exchange: ExchangeRepository,
    private val tokens: TokensRepository,
    private val strategies: StrategiesRepository,
    private val custody: CustodyRepository,
    private val bailout: BailoutRepository,
    private val trading: TradingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(InvestUiState())
    val uiState: StateFlow<InvestUiState> = _uiState.asStateFlow()

    init { load() }

    fun onRetry() = load()

    fun onQueryChange(query: String) = _uiState.update { it.copy(query = query) }

    fun load() {
        _uiState.update { it.copy(phase = InvestUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            // Sequential reads (each is a cheap poll; sequential keeps the code + error handling simple).
            val symbolsR = exchange.symbols()
            val tokensR = tokens.market()
            val strategiesR = strategies.market()
            val stakingR = custody.getStaking()
            val tokenAuctionsR = tokens.openAuctions()
            val bailoutsR = bailout.bailouts()
            val stakeReqR = trading.stakeRequestsBrowse()
            val peerAuctionsR = trading.auctionsBrowse()

            // A transport failure on ANY read fails the whole hub (retryable). Endpoint-404s do NOT
            // reach here — the repositories already fold those into empty Success values.
            val netError = listOf(
                symbolsR, tokensR, strategiesR, stakingR, tokenAuctionsR, bailoutsR, stakeReqR, peerAuctionsR,
            ).firstOrNull { it is ApiResult.NetworkError }
            if (netError != null) {
                _uiState.update {
                    it.copy(
                        phase = InvestUiState.Phase.Error,
                        errorMessage = "No connection. Check your network and retry.",
                    )
                }
                return@launch
            }

            // ---- Markets ----
            val instruments = (symbolsR as? ApiResult.Success)?.data.orEmpty()
            val marketItems = InvestMath.rankBySortKey(
                instruments.map { i ->
                    InvestItem(
                        kind = InvestKind.MARKET,
                        id = i.symbolId.toString(),
                        title = i.symbol,
                        subtitle = if (i.isPerpetual) "Perpetual" else "Spot",
                        metric = "Ref ${i.display(i.referencePrice)}",
                        route = SymbolDetailDest.build(i.symbolId),
                        // No live change here (that needs per-symbol candle polls); rank spot/perp
                        // deterministically by symbolId so the ordering is stable.
                        sortKey = i.symbolId.toDouble(),
                        searchText = (i.symbol + " " + if (i.isPerpetual) "perp perpetual" else "spot").lowercase(),
                    )
                },
            )
            // Markets are always available (the repo has a hardcoded fallback catalogue).
            val marketsSection = InvestSectionState(
                kind = InvestKind.MARKET,
                items = marketItems,
                pending = instruments.isEmpty(),
                seeAllRoute = MarketsDest.ROUTE,
            )

            // ---- Creator tokens ----
            val tokenList = (tokensR as? ApiResult.Success)?.data.orEmpty()
            val tokenItems = InvestMath.rankBySortKey(
                tokenList.map { t ->
                    InvestItem(
                        kind = InvestKind.TOKEN,
                        id = t.tokenId,
                        title = t.ticker.ifBlank { t.name },
                        subtitle = t.name,
                        metric = "${t.revenueShareBps / 100.0}% rev-share",
                        route = TokenDetailDest.build(t.tokenId),
                        sortKey = t.revenueShareBps.toDouble(),
                        searchText = (t.ticker + " " + t.name).lowercase(),
                    )
                },
            )
            val tokensSection = InvestSectionState(
                kind = InvestKind.TOKEN,
                items = tokenItems,
                pending = tokenList.isEmpty(),
                seeAllRoute = TokensMarketDest.ROUTE,
            )

            // ---- Strategy funds (top by inception return, then AUM) ----
            val strategyList = (strategiesR as? ApiResult.Success)?.data.orEmpty()
            val strategyItems = InvestMath.rankBySortKey(
                strategyList.map { s ->
                    val cap = InvestMath.capacityRemainingFraction(s.maxAumCents, s.aumCents)
                    val fees = "${s.mgmtFeeBps / 100.0}%/${s.perfFeeBps / 100.0}% fees"
                    val capText = cap?.let { " · ${(it * 100).toInt()}% open" } ?: ""
                    InvestItem(
                        kind = InvestKind.STRATEGY,
                        id = s.strategyId,
                        title = s.name,
                        subtitle = "${(s.inceptionReturnBps ?: 0) / 100.0}% since inception",
                        metric = fees + capText,
                        route = StrategyDetailDest.build(s.strategyId),
                        // Primary rank = inception return; AUM as a tiny secondary nudge for ties.
                        sortKey = InvestMath.returnKey(s.inceptionReturnBps) +
                            (InvestMath.aumKey(s.aumCents) / 1_000_000_000.0),
                        searchText = s.name.lowercase(),
                    )
                },
            )
            val strategiesSection = InvestSectionState(
                kind = InvestKind.STRATEGY,
                items = strategyItems,
                pending = strategyList.isEmpty(),
                seeAllRoute = StrategyMarketDest.ROUTE,
            )

            // ---- Staking (providers/yield) ----
            val stakingDash = (stakingR as? ApiResult.Success)?.data
            val stakingProviders = stakingDash?.providers.orEmpty()
            val stakingItems = InvestMath.rankBySortKey(
                stakingProviders.map { p ->
                    InvestItem(
                        kind = InvestKind.STAKING,
                        id = p.displayId,
                        title = p.asset.ifBlank { p.displayId },
                        subtitle = p.chain.ifBlank { p.kind },
                        metric = p.kind.ifBlank { "Staking" },
                        route = CustodyDest.ROUTE,
                        sortKey = 0.0,
                        searchText = (p.asset + " " + p.chain + " " + p.kind).lowercase(),
                    )
                },
            )
            val stakingSection = InvestSectionState(
                kind = InvestKind.STAKING,
                items = stakingItems,
                // Unavailable (404/403) or simply empty -> pending note.
                pending = stakingProviders.isEmpty(),
                seeAllRoute = CustodyDest.ROUTE,
            )

            // ---- Opportunities (open IPO token auctions + open bailouts + peer stake/auction discovery) ----
            val openTokenAuctions = (tokenAuctionsR as? ApiResult.Success)?.data.orEmpty()
            val openBailouts = (bailoutsR as? ApiResult.Success)?.data.orEmpty()
            val stakeBrowse = (stakeReqR as? ApiResult.Success)?.data
            val peerAuctions = (peerAuctionsR as? ApiResult.Success)?.data

            val oppItems = buildList {
                openTokenAuctions.forEach { a ->
                    add(
                        InvestItem(
                            kind = InvestKind.OPPORTUNITY,
                            id = "tokauction:${a.auctionId.ifBlank { a.tokenId }}",
                            title = "Token IPO",
                            subtitle = a.tokenId.ifBlank { a.auctionId },
                            metric = "${a.offeredPctBps / 100.0}% offered",
                            route = if (a.tokenId.isNotBlank()) TokenDetailDest.build(a.tokenId) else TokensMarketDest.ROUTE,
                            sortKey = a.offeredPctBps.toDouble(),
                            searchText = ("token ipo auction " + a.tokenId).lowercase(),
                        ),
                    )
                }
                openBailouts.forEach { b ->
                    add(
                        InvestItem(
                            kind = InvestKind.OPPORTUNITY,
                            id = "bailout:${b.auctionId}",
                            title = "Bailout rescue",
                            subtitle = "Symbol ${b.symbolId} · ${b.side}",
                            metric = "up to ${b.maxShareBps / 100.0}% share",
                            route = BailoutBoardDest.ROUTE,
                            sortKey = b.maxShareBps.toDouble(),
                            searchText = ("bailout rescue symbol " + b.symbolId).lowercase(),
                        ),
                    )
                }
                stakeBrowse?.items.orEmpty().forEach { r ->
                    add(
                        InvestItem(
                            kind = InvestKind.OPPORTUNITY,
                            id = "stakereq:${r.requestId ?: r.hashCode()}",
                            title = "Stake request",
                            subtitle = r.symbolLabel ?: r.idLabel,
                            metric = r.maxStakePct?.let { "max $it%" }.orEmpty(),
                            route = "",
                            sortKey = 0.0,
                            searchText = ("stake request " + (r.symbolLabel ?: "")).lowercase(),
                        ),
                    )
                }
                peerAuctions?.items.orEmpty().forEach { a ->
                    add(
                        InvestItem(
                            kind = InvestKind.OPPORTUNITY,
                            id = "peerauction:${a.auctionId ?: a.hashCode()}",
                            title = "Position auction",
                            subtitle = a.symbolLabel ?: a.idLabel,
                            metric = a.qty?.let { "qty $it" }.orEmpty(),
                            route = "",
                            sortKey = 0.0,
                            searchText = ("position auction " + (a.symbolLabel ?: "")).lowercase(),
                        ),
                    )
                }
            }
            val opportunitiesSection = InvestSectionState(
                kind = InvestKind.OPPORTUNITY,
                items = InvestMath.rankBySortKey(oppItems),
                pending = oppItems.isEmpty(),
                seeAllRoute = BailoutBoardDest.ROUTE,
            )

            _uiState.update {
                it.copy(
                    phase = InvestUiState.Phase.Content,
                    markets = marketsSection,
                    tokens = tokensSection,
                    strategies = strategiesSection,
                    staking = stakingSection,
                    opportunities = opportunitiesSection,
                    errorMessage = null,
                )
            }
        }
    }
}
