package com.testlogon.android.feature.portfolio

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.custody.CustodyRepository
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.PriceMap
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.feature.paper.PaperAccountStore
import com.testlogon.android.feature.paper.PaperEngine
import com.testlogon.android.feature.paper.PaperModeStore
import com.testlogon.android.feature.paper.PaperViews
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Read-only Portfolio ViewModel: fans the four independent venue reads out in parallel (custody
 * balances + staking via [CustodyRepository]; spot balance + margin account via [TradingRepository]),
 * then folds them into a single [PortfolioUiState] via the pure [PortfolioAggregator]. No writes.
 *
 * The reads are launched concurrently with [async] and awaited together; each already folds its own
 * transport failure into an [com.testlogon.android.core.model.ApiResult] variant, so the aggregator
 * degrades any broken/undeployed venue to an "unavailable" card without failing the others.
 */
@HiltViewModel
class PortfolioViewModel @Inject constructor(
    private val custody: CustodyRepository,
    private val trading: TradingRepository,
    private val exchange: ExchangeRepository,
    private val paperStore: PaperAccountStore,
    private val paperModeStore: PaperModeStore,
) : ViewModel() {

    // Live (cross-venue) portfolio state produced by [refresh]. Exposed verbatim when paper mode is OFF.
    private val _uiState = MutableStateFlow(PortfolioUiState())

    // Latest PAPER portfolio projection (a single paper card + paper positions); null until first poll.
    private val paperFlow = MutableStateFlow<PortfolioUiState?>(null)

    /** Latest known live mark per paper symbolId, so paper positions/equity mark-to-market. */
    private val paperMarks = HashMap<Int, Long>()

    /**
     * The exposed state switches source on the paper-mode flag: the shared PAPER account snapshot when
     * ON (loading until its first poll lands), else the live cross-venue snapshot. Read-only either way.
     */
    val uiState: StateFlow<PortfolioUiState> =
        combine(_uiState, paperModeStore.paperMode, paperFlow) { live, paper, paperState ->
            if (paper) (paperState ?: PortfolioUiState(loading = true, cards = emptyList(), paper = true)) else live
        }.stateIn(viewModelScope, SharingStarted.Eagerly, PortfolioUiState())

    init {
        refresh()
        pollPaper()
    }

    /**
     * Continuously project the shared PAPER account into a single-card [PortfolioUiState] while the VM is
     * alive: reload the account, refresh live marks, and fold cash + equity + positions through
     * [PaperViews]. Surfaced only while paper mode is ON; polled unconditionally to stay warm.
     */
    private fun pollPaper() {
        viewModelScope.launch {
            val instruments = (exchange.symbols() as? ApiResult.Success)?.data ?: emptyList()
            val names = instruments.associate { it.symbolId to it.symbol }
            while (true) {
                val acct = paperStore.load()
                if (acct == null) {
                    paperFlow.value = PortfolioUiState(loading = false, cards = emptyList(), paper = true)
                } else {
                    val symbols = (acct.positions.keys + acct.orders.map { it.symbolId }).toSet()
                    for (sid in symbols) {
                        val mark = fetchMark(sid)
                        if (mark != null) paperMarks[sid] = mark
                    }
                    val equity = PaperEngine.equity(acct, paperMarks)
                    val unrealized = PaperEngine.unrealized(acct, paperMarks)
                    val card = VenueCard(
                        venue = PortfolioVenue.PAPER,
                        loading = false,
                        equity = equity.toDouble(),
                        equityUsd = 0.0,
                        lines = listOf(
                            PortfolioLine("Cash", acct.cash.toString()),
                            PortfolioLine("Equity", equity.toString()),
                            PortfolioLine("Unrealized", unrealized.toString()),
                            PortfolioLine("Realized", acct.realizedPnl.toString()),
                            PortfolioLine("Starting cash", acct.startingCash.toString()),
                        ),
                    )
                    paperFlow.value = PortfolioUiState(
                        loading = false,
                        cards = listOf(card),
                        positions = PaperViews.portfolioPositions(acct, paperMarks, names),
                        priced = false,
                        pricesStub = false,
                        paper = true,
                    )
                }
                delay(2_000L)
            }
        }
    }

    /** Best available live price for [symbolId]: last trade, else order-book mid. Null when unavailable. */
    private suspend fun fetchMark(symbolId: Int): Long? {
        val last = (exchange.trades(symbolId) as? ApiResult.Success)?.data?.firstOrNull()?.price
        if (last != null) return last
        val book = (exchange.orderBook(symbolId) as? ApiResult.Success)?.data
        return book?.mid?.let { Math.round(it) }
    }

    fun refresh() {
        _uiState.value = PortfolioUiState(loading = true)
        viewModelScope.launch {
            val snapshot = coroutineScope {
                val custodyDef = async { custody.getBalance() }
                val stakingDef = async { custody.getStaking() }
                val spotDef = async { trading.spotBalance() }
                val marginDef = async { trading.marginAccount() }
                val pricesDef = async { trading.getPrices() }
                PortfolioAggregator.aggregate(
                    custody = custodyDef.await(),
                    staking = stakingDef.await(),
                    spot = spotDef.await(),
                    margin = marginDef.await(),
                    prices = (pricesDef.await() as? ApiResult.Success)?.data ?: PriceMap.unavailable(),
                )
            }
            _uiState.value = snapshot
        }
    }
}
