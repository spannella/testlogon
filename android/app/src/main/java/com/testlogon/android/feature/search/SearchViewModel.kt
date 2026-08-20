package com.testlogon.android.feature.search

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.TradingUiPrefsStore
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [SearchUiState] for the global search screen. Builds a single searchable catalogue from:
 *  - the exchange instrument list (`md/symbols`, via [ExchangeRepository]) → SYMBOL results,
 *  - a static list of the app's trading DESTINATIONS,
 *  - a small curated set of ACTIONS,
 * then filters/ranks it with the pure [SearchMatching] as the query changes. Recently-opened results
 * are remembered in-memory for the process and surfaced when the query is blank.
 *
 * The screen resolves a tapped [SearchItem] to a nav route via the `on…` lambdas in its route
 * composable; this ViewModel only records the tap into [recents]. All navigation targets are existing
 * authenticated-graph routes.
 */
@HiltViewModel
class SearchViewModel @Inject constructor(
    private val repository: ExchangeRepository,
    private val prefsStore: TradingUiPrefsStore,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SearchUiState())
    val uiState: StateFlow<SearchUiState> = _uiState.asStateFlow()

    /** Full searchable catalogue: destinations + actions immediately, symbols appended once loaded. */
    private var catalogue: List<SearchItem> = staticCatalogue()

    /** Recently-opened item ids, most-recent-first, capped at [MAX_RECENTS]. */
    private val recentIds = ArrayDeque<String>()

    init {
        loadSymbols()
    }

    private fun loadSymbols() {
        viewModelScope.launch {
            val symbols = when (val r = repository.symbols()) {
                is ApiResult.Success -> r.data
                else -> emptyList()
            }.map { instrument ->
                SearchItem(
                    id = "symbol:${instrument.symbolId}",
                    kind = SearchResultKind.SYMBOL,
                    title = instrument.symbol,
                    subtitle = if (instrument.isPerpetual) "Perpetual" else "Spot",
                    keywords = symbolAliases(instrument.symbol),
                    symbolId = instrument.symbolId,
                )
            }
            catalogue = symbols + staticCatalogue()
            recompute(_uiState.value.query)
        }
    }

    /** Called on every text-field change. */
    fun onQueryChange(query: String) = recompute(query)

    /** Record an opened result so it surfaces under "Recent" on the next blank query. */
    fun onResultOpened(item: SearchItem) {
        recentIds.remove(item.id)
        recentIds.addFirst(item.id)
        while (recentIds.size > MAX_RECENTS) recentIds.removeLast()
        // Refresh recents projection if the field is currently blank.
        if (_uiState.value.query.isBlank()) recompute("")
    }

    private fun recompute(query: String) {
        val groups = SearchMatching.filterGrouped(catalogue, query)
        val recents = if (query.isBlank()) resolveRecents() else emptyList()
        val phase = when {
            query.isBlank() -> SearchUiState.Phase.Idle
            groups.isEmpty() -> SearchUiState.Phase.Empty
            else -> SearchUiState.Phase.Results
        }
        _uiState.update {
            it.copy(query = query, groups = groups, recents = recents, phase = phase)
        }
    }

    private fun resolveRecents(): List<SearchItem> =
        recentIds.mapNotNull { id -> catalogue.firstOrNull { it.id == id } }

    /** Split e.g. "BTCUSDC" into ["btc","usdc"] so a search for "btc" or "usdc" matches. */
    private fun symbolAliases(symbol: String): List<String> {
        val quotes = listOf("USDC", "USDT", "USD")
        val quote = quotes.firstOrNull { symbol.endsWith(it) }
        return if (quote != null) listOf(symbol.removeSuffix(quote), quote) else listOf(symbol)
    }

    /** Resolve the current default-symbol target for the "Trade default symbol" action (or null). */
    fun defaultSymbolId(): Int? =
        prefsStore.currentDefaultSymbol().takeIf { it != TradingUiPrefsStore.NO_DEFAULT }

    private companion object {
        const val MAX_RECENTS = 6

        /** The app's trading DESTINATIONS + curated ACTIONS (kind-order preserved by the matcher). */
        fun staticCatalogue(): List<SearchItem> = destinations() + actions()

        fun destinations(): List<SearchItem> = listOf(
            dest(SearchDest.HOME, "Home", "Trading dashboard", "dashboard", "overview"),
            dest(SearchDest.MARKETS, "Markets", "Instruments & live quotes", "instruments", "tickers", "watchlist"),
            dest(SearchDest.PORTFOLIO, "Portfolio", "Cross-venue balances", "balances", "holdings", "positions"),
            dest(SearchDest.PNL, "PnL", "Realized & unrealized performance", "profit", "loss", "performance"),
            dest(SearchDest.BLOTTER, "Blotter", "Orders, fills & positions", "orders", "fills", "trades"),
            dest(SearchDest.CUSTODY, "Custody", "Deposit, withdraw & balances", "wallet", "deposit", "withdraw"),
            dest(SearchDest.STAKING, "Staking", "Staking rewards", "rewards", "earn"),
            dest(SearchDest.SETTINGS, "Settings", "Trading preferences", "preferences", "config"),
            dest(SearchDest.PRICE_ALERTS, "Price alerts", "Your price alerts", "alert", "notify"),
            dest(SearchDest.TRADING_ALERTS, "Trading alerts", "Fills, funding & margin alerts", "alert", "notify"),
        )

        fun dest(dest: SearchDest, title: String, subtitle: String, vararg keywords: String) =
            SearchItem(
                id = "dest:${dest.name}",
                kind = SearchResultKind.DESTINATION,
                title = title,
                subtitle = subtitle,
                keywords = keywords.toList(),
            )

        fun actions(): List<SearchItem> = listOf(
            action(SearchActionId.NEW_PRICE_ALERT, "New price alert", "Create a price alert", "add", "alert"),
            action(SearchActionId.DEPOSIT, "Deposit", "Fund your account", "add funds", "custody"),
            action(SearchActionId.TRADE_DEFAULT_SYMBOL, "Trade default symbol", "Open your default market", "trade", "buy", "sell"),
        )

        fun action(id: SearchActionId, title: String, subtitle: String, vararg keywords: String) =
            SearchItem(
                id = "action:${id.name}",
                kind = SearchResultKind.ACTION,
                title = title,
                subtitle = subtitle,
                keywords = keywords.toList(),
                actionId = id,
            )
    }
}

/** The trading destinations reachable from search; mapped to concrete routes in the route composable. */
enum class SearchDest {
    HOME, MARKETS, PORTFOLIO, PNL, BLOTTER, CUSTODY, STAKING, SETTINGS, PRICE_ALERTS, TRADING_ALERTS
}
