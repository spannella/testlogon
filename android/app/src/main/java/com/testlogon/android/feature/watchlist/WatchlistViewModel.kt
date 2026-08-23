package com.testlogon.android.feature.watchlist

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.watchlist.WatchItem
import com.testlogon.android.data.exchange.watchlist.WatchKind
import com.testlogon.android.data.exchange.watchlist.WatchlistStore
import com.testlogon.android.data.exchange.watchlist.sortForDisplay
import com.testlogon.android.data.strategies.StrategiesRepository
import com.testlogon.android.data.tokens.TokensRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * One render-ready row of the UNIFIED watchlist. [item] carries the kind + id; [title]/[subtitle] are
 * kind-appropriate labels; [priceText]/[changeText] are the live price/NAV surface (null while loading
 * or when the backend degrades on 404). [route] is the destination this row deep-links to.
 */
data class WatchRow(
    val item: WatchItem,
    val title: String,
    val subtitle: String,
    val priceText: String? = null,
    val changeText: String? = null,
    val changeUp: Boolean? = null,
    val route: String,
)

data class WatchlistUiState(
    val phase: Phase = Phase.Loading,
    val rows: List<WatchRow> = emptyList(),
) {
    enum class Phase { Loading, Content, Empty }
}

/**
 * Drives the unified Watchlist screen. Reads the starred set from [WatchlistStore] (which already
 * spans symbols + tokens + strategies), then enriches each item with a live price/NAV + change from
 * its existing repository. Every enrichment read DEGRADES quietly on 404 (the token/strategy backends
 * are pending) — the row still renders with its label and a "—" price. Removing an item mutates the
 * shared store, so the change reflects everywhere (markets filter, detail stars) immediately.
 */
@HiltViewModel
class WatchlistViewModel @Inject constructor(
    private val watchlist: WatchlistStore,
    private val exchange: ExchangeRepository,
    private val tokens: TokensRepository,
    private val strategies: StrategiesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(WatchlistUiState())
    val uiState: StateFlow<WatchlistUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    /** Remove an item from the unified watchlist and re-render. */
    fun remove(item: WatchItem) {
        watchlist.remove(item.kind, item.id)
        load()
    }

    private fun load() {
        val items = sortForDisplay(watchlist.current())
        if (items.isEmpty()) {
            _uiState.update { WatchlistUiState(phase = WatchlistUiState.Phase.Empty, rows = emptyList()) }
            return
        }
        // First render the skeleton rows (labels + routes) so the list appears instantly, then enrich.
        _uiState.update {
            WatchlistUiState(
                phase = WatchlistUiState.Phase.Content,
                rows = items.map { skeletonRow(it) },
            )
        }
        viewModelScope.launch { enrich(items) }
    }

    private fun skeletonRow(item: WatchItem): WatchRow = when (item.kind) {
        WatchKind.SYMBOL -> WatchRow(
            item = item,
            title = "Symbol #${item.id}",
            subtitle = "Exchange market",
            route = "markets/${item.id}",
        )
        WatchKind.TOKEN -> WatchRow(
            item = item,
            title = "Token",
            subtitle = "Creator revenue-share token",
            route = "tokens/detail/${android.net.Uri.encode(item.id)}",
        )
        WatchKind.STRATEGY -> WatchRow(
            item = item,
            title = "Strategy",
            subtitle = "Strategy fund",
            route = "strategies/detail/${android.net.Uri.encode(item.id)}",
        )
    }

    /** Enrich each row with a live price/NAV + label, degrading quietly per-item on 404/absent. */
    private suspend fun enrich(items: List<WatchItem>) {
        // Load the instrument catalogue once for symbol labels/prices (degrades to empty).
        val instruments: List<Instrument> =
            (exchange.symbols() as? ApiResult.Success)?.data.orEmpty()

        for (item in items) {
            val enriched = when (item.kind) {
                WatchKind.SYMBOL -> enrichSymbol(item, instruments)
                WatchKind.TOKEN -> enrichToken(item)
                WatchKind.STRATEGY -> enrichStrategy(item)
            }
            _uiState.update { state ->
                state.copy(rows = state.rows.map { if (it.item == item) enriched else it })
            }
        }
    }

    private suspend fun enrichSymbol(item: WatchItem, instruments: List<Instrument>): WatchRow {
        val id = item.id.toIntOrNull()
        val instrument = instruments.firstOrNull { it.symbolId == id }
        val title = instrument?.symbol ?: "Symbol #${item.id}"
        val subtitle = when {
            instrument == null -> "Exchange market"
            instrument.isPerpetual -> "Perpetual"
            else -> "Spot"
        }
        var priceText: String? = null
        if (id != null) {
            val last = (exchange.trades(id) as? ApiResult.Success)?.data?.firstOrNull()?.price
            val book = (exchange.orderBook(id) as? ApiResult.Success)?.data
            val raw = last?.let { instrument?.display(it) } ?: book?.mid
            if (raw != null) priceText = formatUsd(raw)
        }
        return skeletonRow(item).copy(title = title, subtitle = subtitle, priceText = priceText)
    }

    private suspend fun enrichToken(item: WatchItem): WatchRow {
        val token = (tokens.token(item.id) as? ApiResult.Success)?.data
        val title = token?.let { it.ticker.ifBlank { it.name } }?.ifBlank { "Token" } ?: "Token"
        val subtitle = token?.name?.takeIf { it.isNotBlank() && it != title }
            ?: "Creator revenue-share token"
        val priceText = token?.clearingPrice?.let { centsToUsd(it) }
        return skeletonRow(item).copy(title = title, subtitle = subtitle, priceText = priceText)
    }

    private suspend fun enrichStrategy(item: WatchItem): WatchRow {
        val strategy = (strategies.strategy(item.id) as? ApiResult.Success)?.data
        val nav = (strategies.nav(item.id) as? ApiResult.Success)?.data
        val title = strategy?.name?.ifBlank { "Strategy" } ?: "Strategy"
        val navPerUnit = nav?.navPerUnit ?: strategy?.navPerUnit
        val priceText = navPerUnit?.let { "NAV " + centsToUsd(it) }
        val retBps = nav?.inceptionReturnBps ?: strategy?.inceptionReturnBps
        val changeText = retBps?.let { formatBpsPct(it) }
        val changeUp = retBps?.let { it >= 0 }
        return skeletonRow(item).copy(
            title = title,
            subtitle = "Strategy fund",
            priceText = priceText,
            changeText = changeText,
            changeUp = changeUp,
        )
    }

    private fun formatUsd(value: Double): String = "$" + String.format("%,.2f", value)

    private fun centsToUsd(cents: Long): String = "$" + String.format("%,.2f", cents / 100.0)

    private fun formatBpsPct(bps: Int): String {
        val pct = bps / 100.0
        val sign = if (pct >= 0) "+" else ""
        return "$sign" + String.format("%.2f", pct) + "%"
    }
}
