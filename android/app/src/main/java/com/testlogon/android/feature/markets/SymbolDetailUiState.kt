package com.testlogon.android.feature.markets

import com.testlogon.android.data.exchange.Candle
import com.testlogon.android.data.exchange.OrderBook
import com.testlogon.android.data.exchange.Trade

/**
 * Single immutable state for the per-symbol detail (chart / order book / trades). Content persists
 * across 2s poll ticks; [phase] gates only the very first render (before any data arrives).
 */
data class SymbolDetailUiState(
    val phase: Phase = Phase.Loading,
    val symbolId: Int = 0,
    val symbolName: String = "",
    val candles: List<Candle> = emptyList(),
    val orderBook: OrderBook? = null,
    val trades: List<Trade> = emptyList(),
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}
