package com.testlogon.android.feature.markets

import com.testlogon.android.data.exchange.Candle
import com.testlogon.android.data.exchange.OrderBook
import com.testlogon.android.data.exchange.Trade

/**
 * Single immutable state for the per-symbol detail (chart / order book / trades). Content persists
 * across updates; [phase] gates only the very first render (before any data arrives). The order book
 * and latest candle are driven LIVE by SSE ([live] flips true once the first stream frame lands);
 * trades still arrive on a relaxed REST poll.
 */
data class SymbolDetailUiState(
    val phase: Phase = Phase.Loading,
    val symbolId: Int = 0,
    val symbolName: String = "",
    val candles: List<Candle> = emptyList(),
    val orderBook: OrderBook? = null,
    val trades: List<Trade> = emptyList(),
    val live: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}
