package com.testlogon.android.feature.markets

import com.testlogon.android.data.exchange.Instrument

/** One render-ready row of the Markets list: an [instrument] plus its live top-of-book snapshot. */
data class MarketRow(
    val instrument: Instrument,
    val lastPrice: Double? = null,
    val bestBid: Long? = null,
    val bestAsk: Long? = null,
)

/**
 * Single immutable Markets-list state. [phase] enumerates the mutually-exclusive top-level surfaces;
 * [rows] persists across refresh ticks so quote updates do not flash the list back to Loading.
 */
data class MarketsUiState(
    val phase: Phase = Phase.Loading,
    val rows: List<MarketRow> = emptyList(),
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error }
}
