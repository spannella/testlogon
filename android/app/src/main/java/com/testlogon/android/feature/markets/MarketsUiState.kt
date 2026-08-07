package com.testlogon.android.feature.markets

import com.testlogon.android.data.exchange.Instrument

/**
 * One render-ready row of the Markets list: an [instrument] plus its live top-of-book snapshot,
 * a recent-close [spark] series for the row sparkline, and a computed [changePct] over that window.
 */
data class MarketRow(
    val instrument: Instrument,
    val lastPrice: Double? = null,
    val bestBid: Long? = null,
    val bestAsk: Long? = null,
    val spark: List<Float> = emptyList(),
    val changePct: Double? = null,
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
