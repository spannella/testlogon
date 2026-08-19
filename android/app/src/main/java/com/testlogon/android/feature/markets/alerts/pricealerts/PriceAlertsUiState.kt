package com.testlogon.android.feature.markets.alerts.pricealerts

import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.alerts.PriceAlert

/**
 * Immutable state for the Price Alerts management screen.
 *
 * [instruments] is the symbol catalogue for the add-form picker; [lastTicks] is the latest raw last
 * price per symbolId (updated by the on-screen poll) used to render each alert's "current price" and
 * to validate the add form. [alerts] is the persisted user-authored set (newest-created first).
 */
data class PriceAlertsUiState(
    val alerts: List<PriceAlert> = emptyList(),
    val instruments: List<Instrument> = emptyList(),
    val lastTicks: Map<Int, Long> = emptyMap(),
) {
    val active: List<PriceAlert> get() = alerts.filter { it.armed && it.triggeredTs == null }
    val triggered: List<PriceAlert> get() = alerts.filter { !(it.armed && it.triggeredTs == null) }

    fun instrument(symbolId: Int): Instrument? = instruments.firstOrNull { it.symbolId == symbolId }
    fun lastFor(symbolId: Int): Long? = lastTicks[symbolId]
}
