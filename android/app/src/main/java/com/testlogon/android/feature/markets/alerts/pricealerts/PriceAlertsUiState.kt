package com.testlogon.android.feature.markets.alerts.pricealerts

import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.alerts.PriceAlert
import com.testlogon.android.data.exchange.alerts.PriceAlertSubject
import com.testlogon.android.data.strategies.Strategy
import com.testlogon.android.data.tokens.Token

/**
 * Immutable state for the (generalized) Price Alerts management screen, now covering SYMBOL, TOKEN and
 * STRATEGY subjects.
 *
 * [instruments] is the symbol catalogue for the add-form picker; [lastTicks] is the latest raw last
 * price per symbolId (updated by the on-screen poll). [tokens] / [strategies] are the creator-token and
 * strategy-fund catalogues for their pickers, and [tokenPriceById] / [strategyNavById] hold the latest
 * live value (integer CENTS) per token id / strategy id used to render each alert row current value.
 * [alerts] is the persisted user-authored set (newest-created first, all kinds).
 */
data class PriceAlertsUiState(
    val alerts: List<PriceAlert> = emptyList(),
    val instruments: List<Instrument> = emptyList(),
    val lastTicks: Map<Int, Long> = emptyMap(),
    val tokens: List<Token> = emptyList(),
    val strategies: List<Strategy> = emptyList(),
    val tokenPriceById: Map<String, Long> = emptyMap(),
    val strategyNavById: Map<String, Long> = emptyMap(),
) {
    val active: List<PriceAlert> get() = alerts.filter { it.armed && it.triggeredTs == null }
    val triggered: List<PriceAlert> get() = alerts.filter { !(it.armed && it.triggeredTs == null) }

    fun instrument(symbolId: Int): Instrument? = instruments.firstOrNull { it.symbolId == symbolId }
    fun lastFor(symbolId: Int): Long? = lastTicks[symbolId]

    fun token(id: String): Token? = tokens.firstOrNull { it.tokenId == id }
    fun strategy(id: String): Strategy? = strategies.firstOrNull { it.strategyId == id }

    /** Current live value (integer cents/ticks) for an alert of any kind, or null when unknown. */
    fun currentValue(alert: PriceAlert): Long? = when (alert.subject) {
        PriceAlertSubject.SYMBOL -> lastTicks[alert.symbolId]
        PriceAlertSubject.TOKEN -> tokenPriceById[alert.subjectId]
        PriceAlertSubject.STRATEGY -> strategyNavById[alert.subjectId]
    }
}
