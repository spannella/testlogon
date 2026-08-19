package com.testlogon.android.data.exchange.alerts

import com.testlogon.android.data.exchange.Instrument
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Runs the pure [PriceAlertEval] over the user's persisted [PriceAlert]s against the live last prices
 * the Markets poll already fetches — no new always-on worker; it is driven from the on-screen poll
 * loop (the Markets VM) exactly like the derived-alerts poller.
 *
 * On a fire it: (1) persists the alert as disarmed + triggered (one-shot), and (2) raises it through
 * the SAME [TradingAlertsStore] as a [TradingAlertKind.PRICE] alert so it appears in the shared alerts
 * inbox alongside fills/liquidations/etc. The caller receives the freshly-fired [TradingAlert]s so it
 * can post a system notification (consistent with how the derived poller returns its new alerts).
 *
 * Edge-detection state (the previous last price per symbol) is held in-memory here so an alert armed
 * while the price is already past the threshold does not fire until a genuine crossing.
 */
@Singleton
class PriceAlertsEvaluator @Inject constructor(
    private val store: PriceAlertsStore,
    private val alertsStore: TradingAlertsStore,
    private val clock: AlertClock,
) {
    /** Previous last price (raw ticks) seen per symbolId, for edge detection across ticks. */
    private val prevTicks = HashMap<Int, Long>()

    /** The user's persisted price alerts (newest-created first) for the management screen. */
    fun alerts(): Flow<List<PriceAlert>> = store.alerts()

    suspend fun add(alert: PriceAlert) = store.upsert(alert)
    suspend fun delete(id: String) = store.delete(id)
    suspend fun rearm(id: String) = store.rearm(id)

    /**
     * Evaluate every armed alert whose symbol has a fresh last price in [lastBySymbol] (raw ticks).
     * Persists any one-shot fires and mirrors them into the shared alerts inbox; returns the newly
     * raised [TradingAlert]s (empty when nothing crossed). Never throws.
     *
     * [instruments] is used only to render a human label ("BTC crossed above 65000") from the symbolId
     * and to format the threshold via the symbol scaler; a missing instrument falls back to "#id".
     */
    suspend fun evaluate(
        lastBySymbol: Map<Int, Long>,
        instruments: List<Instrument>,
    ): List<TradingAlert> {
        if (lastBySymbol.isEmpty()) return emptyList()
        val current = store.snapshot()
        if (current.isEmpty()) {
            // Still advance edge state so a later-added alert edge-detects correctly.
            lastBySymbol.forEach { (sym, ticks) -> prevTicks[sym] = ticks }
            return emptyList()
        }

        val now = clock.nowMs()
        val byId = instruments.associateBy { it.symbolId }
        val fired = ArrayList<TradingAlert>()
        var changed = false

        val updated = current.map { alert ->
            val last = lastBySymbol[alert.symbolId] ?: return@map alert
            val prev = prevTicks[alert.symbolId]
            val result = PriceAlertEval.evaluate(alert, prev, last, now)
            if (result.fired) {
                changed = true
                fired += toTradingAlert(result.alert, last, byId[alert.symbolId], now)
            }
            result.alert
        }

        // Advance edge state AFTER evaluating this tick.
        lastBySymbol.forEach { (sym, ticks) -> prevTicks[sym] = ticks }

        if (changed) store.replaceAll(updated)
        if (fired.isNotEmpty()) alertsStore.addAlerts(fired)
        return fired
    }

    private fun toTradingAlert(
        alert: PriceAlert,
        lastTicks: Long,
        instrument: Instrument?,
        now: Long,
    ): TradingAlert {
        val label = instrument?.symbol ?: ("#" + alert.symbolId)
        val dir = if (alert.direction == PriceAlertDirection.ABOVE) "above" else "below"
        val threshold = instrument?.display(alert.priceTicks) ?: alert.priceTicks.toDouble()
        val lastDisp = instrument?.display(lastTicks) ?: lastTicks.toDouble()
        val thresholdStr = fmt(threshold)
        val body = buildString {
            append(label).append(" crossed ").append(dir).append(' ').append(thresholdStr)
            append(" (last ").append(fmt(lastDisp)).append(')')
            alert.note?.takeIf { it.isNotBlank() }?.let { append(" — ").append(it) }
        }
        return TradingAlert(
            id = "price:" + alert.id + ":" + alert.triggeredTs,
            kind = TradingAlertKind.PRICE,
            title = label + " price alert",
            body = body,
            eventTsNs = 0L,
            createdAtMs = now,
        )
    }

    private fun fmt(v: Double): String =
        if (v == v.toLong().toDouble()) v.toLong().toString() else v.toString()
}
