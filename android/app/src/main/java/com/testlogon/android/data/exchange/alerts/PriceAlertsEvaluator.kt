package com.testlogon.android.data.exchange.alerts

import com.testlogon.android.data.exchange.Instrument
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Runs the pure [PriceAlertEval] over the user persisted [PriceAlert]s against live values the on-screen
 * polls already fetch - no new always-on worker. It supports all three subject kinds:
 *  - SYMBOL: last price (raw ticks) from the Markets poll (via [evaluate], driven by the Markets VM).
 *  - TOKEN:  creator-token last/clearing price (cents) via [evaluateSubjects].
 *  - STRATEGY: strategy fund NAV per unit (cents) via [evaluateSubjects].
 *
 * On a fire it: (1) persists the alert as disarmed + triggered (one-shot), and (2) raises it through
 * the SAME [TradingAlertsStore] as a [TradingAlertKind.PRICE] alert so it appears in the shared alerts
 * inbox alongside fills/liquidations/etc. The caller receives the freshly-fired [TradingAlert]s so it
 * can post a system notification.
 *
 * Edge-detection state (the previous value per subject) is held in-memory here, keyed by a composite of
 * subject kind + id, so a token and a symbol that happen to share an id never collide and an alert armed
 * while the value is already past the threshold does not fire until a genuine crossing.
 */
@Singleton
class PriceAlertsEvaluator @Inject constructor(
    private val store: PriceAlertsStore,
    private val alertsStore: TradingAlertsStore,
    private val clock: AlertClock,
) {
    /** Previous observed value per composite subject key, for edge detection across ticks. */
    private val prevValue = HashMap<String, Long>()

    /** The user persisted price alerts (newest-created first) for the management screen. */
    fun alerts(): Flow<List<PriceAlert>> = store.alerts()

    suspend fun add(alert: PriceAlert) = store.upsert(alert)
    suspend fun delete(id: String) = store.delete(id)
    suspend fun rearm(id: String) = store.rearm(id)

    private fun key(subject: PriceAlertSubject, subjectId: String) = subject.name + ":" + subjectId

    suspend fun evaluate(
        lastBySymbol: Map<Int, Long>,
        instruments: List<Instrument>,
    ): List<TradingAlert> {
        if (lastBySymbol.isEmpty()) return emptyList()
        val current = store.snapshot().filter { it.subject == PriceAlertSubject.SYMBOL }
        if (current.isEmpty()) {
            lastBySymbol.forEach { (sym, ticks) -> prevValue[key(PriceAlertSubject.SYMBOL, sym.toString())] = ticks }
            return emptyList()
        }

        val now = clock.nowMs()
        val byId = instruments.associateBy { it.symbolId }
        val fired = ArrayList<TradingAlert>()
        val updatedById = HashMap<String, PriceAlert>()

        current.forEach { alert ->
            val last = lastBySymbol[alert.symbolId] ?: return@forEach
            val k = key(PriceAlertSubject.SYMBOL, alert.symbolId.toString())
            val result = PriceAlertEval.evaluate(alert, prevValue[k], last, now)
            if (result.fired) {
                val instr = byId[alert.symbolId]
                fired += toTradingAlert(
                    alert = result.alert,
                    lastValue = last,
                    subjectName = instr?.symbol,
                    format = { raw -> fmt(instr?.display(raw) ?: raw.toDouble()) },
                    now = now,
                )
                updatedById[alert.id] = result.alert
            }
        }

        lastBySymbol.forEach { (sym, ticks) -> prevValue[key(PriceAlertSubject.SYMBOL, sym.toString())] = ticks }

        if (updatedById.isNotEmpty()) persistFires(updatedById)
        if (fired.isNotEmpty()) alertsStore.addAlerts(fired)
        return fired
    }

    suspend fun evaluateSubjects(
        subject: PriceAlertSubject,
        valueById: Map<String, Long>,
        labelById: Map<String, String> = emptyMap(),
    ): List<TradingAlert> {
        if (valueById.isEmpty()) return emptyList()
        val current = store.snapshot().filter { it.subject == subject }
        if (current.isEmpty()) {
            valueById.forEach { (id, v) -> prevValue[key(subject, id)] = v }
            return emptyList()
        }

        val now = clock.nowMs()
        val fired = ArrayList<TradingAlert>()
        val updatedById = HashMap<String, PriceAlert>()

        current.forEach { alert ->
            val value = valueById[alert.subjectId] ?: return@forEach
            val k = key(subject, alert.subjectId)
            val result = PriceAlertEval.evaluate(alert, prevValue[k], value, now)
            if (result.fired) {
                val name = labelById[alert.subjectId] ?: alert.subjectLabel
                fired += toTradingAlert(
                    alert = result.alert,
                    lastValue = value,
                    subjectName = name,
                    format = { raw -> fmtCents(raw) },
                    now = now,
                )
                updatedById[alert.id] = result.alert
            }
        }

        valueById.forEach { (id, v) -> prevValue[key(subject, id)] = v }

        if (updatedById.isNotEmpty()) persistFires(updatedById)
        if (fired.isNotEmpty()) alertsStore.addAlerts(fired)
        return fired
    }

    private suspend fun persistFires(updatedById: Map<String, PriceAlert>) {
        if (updatedById.isEmpty()) return
        val all = store.snapshot().map { updatedById[it.id] ?: it }
        store.replaceAll(all)
    }

    private fun toTradingAlert(
        alert: PriceAlert,
        lastValue: Long,
        subjectName: String?,
        format: (Long) -> String,
        now: Long,
    ): TradingAlert {
        val label = subjectName ?: alert.subjectLabel ?: ("#" + alert.subjectId)
        val dir = if (alert.direction == PriceAlertDirection.ABOVE) "above" else "below"
        val kindWord = when (alert.subject) {
            PriceAlertSubject.SYMBOL -> "price"
            PriceAlertSubject.TOKEN -> "token"
            PriceAlertSubject.STRATEGY -> "NAV"
        }
        val body = buildString {
            append(label).append(SP).append(kindWord).append(" crossed ").append(dir).append(SP)
            append(format(alert.priceTicks))
            append(" (now ").append(format(lastValue)).append(RP)
            alert.note?.takeIf { it.isNotBlank() }?.let { append(" - ").append(it) }
        }
        return TradingAlert(
            id = "price:" + alert.id + ":" + alert.triggeredTs,
            kind = TradingAlertKind.PRICE,
            title = label + " " + kindWord + " alert",
            body = body,
            eventTsNs = 0L,
            createdAtMs = now,
        )
    }

    private fun fmt(v: Double): String =
        if (v == v.toLong().toDouble()) v.toLong().toString() else v.toString()

    private fun fmtCents(cents: Long): String {
        val sign = if (cents < 0) "-" else ""
        val abs = kotlin.math.abs(cents)
        return sign + "$" + (abs / 100) + "." + (abs % 100).toString().padStart(2, ZERO)
    }

    private companion object {
        const val SP = ' '
        const val RP = ')'
        const val ZERO = '0'
    }
}
