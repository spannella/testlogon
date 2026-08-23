package com.testlogon.android.data.exchange.alerts

/**
 * Which way the observed value must cross the [PriceAlert.priceTicks] threshold to fire.
 *  - [ABOVE]: fires when the value crosses from at/below the threshold to strictly above it.
 *  - [BELOW]: fires when the value crosses from at/above the threshold to strictly below it.
 */
enum class PriceAlertDirection { ABOVE, BELOW }

/**
 * What an alert watches. EXTENDS the original symbol-only alerts (mirrors the parallel web change):
 *  - [SYMBOL]: an exchange instrument last price (raw integer ticks, scaled by the symbol scaler).
 *  - [TOKEN]: a creator revenue-share token last/clearing price (integer CENTS).
 *  - [STRATEGY]: a strategy fund NAV per unit (integer CENTS).
 * The comparison in every case is a pure integer edge-cross against [PriceAlert.priceTicks].
 */
enum class PriceAlertSubject { SYMBOL, TOKEN, STRATEGY }

/**
 * One user-authored price alert. Generalized over a [subject] kind:
 *  - For [PriceAlertSubject.SYMBOL] the subject is [symbolId] and [priceTicks] is the threshold in the
 *    symbol raw integer ticks (parsed via the symbol priceScaler).
 *  - For [PriceAlertSubject.TOKEN] / [PriceAlertSubject.STRATEGY] the subject is [subjectId] (the token
 *    id / strategy id) and [priceTicks] is the threshold in integer CENTS (token last/clearing price,
 *    or strategy NAV per unit).
 *
 * [subjectId] is the canonical subject key for all kinds; for a SYMBOL alert it is the symbolId as a
 * string (kept in sync with the legacy [symbolId] field for backward compatibility). [subjectLabel] is
 * a cached human ticker/name for rendering when the live catalogue cannot resolve the id.
 *
 * [armed] is the one-shot latch: an armed alert fires once when the value CROSSES the threshold (edge
 * trigger), which stamps [triggeredTs] and sets [armed] = false so it never re-fires until re-armed.
 */
data class PriceAlert(
    val id: String,
    val symbolId: Int,
    val direction: PriceAlertDirection,
    val priceTicks: Long,
    val note: String? = null,
    val createdTs: Long,
    val triggeredTs: Long? = null,
    val armed: Boolean = true,
    val subject: PriceAlertSubject = PriceAlertSubject.SYMBOL,
    val subjectId: String = symbolId.toString(),
    val subjectLabel: String? = null,
)

/**
 * Pure, deterministic edge-trigger evaluation for a single [PriceAlert] — the unit-tested seam.
 *
 * An armed alert fires when the value CROSSES its threshold between two consecutive observations
 * (not merely when the value sits on the far side). The caller supplies [prevTicks] (the value the
 * evaluator saw for this subject on the previous tick, or null if this is the first observation) and
 * [lastTicks] (the current value). Crossing is edge-detected so an alert armed while the value is
 * already past the threshold does not immediately fire — it fires only on a genuine crossing.
 *
 * One-shot: on a fire the returned alert has [PriceAlert.armed] = false and [PriceAlert.triggeredTs]
 * stamped with [nowMs]. A disarmed or already-triggered alert never fires; re-arming (armed = true,
 * triggeredTs = null) makes it eligible again.
 */
object PriceAlertEval {

    /**
     * The outcome of evaluating one alert against one observation: the (possibly updated) [alert] and
     * whether it [fired] on this tick (so the caller can raise a notification exactly once).
     */
    data class Result(val alert: PriceAlert, val fired: Boolean)

    /**
     * Evaluate [alert] given the previous ([prevTicks]) and current ([lastTicks]) observed values.
     *
     *  - Returns the alert unchanged with fired=false when it is not armed, already triggered, or the
     *    value did not cross the threshold this tick.
     *  - On the first observation ([prevTicks] == null) an alert never fires.
     *  - ABOVE crosses when prev <= threshold < last. BELOW crosses when prev >= threshold > last.
     */
    fun evaluate(
        alert: PriceAlert,
        prevTicks: Long?,
        lastTicks: Long,
        nowMs: Long,
    ): Result {
        if (!alert.armed || alert.triggeredTs != null) return Result(alert, false)
        if (prevTicks == null) return Result(alert, false)
        if (!alertCrossed(prevTicks, lastTicks, alert.direction, alert.priceTicks)) {
            return Result(alert, false)
        }
        return Result(alert = alert.copy(armed = false, triggeredTs = nowMs), fired = true)
    }
}

/**
 * PURE edge-trigger predicate shared by the evaluator and the unit tests: did the value cross the
 * [target] this observation, in the [condition] direction?
 *  - [PriceAlertDirection.ABOVE]: true when prev <= target && curr > target.
 *  - [PriceAlertDirection.BELOW]: true when prev >= target && curr < target.
 * Edge-detected, so a value that was already past the target and stays there does NOT cross.
 */
fun alertCrossed(prev: Long, curr: Long, condition: PriceAlertDirection, target: Long): Boolean =
    when (condition) {
        PriceAlertDirection.ABOVE -> prev <= target && curr > target
        PriceAlertDirection.BELOW -> prev >= target && curr < target
    }

/**
 * PURE human label for an alert across all subject kinds, e.g. "BTC above 65000" or "ACME token below
 * 250". [subjectName] is the resolved ticker/name (falls back to the alert cached [PriceAlert.subjectLabel]
 * then to a "#id" form). [formatTarget] renders the integer threshold for the subject (symbol scaler /
 * cents), defaulting to the raw integer when omitted.
 */
fun alertLabel(
    alert: PriceAlert,
    subjectName: String? = null,
    formatTarget: (Long) -> String = { it.toString() },
): String {
    val name = subjectName
        ?: alert.subjectLabel?.takeIf { it.isNotBlank() }
        ?: ("#" + alert.subjectId)
    val kindTag = when (alert.subject) {
        PriceAlertSubject.SYMBOL -> ""
        PriceAlertSubject.TOKEN -> " token"
        PriceAlertSubject.STRATEGY -> " NAV"
    }
    val dir = if (alert.direction == PriceAlertDirection.ABOVE) "above" else "below"
    return name + kindTag + " " + dir + " " + formatTarget(alert.priceTicks)
}
