package com.testlogon.android.data.exchange.alerts

/**
 * Which way the last price must cross the [PriceAlert.priceTicks] threshold to fire.
 *  - [ABOVE]: fires when last price crosses from at/below the threshold to strictly above it.
 *  - [BELOW]: fires when last price crosses from at/above the threshold to strictly below it.
 */
enum class PriceAlertDirection { ABOVE, BELOW }

/**
 * One user-authored price alert. [priceTicks] is the threshold in the symbol's raw integer ticks
 * (parsed from the user's decimal input via the symbol's priceScaler), NOT a display double, so it is
 * compared directly against the raw last-trade price. [armed] is the one-shot latch: an armed alert
 * fires once when the price CROSSES the threshold (edge trigger), which stamps [triggeredTs] and sets
 * [armed] = false so it never re-fires until the user re-arms it.
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
)

/**
 * Pure, deterministic edge-trigger evaluation for a single [PriceAlert] — the unit-tested seam.
 *
 * An armed alert fires when the last price CROSSES its threshold between two consecutive observations
 * (not merely when the price sits on the far side). The caller supplies [prevTicks] (the last price the
 * evaluator saw for this symbol on the previous tick, or null if this is the first observation) and
 * [lastTicks] (the current last price). Crossing is edge-detected so an alert armed while the price is
 * already past the threshold does not immediately fire — it fires only on a genuine crossing.
 *
 * One-shot: on a fire the returned alert has [PriceAlert.armed] = false and [PriceAlert.triggeredTs]
 * stamped with [nowMs]. A disarmed or already-triggered alert never fires; re-arming (armed = true,
 * triggeredTs = null) makes it eligible again.
 */
object PriceAlertEval {

    /**
     * The outcome of evaluating one alert against one price tick: the (possibly updated) [alert] and
     * whether it [fired] on this tick (so the caller can raise a notification exactly once).
     */
    data class Result(val alert: PriceAlert, val fired: Boolean)

    /**
     * Evaluate [alert] given the previous ([prevTicks]) and current ([lastTicks]) last prices.
     *
     *  - Returns the alert unchanged with fired=false when it is not armed, already triggered, or the
     *    price did not cross the threshold this tick.
     *  - On the first observation ([prevTicks] == null) an alert never fires: with no prior price there
     *    is no edge, so opening the app while the price is already past the threshold does not fire.
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

        val threshold = alert.priceTicks
        val crossed = when (alert.direction) {
            PriceAlertDirection.ABOVE -> prevTicks <= threshold && lastTicks > threshold
            PriceAlertDirection.BELOW -> prevTicks >= threshold && lastTicks < threshold
        }
        if (!crossed) return Result(alert, false)

        return Result(
            alert = alert.copy(armed = false, triggeredTs = nowMs),
            fired = true,
        )
    }
}
