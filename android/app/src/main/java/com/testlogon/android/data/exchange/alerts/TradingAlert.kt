package com.testlogon.android.data.exchange.alerts

import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.PmResolution

/**
 * The five kinds of trading alert the detector derives from the existing trader feed reads. There is
 * no backend notifications route — each kind is inferred from a new event appearing in one of the
 * polled feeds (fills / liquidations / funding / margin-distress / PM-resolution).
 */
enum class TradingAlertKind { FILL, LIQUIDATION, FUNDING, MARGIN_DISTRESS, PM_RESOLVED, PRICE }

/**
 * One derived, render-ready trading alert. [id] is a stable de-dupe key (kind + event identity) so the
 * same underlying event never produces two alerts across polls; [read] is the local read state.
 *
 * [eventTsNs] is the source event's nanosecond timestamp when the feed carries one (fills/liquidations/
 * funding). Margin-distress and PM-resolution rows carry [eventTsNs] = 0 (no per-event ns on the feed)
 * and are ordered by [createdAtMs] instead. Money amounts are the engine's integer minor units, shown
 * verbatim — the detector does no monetary math.
 */
data class TradingAlert(
    val id: String,
    val kind: TradingAlertKind,
    val title: String,
    val body: String,
    val eventTsNs: Long,
    val createdAtMs: Long,
    val read: Boolean = false,
)

/**
 * The high-water marks the detector remembers between polls so it only emits alerts for genuinely NEW
 * events. Timestamp-keyed feeds (fills/liquidations/funding) advance a max-nanosecond watermark; the
 * margin-distress signal is level-triggered (fires on a rising edge into distress/liquidating) so it
 * remembers the last observed [marginDistressLevel] + [marginLiquidating]; PM-resolutions carry no
 * reliable per-row id so we remember the count seen as the fingerprint.
 *
 * [seeded] distinguishes the very first fetch (seed the marks, emit NOTHING) from steady-state polls.
 */
data class TradingAlertsMarker(
    val seeded: Boolean = false,
    val lastFillTsNs: Long = 0L,
    val lastLiquidationTsNs: Long = 0L,
    val lastFundingTsNs: Long = 0L,
    val marginDistressLevel: Int = 0,
    val marginLiquidating: Boolean = false,
    val pmResolutionCount: Int = 0,
)

/** The immutable inputs the detector reads for one poll (each already degraded-to-empty on 404). */
data class TradingFeeds(
    val fills: FillsFees,
    val liquidations: Liquidations,
    val funding: FundingPayments,
    val margin: MarginAccount?,
    val pmResolutions: List<PmResolution>,
)

/** The detector's output for one poll: the newly-detected alerts + the advanced marker to persist. */
data class TradingAlertsResult(
    val newAlerts: List<TradingAlert>,
    val marker: TradingAlertsMarker,
)

/**
 * Pure new-event detection for trading alerts. Given the current [feeds], the previously-persisted
 * [marker], and a [nowMs] clock, returns the alerts for events not seen before plus the advanced
 * marker. Deterministic and side-effect-free (the single unit-tested seam).
 *
 * De-dupe / seeding rules:
 *  - First call (marker.seeded == false): seed all watermarks from the current feeds and emit NOTHING,
 *    so opening the app never floods with historical fills.
 *  - Timestamp feeds (fills/liquidations/funding): a row is new iff its tsNs > the stored watermark;
 *    the watermark advances to the max tsNs seen.
 *  - Margin distress: level-triggered on a RISING edge — fires only when distressLevel increases or
 *    liquidating flips false->true (not re-firing while it stays elevated).
 *  - PM-resolutions: new iff the feed grew; emits one alert per newly-appeared resolution (tail of the
 *    list), keyed by market label + ts so a re-fetch of the same list never re-fires.
 */
object TradingAlertsDetector {

    fun detect(
        feeds: TradingFeeds,
        marker: TradingAlertsMarker,
        nowMs: Long,
        enabledKinds: Set<TradingAlertKind> = TradingAlertKind.entries.toSet(),
    ): TradingAlertsResult {
        val maxFill = feeds.fills.fills.maxOfOrNull { it.tsNs } ?: 0L
        val maxLiq = feeds.liquidations.events.maxOfOrNull { it.tsNs } ?: 0L
        val maxFund = feeds.funding.payments.maxOfOrNull { it.tsNs } ?: 0L
        val distressLevel = feeds.margin?.distressLevel ?: 0
        val liquidating = feeds.margin?.isLiquidating ?: false
        val pmCount = feeds.pmResolutions.size

        if (!marker.seeded) {
            // First fetch: adopt the current state as the baseline; emit no alerts.
            return TradingAlertsResult(
                newAlerts = emptyList(),
                marker = TradingAlertsMarker(
                    seeded = true,
                    lastFillTsNs = maxFill,
                    lastLiquidationTsNs = maxLiq,
                    lastFundingTsNs = maxFund,
                    marginDistressLevel = distressLevel,
                    marginLiquidating = liquidating,
                    pmResolutionCount = pmCount,
                ),
            )
        }

        val out = ArrayList<TradingAlert>()

        // ---- fills (emitted oldest-new first so read order is chronological) ----
        feeds.fills.fills
            .filter { it.tsNs > marker.lastFillTsNs }
            .sortedBy { it.tsNs }
            .forEach { f ->
                val sideLabel = f.side?.name?.lowercase()?.replaceFirstChar { c -> c.uppercase() } ?: "Filled"
                out += TradingAlert(
                    id = "fill:" + f.symbolId + ":" + f.tsNs + ":" + f.price + ":" + f.qty,
                    kind = TradingAlertKind.FILL,
                    title = "Order filled",
                    body = sideLabel + " " + f.qty + " @ " + f.price + " on #" + f.symbolId + " (fee " + f.fee + ")",
                    eventTsNs = f.tsNs,
                    createdAtMs = nowMs,
                )
            }

        // ---- liquidations ----
        feeds.liquidations.events
            .filter { it.tsNs > marker.lastLiquidationTsNs }
            .sortedBy { it.tsNs }
            .forEach { e ->
                out += TradingAlert(
                    id = "liq:" + e.symbolId + ":" + e.tsNs + ":" + e.qty,
                    kind = TradingAlertKind.LIQUIDATION,
                    title = "Position liquidated",
                    body = "Force-liquidated " + e.qty + " on #" + e.symbolId + " @ " + e.markPrice + " (PnL " + e.realizedPnl + ")",
                    eventTsNs = e.tsNs,
                    createdAtMs = nowMs,
                )
            }

        // ---- funding ----
        feeds.funding.payments
            .filter { it.tsNs > marker.lastFundingTsNs }
            .sortedBy { it.tsNs }
            .forEach { p ->
                val verb = if (p.received) "Received" else "Paid"
                val amt = kotlin.math.abs(p.payment)
                out += TradingAlert(
                    id = "fund:" + p.symbolId + ":" + p.tsNs + ":" + p.payment,
                    kind = TradingAlertKind.FUNDING,
                    title = "Funding " + (if (p.received) "received" else "paid"),
                    body = verb + " funding " + amt + " on #" + p.symbolId + " (" + p.fundingRateBps + " bps)",
                    eventTsNs = p.tsNs,
                    createdAtMs = nowMs,
                )
            }

        // ---- margin distress: rising edge only ----
        val distressRose = distressLevel > marker.marginDistressLevel
        val liquidationEdge = liquidating && !marker.marginLiquidating
        if (distressRose || liquidationEdge) {
            val body = if (liquidating) {
                "Your account is being liquidated (distress level " + distressLevel + ")"
            } else {
                "Margin distress rose to level " + distressLevel + " — top up collateral to avoid liquidation"
            }
            out += TradingAlert(
                // Keyed by the level/flag it rose TO, so the same elevated state never re-fires.
                id = "margin:" + distressLevel + ":" + liquidating,
                kind = TradingAlertKind.MARGIN_DISTRESS,
                title = if (liquidating) "Liquidation in progress" else "Margin distress",
                body = body,
                eventTsNs = 0L,
                createdAtMs = nowMs,
            )
        }

        // ---- PM resolutions: only the rows that newly appeared (list grew) ----
        if (pmCount > marker.pmResolutionCount) {
            feeds.pmResolutions.drop(marker.pmResolutionCount).forEach { r ->
                out += TradingAlert(
                    id = "pm:" + r.marketLabel + ":" + r.outcomeLabel + ":" + r.ts,
                    kind = TradingAlertKind.PM_RESOLVED,
                    title = "Market resolved",
                    body = r.marketLabel + " resolved " + r.outcomeLabel,
                    eventTsNs = 0L,
                    createdAtMs = nowMs,
                )
            }
        }

        // Drop alerts whose kind the user has disabled. The marker still advances below for ALL
        // kinds, so re-enabling a kind never back-fires the events it missed while it was off.
        val emitted = if (enabledKinds.size == TradingAlertKind.entries.size) out
            else out.filterTo(ArrayList()) { it.kind in enabledKinds }

        val nextMarker = marker.copy(
            lastFillTsNs = maxOf(marker.lastFillTsNs, maxFill),
            lastLiquidationTsNs = maxOf(marker.lastLiquidationTsNs, maxLiq),
            lastFundingTsNs = maxOf(marker.lastFundingTsNs, maxFund),
            // Track distress DOWN too, so a later re-rise is a fresh rising edge.
            marginDistressLevel = distressLevel,
            marginLiquidating = liquidating,
            pmResolutionCount = maxOf(marker.pmResolutionCount, pmCount),
        )
        return TradingAlertsResult(newAlerts = emitted, marker = nextMarker)
    }
}
