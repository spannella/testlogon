package com.testlogon.android.feature.activity

import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.PmResolution

/**
 * The consolidated ACTIVITY CENTER model. A durable, filterable, day-grouped timeline of account
 * events - distinct from transient toasts / notifications. Everything here is PURE (no Android / no
 * coroutines / no I/O): the ViewModel assembles the already-degraded feed reads into [ActivityEvent]s
 * via the per-feed normalizers, then merges / groups / filters through these functions.
 *
 * Money is integer minor units ([amountCents]-style Long), shown verbatim; the model does no monetary
 * math. Timestamps are epoch MILLISECONDS ([ts]) so day-grouping is trivial and the mixed feeds (some
 * carry nanosecond event stamps, some do not) share one comparable axis.
 */

/** Top-level grouping for a filter chip + section colour. */
enum class ActivityCategory { TRADE, FUNDING, LIQUIDATION, RISK, MONEY, SYSTEM }

/** Visual weight of an event (drives icon tint / accent). */
enum class ActivitySeverity { INFO, SUCCESS, WARNING, CRITICAL }

/**
 * One normalized, render-ready account event.
 *
 * [id]        stable de-dupe key (feed-kind + event identity) so one underlying event never appears twice.
 * [ts]        epoch millis used for sort + day-grouping + unread comparison.
 * [kind]      a short machine tag ("FILL" / "FUNDING" / ...) surfaced as a mono badge.
 * [category]  the filter bucket.
 * [title]     one-line headline.
 * [subtitle]  optional detail line.
 * [amountCents] optional signed integer minor-unit amount (verbatim; null when not money-shaped).
 * [route]     optional deep-link target (a MoreRoutes / Dest route string) for tap-through.
 * [severity]  visual weight.
 */
data class ActivityEvent(
    val id: String,
    val ts: Long,
    val kind: String,
    val category: ActivityCategory,
    val title: String,
    val subtitle: String? = null,
    val amountCents: Long? = null,
    val route: String? = null,
    val severity: ActivitySeverity = ActivitySeverity.INFO,
)

/** A day bucket of events (newest day first; events within a day are newest-first). */
data class ActivityDay(
    val dayKey: Long,
    val events: List<ActivityEvent>,
)

/**
 * Pure normalizers + timeline algebra. Kept object-scoped so the whole surface is unit-testable
 * without Hilt / Compose. Deep-link routes are plain strings the caller maps to nav destinations.
 */
object ActivityModel {

    /** Deep-link route strings (kept as literals so this stays Android-free for the JVM test). */
    const val ROUTE_MARKETS = "markets"
    const val ROUTE_TRADING_ALERTS = "markets/alerts"
    const val ROUTE_PORTFOLIO = "portfolio"
    const val ROUTE_WALLET = "wallet"

    private const val MS_PER_DAY = 86_400_000L

    // ---- per-feed normalizers (each already degraded-to-empty on 404 by the repo) ----

    /** Fills feed (me/fills/fees) -> TRADE events. [nowMs] backstops rows the feed left at ts 0. */
    fun fromFills(feed: FillsFees, nowMs: Long): List<ActivityEvent> =
        feed.fills.map { f ->
            val side = f.side?.name?.lowercase()?.replaceFirstChar { it.uppercase() } ?: "Filled"
            ActivityEvent(
                id = "fill:" + f.symbolId + ":" + f.tsNs + ":" + f.price + ":" + f.qty,
                ts = nsToMs(f.tsNs, nowMs),
                kind = "FILL",
                category = ActivityCategory.TRADE,
                title = "Order filled",
                subtitle = side + " " + f.qty + " @ " + f.price + " on #" + f.symbolId + " (fee " + f.fee + ")",
                amountCents = f.fee,
                route = ROUTE_MARKETS,
                severity = if (f.side == OrderSide.SELL) ActivitySeverity.INFO else ActivitySeverity.SUCCESS,
            )
        }

    /** Funding feed (me/funding/payments) -> FUNDING events (signed money). */
    fun fromFunding(feed: FundingPayments, nowMs: Long): List<ActivityEvent> =
        feed.payments.map { p ->
            val verb = if (p.received) "Received" else "Paid"
            val amt = kotlin.math.abs(p.payment)
            ActivityEvent(
                id = "fund:" + p.symbolId + ":" + p.tsNs + ":" + p.payment,
                ts = nsToMs(p.tsNs, nowMs),
                kind = "FUNDING",
                category = ActivityCategory.FUNDING,
                title = "Funding " + (if (p.received) "received" else "paid"),
                subtitle = verb + " " + amt + " on #" + p.symbolId + " (" + p.fundingRateBps + " bps)",
                amountCents = p.payment,
                route = ROUTE_PORTFOLIO,
                severity = if (p.received) ActivitySeverity.SUCCESS else ActivitySeverity.WARNING,
            )
        }

    /** Liquidations feed (me/liquidations) -> LIQUIDATION events (always CRITICAL). */
    fun fromLiquidations(feed: Liquidations, nowMs: Long): List<ActivityEvent> =
        feed.events.map { e ->
            ActivityEvent(
                id = "liq:" + e.symbolId + ":" + e.tsNs + ":" + e.qty,
                ts = nsToMs(e.tsNs, nowMs),
                kind = "LIQUIDATION",
                category = ActivityCategory.LIQUIDATION,
                title = "Position liquidated",
                subtitle = "Force-liquidated " + e.qty + " on #" + e.symbolId + " @ " + e.markPrice + " (PnL " + e.realizedPnl + ")",
                amountCents = e.realizedPnl,
                route = ROUTE_PORTFOLIO,
                severity = ActivitySeverity.CRITICAL,
            )
        }

    /**
     * Margin account (me/margin) -> at most ONE current RISK event when the account is in distress /
     * being liquidated. Level-triggered snapshot (not a feed), so it is keyed by the current level/flag
     * and stamped [nowMs]; a healthy account (null margin or level 0) contributes nothing.
     */
    fun fromMargin(margin: MarginAccount?, nowMs: Long): List<ActivityEvent> {
        if (margin == null) return emptyList()
        val level = margin.distressLevel
        val liquidating = margin.isLiquidating
        if (level <= 0 && !liquidating) return emptyList()
        val subtitle = if (liquidating) {
            "Your account is being liquidated (distress level " + level + ")"
        } else {
            "Margin distress at level " + level + " - top up collateral to avoid liquidation"
        }
        return listOf(
            ActivityEvent(
                id = "margin:" + level + ":" + liquidating,
                ts = nowMs,
                kind = "RISK",
                category = ActivityCategory.RISK,
                title = if (liquidating) "Liquidation in progress" else "Margin distress",
                subtitle = subtitle,
                route = ROUTE_PORTFOLIO,
                severity = ActivitySeverity.CRITICAL,
            ),
        )
    }

    /** PM resolutions (admin/pm resolutions log) -> SYSTEM events. [ts] is seconds on the wire. */
    fun fromPmResolutions(resolutions: List<PmResolution>, nowMs: Long): List<ActivityEvent> =
        resolutions.map { r ->
            ActivityEvent(
                id = "pm:" + r.marketLabel + ":" + r.outcomeLabel + ":" + r.ts,
                ts = if (r.ts > 0L) r.ts * 1000L else nowMs,
                kind = "RESOLVED",
                category = ActivityCategory.SYSTEM,
                title = "Market resolved",
                subtitle = r.marketLabel + " resolved " + r.outcomeLabel,
                route = ROUTE_MARKETS,
                severity = ActivitySeverity.INFO,
            )
        }

    // ---- timeline algebra ----

    /**
     * Merge any number of already-normalized event lists into one timeline: de-duped by [ActivityEvent.id]
     * (first occurrence wins) and sorted newest-first ([ts] desc, id desc as a stable tiebreak). Pure.
     */
    fun mergeEvents(vararg sources: List<ActivityEvent>): List<ActivityEvent> =
        mergeEvents(sources.asList())

    fun mergeEvents(sources: List<List<ActivityEvent>>): List<ActivityEvent> {
        val seen = HashSet<String>()
        val merged = ArrayList<ActivityEvent>()
        sources.forEach { list ->
            list.forEach { e -> if (seen.add(e.id)) merged += e }
        }
        merged.sortWith(compareByDescending<ActivityEvent> { it.ts }.thenByDescending { it.id })
        return merged
    }

    /** Filter to a single category, or return the input unchanged when [category] is null (== All). */
    fun filterByCategory(events: List<ActivityEvent>, category: ActivityCategory?): List<ActivityEvent> =
        if (category == null) events else events.filter { it.category == category }

    /**
     * Group a (typically already newest-first) event list into day buckets. Each bucket carries the
     * day-start epoch-millis [ActivityDay.dayKey] (UTC-day, derived by integer division so the model
     * stays timezone-free / deterministic). Days are newest-first; within a day, newest-first.
     */
    fun groupByDay(events: List<ActivityEvent>): List<ActivityDay> =
        events
            .groupBy { dayKeyOf(it.ts) }
            .map { (day, evs) -> ActivityDay(day, evs.sortedWith(compareByDescending<ActivityEvent> { it.ts }.thenByDescending { it.id })) }
            .sortedByDescending { it.dayKey }

    /** UTC-day-start epoch millis for [ts] (deterministic; used as a group key). */
    fun dayKeyOf(ts: Long): Long = (ts / MS_PER_DAY) * MS_PER_DAY

    /** How many events are strictly newer than [lastSeenTs] (the unread badge count). */
    fun unreadCount(events: List<ActivityEvent>, lastSeenTs: Long): Int =
        events.count { it.ts > lastSeenTs }

    /** The newest event timestamp (what "mark all read" persists), or 0 when empty. */
    fun newestTs(events: List<ActivityEvent>): Long = events.maxOfOrNull { it.ts } ?: 0L

    // ---- helpers ----

    /** Nanosecond event stamp -> millis; falls back to [nowMs] when the feed left it at 0. */
    private fun nsToMs(tsNs: Long, nowMs: Long): Long = if (tsNs > 0L) tsNs / 1_000_000L else nowMs
}
