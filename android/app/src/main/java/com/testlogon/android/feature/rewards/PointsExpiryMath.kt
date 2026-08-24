package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.PointsExpiry
import com.testlogon.android.data.rewards.PointsExpiryLot
import com.testlogon.android.data.rewards.RewardsHistoryEntry
import java.util.Calendar
import java.util.TimeZone

/**
 * Pure, Android-free math + formatting for the POINTS STATEMENT + POINTS EXPIRY surface. Kept out of the
 * ViewModel so the FIFO lot-consumption, expiry policy and running-balance projection are unit testable
 * without Compose/Hilt. Points are integers throughout; timestamps are epoch millis (UTC for calendar
 * math). Everything is total and guards the empty case (empty history -> empty result, never a throw).
 *
 * CANONICAL POLICY (mirrors web): points expire [EXPIRY_MONTHS] = 12 months after they are EARNED, and
 * a lot is "expiring soon" when it expires within [EXPIRING_SOON_DAYS] = 60 days of now.
 *
 * EARN vs SPEND: a history entry with points > 0 is an EARN (opens a FIFO lot); points < 0 is a SPEND
 * (redeem / expire / adjust) that consumes the OLDEST open lots first. Remaining (unspent) lots expire
 * at earnedTs + [EXPIRY_MONTHS]; a lot already past its expiry as of nowMs is dropped from the
 * upcoming-expirations view (its points are treated as already gone).
 */
object PointsExpiryMath {

    /** Points expire this many months after they are earned. Canonical policy (mirrors web). */
    const val EXPIRY_MONTHS: Int = 12

    /** A lot is "expiring soon" when it expires within this many days of now. Canonical policy. */
    const val EXPIRING_SOON_DAYS: Int = 60

    private const val DAY_MS: Long = 24L * 60L * 60L * 1000L

    // ---- Calendar ----

    /**
     * Add [months] calendar months to the UTC instant [ms], clamping the day-of-month (e.g. Jan 31 + 1mo
     * -> Feb 28/29). Pure + deterministic (fixed UTC zone) so expiry dates are stable across devices.
     */
    fun addMonths(ms: Long, months: Int): Long {
        val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        cal.timeInMillis = ms
        cal.add(Calendar.MONTH, months)
        return cal.timeInMillis
    }

    // ---- FIFO expiry computation ----

    /**
     * An open (unspent) earn lot: [pointsRemaining] of the original earn still live, expiring at
     * [expiresTs] (= earnedTs + policyMonths). Sorted oldest-earned first by the computation.
     */
    data class Lot(val earnedTs: Long, val pointsRemaining: Long, val expiresTs: Long) {
        fun toDomain(): PointsExpiryLot = PointsExpiryLot(earnedTs, pointsRemaining, expiresTs)
    }

    /** The client-computed expiry picture: still-live lots + the expiring-soon total + the next expiry. */
    data class Expiry(
        val policyMonths: Int,
        val lots: List<Lot>,
        val expiringSoonPoints: Long,
        val nextExpiryTs: Long,
        val nextExpiryPoints: Long,
    ) {
        val livePoints: Long get() = lots.sumOf { it.pointsRemaining }
    }

    /**
     * Compute the FIFO expiry picture from the rewards [entries] as of [nowMs]. Earn entries (points > 0)
     * open lots in chronological order; spend entries (points < 0) consume the OLDEST open lots first.
     * Each surviving lot expires at earnedTs + [policyMonths] months; lots whose expiry is at/before
     * [nowMs] are dropped (already expired). Returns the still-live lots (sorted by expiry, soonest
     * first), the total points expiring within [EXPIRING_SOON_DAYS], and the very next expiry (ts+points).
     */
    fun computeExpiryFromHistory(
        entries: List<RewardsHistoryEntry>,
        nowMs: Long,
        policyMonths: Int = EXPIRY_MONTHS,
    ): Expiry {
        val months = policyMonths.coerceAtLeast(0)
        // Mutable FIFO queue of open earn lots (oldest earn first).
        val open = ArrayDeque<Lot>()
        // Process in chronological order (ties keep input order via a stable sort on ts).
        val ordered = entries.sortedBy { it.ts }
        for (e in ordered) {
            val pts = e.points
            when {
                pts > 0L -> open.addLast(Lot(earnedTs = e.ts, pointsRemaining = pts, expiresTs = addMonths(e.ts, months)))
                pts < 0L -> consume(open, -pts)
                else -> Unit // zero-point activity (e.g. informational) never touches lots
            }
        }
        // Drop already-expired lots; keep live ones sorted soonest-expiry first.
        val live = open
            .filter { it.pointsRemaining > 0L && it.expiresTs > nowMs }
            .sortedWith(compareBy({ it.expiresTs }, { it.earnedTs }))

        val soonCutoff = nowMs + EXPIRING_SOON_DAYS.toLong() * DAY_MS
        val expiringSoon = live.filter { it.expiresTs <= soonCutoff }.sumOf { it.pointsRemaining }

        // Next expiry = the group of lots sharing the soonest expiry ts (their points summed).
        val soonestTs = live.firstOrNull()?.expiresTs ?: 0L
        val nextPoints = if (soonestTs > 0L) live.filter { it.expiresTs == soonestTs }.sumOf { it.pointsRemaining } else 0L

        return Expiry(
            policyMonths = months,
            lots = live,
            expiringSoonPoints = expiringSoon,
            nextExpiryTs = soonestTs,
            nextExpiryPoints = nextPoints,
        )
    }

    /** Consume [amount] points from the oldest open lots first (FIFO), mutating the queue in place. */
    private fun consume(open: ArrayDeque<Lot>, amount: Long) {
        var remaining = amount
        while (remaining > 0L && open.isNotEmpty()) {
            val head = open.first()
            if (head.pointsRemaining <= remaining) {
                remaining -= head.pointsRemaining
                open.removeFirst()
            } else {
                open[0] = head.copy(pointsRemaining = head.pointsRemaining - remaining)
                remaining = 0L
            }
        }
        // If remaining > 0 the spend exceeds tracked earns (thin/partial history): nothing left to consume.
    }

    // ---- Statement (running balance) ----

    /**
     * One row of the points statement: an activity entry with the [runningBalance] AFTER it is applied.
     * [delta] is the signed points change; [balanceBefore] is the running total before this entry.
     */
    data class StatementRow(
        val ts: Long,
        val type: String,
        val description: String,
        val delta: Long,
        val balanceBefore: Long,
        val runningBalance: Long,
    )

    /**
     * Project the running-balance statement from [entries]. Rows are returned NEWEST FIRST (most recent
     * activity on top) but the running balance is accumulated in chronological order so each row's
     * [runningBalance] is the true balance as of that entry. Empty history -> empty list.
     */
    fun statementRows(entries: List<RewardsHistoryEntry>): List<StatementRow> {
        if (entries.isEmpty()) return emptyList()
        val ordered = entries.sortedBy { it.ts }
        var balance = 0L
        val chrono = ArrayList<StatementRow>(ordered.size)
        for (e in ordered) {
            val before = balance
            balance += e.points
            chrono.add(
                StatementRow(
                    ts = e.ts,
                    type = e.type,
                    description = e.description,
                    delta = e.points,
                    balanceBefore = before,
                    runningBalance = balance,
                )
            )
        }
        return chrono.asReversed()
    }

    // ---- Period filter ----

    /** Statement period filter for the surface. Pure UTC-year/month boundaries so it is testable. */
    enum class StatementPeriod { ALL, THIS_YEAR, THIS_MONTH }

    /**
     * Filter statement [rows] to the [period] relative to [nowMs] (UTC). ALL returns everything; THIS_YEAR
     * keeps rows whose ts is in the same UTC calendar year as now; THIS_MONTH keeps the same UTC year+month.
     * Rows with a non-positive ts are only kept under ALL (undated activity can't be placed in a period).
     */
    fun filterByPeriod(rows: List<StatementRow>, period: StatementPeriod, nowMs: Long): List<StatementRow> {
        if (period == StatementPeriod.ALL) return rows
        val (nowYear, nowMonth) = yearMonthUtc(nowMs)
        return rows.filter { r ->
            if (r.ts <= 0L) return@filter false
            val (y, m) = yearMonthUtc(r.ts)
            when (period) {
                StatementPeriod.THIS_YEAR -> y == nowYear
                StatementPeriod.THIS_MONTH -> y == nowYear && m == nowMonth
                StatementPeriod.ALL -> true
            }
        }
    }

    private fun yearMonthUtc(ms: Long): Pair<Int, Int> {
        val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        cal.timeInMillis = ms
        return cal.get(Calendar.YEAR) to (cal.get(Calendar.MONTH) + 1)
    }

    // ---- CSV export ----

    /**
     * Build a CSV of the statement [rows] (already period-filtered by the caller, newest first). Header:
     * date,type,description,points,running_balance. Descriptions are quoted + inner quotes doubled so a
     * comma/quote never breaks a column. Empty rows -> header only (an honest empty export, never a throw).
     */
    fun expiryToCsv(rows: List<StatementRow>): String {
        val sb = StringBuilder()
        sb.append("date,type,description,points,running_balance\n")
        for (r in rows) {
            sb.append(formatDateUtc(r.ts)).append(',')
            sb.append(csvField(r.type)).append(',')
            sb.append(csvField(r.description)).append(',')
            sb.append(signed(r.delta)).append(',')
            sb.append(r.runningBalance).append('\n')
        }
        return sb.toString()
    }

    private fun csvField(raw: String): String {
        val v = raw.replace("\"", "\"\"")
        return "\"" + v + "\""
    }

    // ---- Formatting ----

    /** Signed integer points ("+250" / "-100" / "0"). */
    fun signed(points: Long): String = if (points > 0L) "+$points" else points.toString()

    /** Signed grouped points for the UI ("+1,250 pts" / "-100 pts"). Reuses RewardsMath grouping. */
    fun signedPointsLabel(points: Long): String {
        val sign = if (points > 0L) "+" else if (points < 0L) "-" else ""
        return sign + RewardsMath.formatPoints(kotlin.math.abs(points))
    }

    /** Format an epoch-millis instant as an ISO date (UTC), "yyyy-MM-dd". Empty for a non-positive ts. */
    fun formatDateUtc(ms: Long): String {
        if (ms <= 0L) return ""
        val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        cal.timeInMillis = ms
        val y = cal.get(Calendar.YEAR)
        val mo = cal.get(Calendar.MONTH) + 1
        val d = cal.get(Calendar.DAY_OF_MONTH)
        return "%04d-%02d-%02d".format(y, mo, d)
    }

    /**
     * Merge the OPTIONAL authoritative [PointsExpiry] with the client [Expiry] computation. When the
     * authoritative read is available AND non-empty it wins (server is the source of truth); otherwise
     * the client computation is used and [Resolved.estimated] is true so the UI can badge "Est.".
     */
    data class Resolved(
        val policyMonths: Int,
        val lots: List<PointsExpiryLot>,
        val expiringSoonPoints: Long,
        val nextExpiryTs: Long,
        val nextExpiryPoints: Long,
        val estimated: Boolean,
    )

    fun resolve(authoritative: PointsExpiry?, client: Expiry): Resolved {
        val useAuthoritative = authoritative != null && authoritative.available &&
            (authoritative.lots.isNotEmpty() || authoritative.expiringSoonPoints > 0L || authoritative.nextExpiryPoints > 0L)
        return if (useAuthoritative && authoritative != null) {
            Resolved(
                policyMonths = if (authoritative.policyMonths > 0) authoritative.policyMonths else EXPIRY_MONTHS,
                lots = authoritative.lots,
                expiringSoonPoints = authoritative.expiringSoonPoints,
                nextExpiryTs = authoritative.nextExpiryTs,
                nextExpiryPoints = authoritative.nextExpiryPoints,
                estimated = false,
            )
        } else {
            Resolved(
                policyMonths = client.policyMonths,
                lots = client.lots.map { it.toDomain() },
                expiringSoonPoints = client.expiringSoonPoints,
                nextExpiryTs = client.nextExpiryTs,
                nextExpiryPoints = client.nextExpiryPoints,
                estimated = true,
            )
        }
    }
}
