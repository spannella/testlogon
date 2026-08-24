package com.testlogon.android.feature.dca

import com.testlogon.android.data.dca.DcaFrequency
import com.testlogon.android.data.dca.DcaPlan
import com.testlogon.android.data.dca.DcaStatus

/**
 * PURE, Android-free schedule + budget math for DCA / RECURRING BUYS. Kept out of the ViewModel so the
 * next-run / upcoming-runs / budget rules are JVM-unit testable without Compose / Hilt / java.time.
 *
 * Design (mirrors EventSlotter's discipline): NO java.time, NO Android. All date math is done in UTC on
 * epoch-millis via a tiny proleptic-Gregorian civil-date conversion (days-from-epoch <-> y/m/d). This is
 * deterministic and desugaring-free. Callers own display-zone formatting; scheduling here is UTC-day
 * granular, which is exactly what a once-per-day/week/month runner needs.
 *
 * Money is integer CENTS throughout. Day-of-week is 1=Mon..7=Sun (ISO). Day-of-month is 1..31 but is
 * CAPPED at 28 at scheduling time so a plan never skips short months (Feb) — per the contract.
 */
object DcaSchedule {

    const val MS_PER_DAY: Long = 86_400_000L
    const val DAY_OF_MONTH_CAP: Int = 28
    const val DEFAULT_PREVIEW_RUNS: Int = 5

    // ---- civil-date <-> days-from-epoch (Howard Hinnant's algorithm; proleptic Gregorian, UTC) ----

    private data class Civil(val year: Long, val month: Int, val day: Int)

    /** Floor-divide epoch-ms to whole UTC days since 1970-01-01. */
    private fun epochDay(ms: Long): Long = Math.floorDiv(ms, MS_PER_DAY)

    /** Start-of-UTC-day epoch-ms for a given days-from-epoch. */
    private fun dayStartMs(days: Long): Long = days * MS_PER_DAY

    /** days-from-epoch -> civil date (UTC). */
    private fun toCivil(days: Long): Civil {
        val z = days + 719_468L
        val era = (if (z >= 0) z else z - 146_096) / 146_097
        val doe = z - era * 146_097 // [0, 146096]
        val yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365 // [0, 399]
        val y = yoe + era * 400
        val doy = doe - (365 * yoe + yoe / 4 - yoe / 100) // [0, 365]
        val mp = (5 * doy + 2) / 153 // [0, 11]
        val d = (doy - (153 * mp + 2) / 5 + 1).toInt() // [1, 31]
        val m = (if (mp < 10) mp + 3 else mp - 9).toInt() // [1, 12]
        return Civil(year = if (m <= 2) y + 1 else y, month = m, day = d)
    }

    /** civil date (UTC) -> days-from-epoch. */
    private fun fromCivil(year: Long, month: Int, day: Int): Long {
        val y = if (month <= 2) year - 1 else year
        val era = (if (y >= 0) y else y - 399) / 400
        val yoe = y - era * 400 // [0, 399]
        val doy = (153 * (if (month > 2) month - 3 else month + 9) + 2) / 5 + (day - 1) // [0, 365]
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy // [0, 146096]
        return era * 146_097 + doe - 719_468
    }

    /** ISO day-of-week for a days-from-epoch value: 1=Mon..7=Sun. 1970-01-01 was a Thursday (=4). */
    private fun isoDowFromDays(days: Long): Int {
        val r = Math.floorMod(days + 3, 7L).toInt() // shift so Monday=0
        return r + 1
    }

    /** Days in [month] of [year] (UTC / proleptic Gregorian). */
    private fun daysInMonth(year: Long, month: Int): Int {
        val nextMonthYear = if (month == 12) year + 1 else year
        val nextMonth = if (month == 12) 1 else month + 1
        return (fromCivil(nextMonthYear, nextMonth, 1) - fromCivil(year, month, 1)).toInt()
    }

    // ---- validation ----

    sealed interface Validation {
        data object Ok : Validation
        data class Invalid(val reason: String) : Validation
    }

    /**
     * Validate a candidate plan's SCHEDULE + money fields (kind-agnostic; target existence is the picker's
     * job). Enforces: positive amount, a known frequency with its required day part, a start, an end (if
     * set) strictly after start, and a total budget (if set) at least one buy.
     */
    fun validatePlan(
        amountCents: Long,
        frequency: DcaFrequency,
        dayOfWeek: Int?,
        dayOfMonth: Int?,
        startTs: Long,
        endTs: Long?,
        totalBudgetCents: Long?,
    ): Validation {
        if (amountCents <= 0L) return Validation.Invalid("Enter a buy amount greater than \$0.")
        if (startTs <= 0L) return Validation.Invalid("Pick a start date.")
        when (frequency) {
            DcaFrequency.WEEKLY -> if (dayOfWeek == null || dayOfWeek !in 1..7) {
                return Validation.Invalid("Pick a day of the week.")
            }
            DcaFrequency.MONTHLY -> if (dayOfMonth == null || dayOfMonth !in 1..31) {
                return Validation.Invalid("Pick a day of the month.")
            }
            DcaFrequency.DAILY -> Unit
            DcaFrequency.UNKNOWN -> return Validation.Invalid("Pick a frequency.")
        }
        if (endTs != null && endTs <= startTs) return Validation.Invalid("End date must be after the start date.")
        if (totalBudgetCents != null && totalBudgetCents < amountCents) {
            return Validation.Invalid("Total budget must cover at least one buy.")
        }
        return Validation.Ok
    }

    // ---- next-run / upcoming-runs ----

    /**
     * The next scheduled run at or after [fromMs] for [plan], or null when the plan will never run again
     * (terminal status, past its end, or budget exhausted). Runs land at the START of the scheduled UTC day.
     */
    fun nextRun(plan: DcaPlan, fromMs: Long): Long? {
        if (plan.status == DcaStatus.CANCELLED || plan.status == DcaStatus.COMPLETED) return null
        if (plan.frequency == DcaFrequency.UNKNOWN) return null
        if (plan.amountCents <= 0L) return null
        if (budgetRemainingCents(plan)?.let { it < plan.amountCents } == true) return null

        // The search floor is the later of the plan start and the requested from-time, aligned to day.
        val floorMs = maxOf(plan.startTs, fromMs)
        val floorDay = epochDay(floorMs)
        val startDay = epochDay(plan.startTs)
        val baseFloorDay = maxOf(floorDay, startDay)

        val runDay: Long = when (plan.frequency) {
            DcaFrequency.DAILY -> baseFloorDay
            DcaFrequency.WEEKLY -> {
                val target = (plan.dayOfWeek ?: return null).coerceIn(1, 7)
                val delta = Math.floorMod((target - isoDowFromDays(baseFloorDay)).toLong(), 7L)
                baseFloorDay + delta
            }
            DcaFrequency.MONTHLY -> {
                val targetDom = (plan.dayOfMonth ?: return null).coerceIn(1, 31).coerceAtMost(DAY_OF_MONTH_CAP)
                var probe = baseFloorDay
                var result: Long = -1
                var guard = 0
                while (guard < 480) { // up to 40 years of months, ample
                    val c = toCivil(probe)
                    val dom = targetDom.coerceAtMost(daysInMonth(c.year, c.month))
                    val candidate = fromCivil(c.year, c.month, dom)
                    if (candidate >= baseFloorDay) {
                        result = candidate
                        break
                    }
                    // move probe to the 1st of next month
                    val ny = if (c.month == 12) c.year + 1 else c.year
                    val nm = if (c.month == 12) 1 else c.month + 1
                    probe = fromCivil(ny, nm, 1)
                    guard++
                }
                if (result < 0) return null
                result
            }
            DcaFrequency.UNKNOWN -> return null
        }

        val runMs = dayStartMs(runDay)
        if (plan.endTs != null && runMs > plan.endTs) return null
        return runMs
    }

    /**
     * The next [n] scheduled runs at or after [fromMs] (respecting start / end / budget), earliest first.
     * Fewer than [n] entries when the plan completes (end reached or budget exhausted) sooner.
     */
    fun upcomingRuns(plan: DcaPlan, fromMs: Long, n: Int = DEFAULT_PREVIEW_RUNS): List<Long> {
        if (n <= 0) return emptyList()
        val out = ArrayList<Long>(n)
        // Track a shrinking budget so previews stop when funds run out.
        var remaining = budgetRemainingCents(plan)
        var cursor = fromMs
        var guard = 0
        while (out.size < n && guard < n * 32 + 64) {
            guard++
            if (remaining != null && remaining < plan.amountCents) break
            val next = nextRun(plan, cursor) ?: break
            out.add(next)
            if (remaining != null) remaining -= plan.amountCents
            // advance the cursor a full day past this run so the next search moves to a later day
            cursor = next + MS_PER_DAY
        }
        return out
    }

    // ---- budget ----

    /**
     * Cents left in the plan's total budget = total_budget - spent (>= 0), or null when the plan has no
     * total-budget cap (runs indefinitely until end/cancel).
     */
    fun budgetRemainingCents(plan: DcaPlan): Long? {
        val total = plan.totalBudgetCents ?: return null
        return (total - plan.spentCents).coerceAtLeast(0L)
    }

    /**
     * How many more buys the remaining budget funds, or null when uncapped. Integer floor of
     * remaining / amount; 0 when a buy no longer fits.
     */
    fun estimatedRunsRemaining(plan: DcaPlan): Int? {
        val remaining = budgetRemainingCents(plan) ?: return null
        if (plan.amountCents <= 0L) return 0
        return (remaining / plan.amountCents).toInt()
    }

    /** Budget progress in [0f, 1f] (spent / total), or null when uncapped. Guards a zero/negative total. */
    fun budgetProgress(plan: DcaPlan): Float? {
        val total = plan.totalBudgetCents ?: return null
        if (total <= 0L) return null
        return (plan.spentCents.toDouble() / total.toDouble()).coerceIn(0.0, 1.0).toFloat()
    }
}
