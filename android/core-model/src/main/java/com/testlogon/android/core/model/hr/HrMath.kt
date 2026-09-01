package com.testlogon.android.core.model.hr

/**
 * HRM-009 (Android) — pure (framework-free) HR / payroll arithmetic + formatting helpers.
 *
 * Deliberately has NO Android / network / coroutine / java.time dependency so it is unit-testable on the
 * plain JVM (see HrMathTest). All money is integer *_cents; there is NO float money arithmetic.
 *
 * Mirrors the backend contract (app/routers/hr.py, app/services/hr_payroll.py) + the web contract
 * (frontend/src/api/endpoints/hr.ts):
 *  - Money is integer cents + ISO-4217 currency.
 *  - Dates/timestamps are epoch-SECONDS.
 *  - A payroll run's gross total is the sum of its line gross_cents (single currency per run).
 */
object HrMath {

    const val SECONDS_PER_DAY: Long = 86_400L
    private const val DAYS_PER_YEAR = 365.25
    private const val DAYS_PER_MONTH = 30.4375 // 365.25 / 12

    /**
     * Sum the gross cents of a set of payroll lines. Callers should pass lines of ONE currency (a run is
     * single-currency); this sums the raw cents regardless. Empty -> 0.
     */
    fun totalGrossCents(lines: List<PayrollLine>): Long =
        lines.fold(0L) { acc, ln -> acc + ln.gross.cents }

    /**
     * The gross total of a payroll run as [HrMoney]. Currency is taken from the first line, falling back
     * to [fallbackCurrency] when the run has no lines. Never throws.
     */
    fun runGrossTotal(run: PayrollRun, fallbackCurrency: String = "USD"): HrMoney {
        val currency = run.lines.firstOrNull()?.gross?.currency ?: fallbackCurrency
        return HrMoney(totalGrossCents(run.lines), currency)
    }

    /**
     * Format integer cents as a plain major-unit decimal string with 2 fraction digits and the currency
     * code appended, e.g. 123456 / "USD" -> "1234.56 USD". Locale-independent (no grouping) so it is
     * deterministic in tests; the screen may re-format with the device locale. Negative cents are
     * rendered with a leading '-'.
     */
    fun formatMoney(money: HrMoney): String {
        val cents = money.cents
        val negative = cents < 0
        val abs = if (negative) -cents else cents
        val major = abs / 100
        val minor = abs % 100
        val sign = if (negative) "-" else ""
        val minorStr = if (minor < 10) "0$minor" else minor.toString()
        return "$sign$major.$minorStr ${money.currency.uppercase()}"
    }

    /**
     * Whole days between [startEpochSeconds] and an end (or "now"). Returns null when the start is null or
     * in the future relative to the end. Uses floor division on the second delta.
     */
    fun tenureDays(startEpochSeconds: Long?, endEpochSeconds: Long?, nowEpochSeconds: Long): Long? {
        if (startEpochSeconds == null || startEpochSeconds <= 0) return null
        val end = endEpochSeconds ?: nowEpochSeconds
        val delta = end - startEpochSeconds
        if (delta < 0) return null
        return delta / SECONDS_PER_DAY
    }

    /**
     * Human tenure label from a day count, e.g. "0 days", "1 day", "3 months", "1 year", "2 years, 4
     * months". Returns null for a null day count. 1..29 days -> "N day(s)"; <1 year -> "N month(s)";
     * >=1 year -> "Y year(s)[, M month(s)]".
     */
    fun tenureLabel(days: Long?): String? {
        if (days == null) return null
        if (days < 0) return null
        if (days < 30) return "$days ${plural(days, "day")}"
        val years = (days / DAYS_PER_YEAR).toLong()
        if (years < 1) {
            val months = (days / DAYS_PER_MONTH).toLong().coerceAtLeast(1)
            return "$months ${plural(months, "month")}"
        }
        val remainderDays = days - (years * DAYS_PER_YEAR).toLong()
        val months = (remainderDays / DAYS_PER_MONTH).toLong()
        val yearPart = "$years ${plural(years, "year")}"
        return if (months <= 0) yearPart else "$yearPart, $months ${plural(months, "month")}"
    }

    /** Convenience: tenure label directly from an employment's dates. */
    fun employmentTenureLabel(employment: Employment, nowEpochSeconds: Long): String? =
        tenureLabel(
            tenureDays(
                employment.startDateEpochSeconds,
                employment.endDateEpochSeconds,
                nowEpochSeconds,
            ),
        )

    /**
     * Annualised compensation in cents for a pay rate at a given [PayPeriod]. HOURLY assumes a
     * [hoursPerWeek] work week (default 40) x 52 weeks. Returns null for an UNKNOWN period. Never throws.
     */
    fun annualizedCents(
        payRateCents: Long,
        period: PayPeriod,
        hoursPerWeek: Int = 40,
    ): Long? = when (period) {
        PayPeriod.MONTHLY -> payRateCents * 12
        PayPeriod.BIWEEKLY -> payRateCents * 26
        PayPeriod.WEEKLY -> payRateCents * 52
        PayPeriod.HOURLY -> payRateCents * hoursPerWeek.toLong() * 52L
        PayPeriod.UNKNOWN -> null
    }

    /** Annualised compensation as [HrMoney] (currency preserved). Null when the period is UNKNOWN. */
    fun annualizedComp(employment: Employment, hoursPerWeek: Int = 40): HrMoney? {
        val cents = annualizedCents(employment.payRate.cents, employment.payPeriod, hoursPerWeek)
            ?: return null
        return HrMoney(cents, employment.payRate.currency)
    }

    /** A short pay-rate label, e.g. "1234.56 USD / month". Falls back to a bare amount for UNKNOWN. */
    fun payRateLabel(employment: Employment): String {
        val amount = formatMoney(employment.payRate)
        val suffix = when (employment.payPeriod) {
            PayPeriod.MONTHLY -> " / month"
            PayPeriod.BIWEEKLY -> " / 2 weeks"
            PayPeriod.WEEKLY -> " / week"
            PayPeriod.HOURLY -> " / hour"
            PayPeriod.UNKNOWN -> ""
        }
        return "$amount$suffix"
    }

    private fun plural(n: Long, unit: String): String = if (n == 1L) unit else "${unit}s"
}
