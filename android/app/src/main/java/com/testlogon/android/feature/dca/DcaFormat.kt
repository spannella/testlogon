package com.testlogon.android.feature.dca

import com.testlogon.android.data.dca.DcaFrequency
import com.testlogon.android.data.dca.DcaStatus
import com.testlogon.android.data.dca.DcaTargetKind
import java.math.BigDecimal
import java.math.RoundingMode
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Display + input helpers for the DCA / recurring-buys UI. Money stays integer CENTS; parsing uses
 * BigDecimal so "10.99" -> 1099 exactly (no binary-float drift), mirroring CashMath. Schedule instants
 * are epoch-ms and are rendered in UTC so the label matches the UTC-day scheduling done by DcaSchedule.
 */
object DcaFormat {

    const val MIN_AMOUNT_CENTS: Long = 100L // $1 minimum buy

    private val DATE_FMT = SimpleDateFormat("MMM d, yyyy", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
    private val DATE_DOW_FMT = SimpleDateFormat("EEE, MMM d, yyyy", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }

    /** Parse a user-entered dollar string to integer cents, or null when blank / non-numeric / negative. */
    fun parseDollarsToCents(text: String): Long? {
        val cleaned = text.trim().removePrefix("$").replace(",", "").trim()
        if (cleaned.isEmpty()) return null
        val dec = cleaned.toBigDecimalOrNull() ?: return null
        if (dec.signum() < 0) return null
        return dec.movePointRight(2).setScale(0, RoundingMode.DOWN).toLong()
    }

    /** Keep digits + a single decimal point, cap to 2 fractional digits. */
    fun sanitizeAmountInput(v: String): String {
        val filtered = v.filter { it.isDigit() || it == '.' }
        val firstDot = filtered.indexOf('.')
        if (firstDot < 0) return filtered.take(12)
        val intPart = filtered.substring(0, firstDot).take(12)
        val fracPart = filtered.substring(firstDot + 1).replace(".", "").take(2)
        return "$intPart.$fracPart"
    }

    fun formatCents(cents: Long): String =
        BigDecimal(cents).movePointLeft(2).setScale(2, RoundingMode.HALF_UP).toPlainString()

    fun formatCentsUsd(cents: Long): String = "$" + formatCents(cents)

    /** Render an epoch-ms instant as a UTC date (matches UTC-day scheduling). 0/negative -> em dash. */
    fun formatDate(ms: Long): String = if (ms <= 0L) "—" else DATE_FMT.format(Date(ms))

    fun formatDateWithDow(ms: Long): String = if (ms <= 0L) "—" else DATE_DOW_FMT.format(Date(ms))

    /** ISO day-of-week (1=Mon..7=Sun) -> short label. */
    fun dayOfWeekLabel(dow: Int?): String = when (dow) {
        1 -> "Monday"
        2 -> "Tuesday"
        3 -> "Wednesday"
        4 -> "Thursday"
        5 -> "Friday"
        6 -> "Saturday"
        7 -> "Sunday"
        else -> "—"
    }

    /** Human summary of the cadence, e.g. "Weekly on Wednesday" / "Monthly on day 15" / "Daily". */
    fun frequencyLabel(frequency: DcaFrequency, dayOfWeek: Int?, dayOfMonth: Int?): String = when (frequency) {
        DcaFrequency.DAILY -> "Daily"
        DcaFrequency.WEEKLY -> "Weekly on ${dayOfWeekLabel(dayOfWeek)}"
        DcaFrequency.MONTHLY -> "Monthly on day ${dayOfMonth?.coerceIn(1, 28) ?: 1}"
        DcaFrequency.UNKNOWN -> "—"
    }

    fun statusLabel(status: DcaStatus): String = when (status) {
        DcaStatus.ACTIVE -> "Active"
        DcaStatus.PAUSED -> "Paused"
        DcaStatus.COMPLETED -> "Completed"
        DcaStatus.CANCELLED -> "Cancelled"
        DcaStatus.UNKNOWN -> "Unknown"
    }

    fun targetKindLabel(kind: DcaTargetKind): String = when (kind) {
        DcaTargetKind.SYMBOL -> "Market"
        DcaTargetKind.TOKEN -> "Creator token"
        DcaTargetKind.STRATEGY -> "Strategy"
        DcaTargetKind.UNKNOWN -> "Target"
    }

    /** A buy amount is valid when it parses to >= the $1 minimum. */
    fun isAmountValid(text: String): Boolean {
        val cents = parseDollarsToCents(text) ?: return false
        return cents >= MIN_AMOUNT_CENTS
    }
}
