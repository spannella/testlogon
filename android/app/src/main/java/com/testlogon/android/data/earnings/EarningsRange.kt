package com.testlogon.android.data.earnings

/**
 * AND-252 — selectable dashboard ranges. The backend has NO `range` param; each range is converted
 * client-side to `from_date`/`to_date` (today - days; ALL omits both). Web presets are 7d/30d/90d/1y/All.
 */
enum class EarningsRange(val apiKey: String, val days: Int?) {
    D7("7d", 7),
    D30("30d", 30),
    D90("90d", 90),
    Y1("1y", 365),
    ALL("all", null),
    ;

    companion object {
        val DEFAULT = D30

        /** Lenient parse of a persisted / deep-link key; unknown -> [DEFAULT]. */
        fun fromKey(key: String?): EarningsRange =
            entries.firstOrNull { it.apiKey.equals(key, ignoreCase = true) } ?: DEFAULT
    }
}

/**
 * Pure date-window math for a range, given "today" as an epoch-DAY (days since 1970). Returns the
 * inclusive `from_date`/`to_date` ISO YYYY-MM-DD pair, or null dates for [EarningsRange.ALL].
 * No java.time -> JVM-unit-testable and API < 26 safe.
 */
data class EarningsDateWindow(val fromDate: String?, val toDate: String?)

fun EarningsRange.toDateWindow(todayEpochDay: Long): EarningsDateWindow {
    val days = this.days ?: return EarningsDateWindow(fromDate = null, toDate = null)
    val to = todayEpochDay
    val from = todayEpochDay - (days - 1).toLong()
    return EarningsDateWindow(fromDate = isoDateFromEpochDay(from), toDate = isoDateFromEpochDay(to))
}

/** epoch-DAY -> "YYYY-MM-DD" (proleptic Gregorian); inverse of [epochDay]. No java.time. */
internal fun isoDateFromEpochDay(epochDay: Long): String {
    var zeroDay = epochDay + 719_468
    val era = (if (zeroDay >= 0) zeroDay else zeroDay - 146_096) / 146_097
    val doe = zeroDay - era * 146_097
    val yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365
    val y = yoe + era * 400
    val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
    val mp = (5 * doy + 2) / 153
    val day = (doy - (153 * mp + 2) / 5 + 1).toInt()
    val month = (if (mp < 10) mp + 3 else mp - 9).toInt()
    val year = (if (month <= 2) y + 1 else y)
    return "%04d-%02d-%02d".format(year, month, day)
}
