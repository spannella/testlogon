package com.testlogon.android.feature.banking

/**
 * Pure, Android-free formatting + validation logic for the banking-accounts feature.
 *
 * Extracted so the money/metadata rules can be unit-tested without a ViewModel, repositories, or Hilt.
 * There is NO Android or network dependency here. All rules mirror the backend contract
 * (`app/routers/banking_accounts.py` + the Pydantic `*In` models):
 *  - narrative: 1..2000 chars (non-blank)
 *  - tag value: 1..100 chars (non-blank)
 *  - comment text: 1..1000 chars (non-blank)
 *  - geotag: lat in [-90, 90], lon in [-180, 180]
 */
object BankingMath {

    // ─── Money formatting ───────────────────────────────────────────────────

    /**
     * Format a dollars balance (Double, NOT cents) as a currency amount with the ISO code, e.g.
     * (1234.5, "usd") -> "USD 1,234.50". Currency code is upper-cased; a blank code is dropped.
     * Always two fraction digits, grouped thousands, half-up rounding.
     */
    fun formatBalance(amount: Double, currency: String): String {
        val code = currency.trim().uppercase()
        val body = formatAmount2dp(amount)
        return if (code.isEmpty()) body else "$code $body"
    }

    /** Format a Double to a grouped 2dp string with a sign preserved, e.g. -1234.5 -> "-1,234.50". */
    fun formatAmount2dp(amount: Double): String {
        val negative = amount < 0.0
        // Round half-up on the absolute value to avoid negative-rounding surprises.
        val cents = Math.round(Math.abs(amount) * 100.0)
        val whole = cents / 100
        val frac = cents % 100
        val grouped = groupThousands(whole)
        val fracStr = if (frac < 10) "0$frac" else "$frac"
        val sign = if (negative && cents != 0L) "-" else ""
        return "$sign$grouped.$fracStr"
    }

    /**
     * Format a decimal transaction-amount string (the wire `amount.value`, e.g. "12.50" or "-3.4")
     * with its currency, e.g. ("12.5", "usd") -> "USD 12.50". A non-numeric value is passed through
     * verbatim after the currency code (never crashes on unexpected shapes).
     */
    fun formatTxnAmount(value: String, currency: String): String {
        val code = currency.trim().uppercase()
        val parsed = value.trim().toDoubleOrNull()
        val body = if (parsed != null) formatAmount2dp(parsed) else value.trim()
        return if (code.isEmpty()) body else "$code $body"
    }

    /** True when a transaction amount string parses to a strictly-negative number (a debit/outflow). */
    fun isDebit(value: String): Boolean = (value.trim().toDoubleOrNull() ?: 0.0) < 0.0

    /** Group a non-negative whole number with comma thousands separators. */
    private fun groupThousands(whole: Long): String {
        val digits = whole.toString()
        if (digits.length <= 3) return digits
        val sb = StringBuilder()
        val firstGroup = digits.length % 3
        if (firstGroup > 0) {
            sb.append(digits, 0, firstGroup)
        }
        var i = firstGroup
        while (i < digits.length) {
            if (sb.isNotEmpty()) sb.append(',')
            sb.append(digits, i, i + 3)
            i += 3
        }
        return sb.toString()
    }

    // ─── Account display ────────────────────────────────────────────────────

    /**
     * A compact one-line account subtitle from the identifiers present: the masked account number, the
     * IBAN, or the routing number (in that preference). Blank/absent identifiers are skipped; returns
     * null when nothing identifying is present.
     */
    fun accountSubtitle(masked: String?, iban: String?, routing: String?): String? {
        masked?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        iban?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        routing?.trim()?.takeIf { it.isNotEmpty() }?.let { return "Routing $it" }
        return null
    }

    // ─── Metadata validation (mirrors backend Field constraints) ─────────────

    const val NARRATIVE_MAX = 2000
    const val TAG_MAX = 100
    const val COMMENT_MAX = 1000

    private fun validText(text: String, max: Int): Boolean {
        val t = text.trim()
        return t.isNotEmpty() && t.length <= max
    }

    fun isValidNarrative(text: String): Boolean = validText(text, NARRATIVE_MAX)

    fun isValidTag(value: String): Boolean = validText(value, TAG_MAX)

    fun isValidComment(text: String): Boolean = validText(text, COMMENT_MAX)

    /** Latitude is valid in the inclusive range [-90, 90]. */
    fun isValidLat(lat: Double): Boolean = lat in -90.0..90.0

    /** Longitude is valid in the inclusive range [-180, 180]. */
    fun isValidLon(lon: Double): Boolean = lon in -180.0..180.0

    /**
     * Whether a geotag input pair (as user-entered strings) is submittable: both parse to numbers and
     * fall within the valid lat/lon ranges.
     */
    fun isValidGeotag(latText: String, lonText: String): Boolean {
        val lat = latText.trim().toDoubleOrNull() ?: return false
        val lon = lonText.trim().toDoubleOrNull() ?: return false
        return isValidLat(lat) && isValidLon(lon)
    }
}
