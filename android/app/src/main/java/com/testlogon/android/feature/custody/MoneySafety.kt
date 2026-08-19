package com.testlogon.android.feature.custody

/**
 * Pure, Android-free money-safety decision logic for the custody transfer/withdraw forms.
 *
 * This was extracted verbatim from [CustodyViewModel] so the money-correctness rules — positive-amount
 * required, over-spend blocked ONLY when the source figure is EXACT (never on best-effort guidance),
 * Max respecting the source decimals, and the decimal-input sanitizer — can be unit-tested without a
 * ViewModel, repositories, or Hilt. There is NO behavior change: the ViewModel now delegates here.
 */
object MoneySafety {

    /** A source balance for a transfer leg: the [amount] (null when unknown) and whether it is EXACT. */
    data class Source(val amount: Double?, val exact: Boolean)

    /** Parse a user-entered amount to a strictly-positive Double, or null when blank/non-numeric/<=0. */
    fun positiveAmount(text: String): Double? = text.trim().toDoubleOrNull()?.takeIf { it > 0.0 }

    /**
     * Whether the entered [amountText] over-spends [source]. Over-spend is only meaningful (and only
     * blocks) when the source is EXACT and known; best-effort guidance never blocks. A non-positive or
     * unparseable amount is NOT an over-spend here (that is a separate positive-amount error).
     */
    fun overspends(amountText: String, source: Source): Boolean {
        val amt = positiveAmount(amountText) ?: return false
        val avail = source.amount ?: return false
        return source.exact && amt > avail
    }

    /** Whether a Max action is meaningful for [source] (only when the figure is EXACT + known). */
    fun canMax(source: Source): Boolean = source.exact && source.amount != null

    /** The value Max should fill for [source], or null when Max is not meaningful. */
    fun maxValue(source: Source): String? {
        if (!canMax(source)) return null
        return trimDecimal(source.amount ?: return null)
    }

    /** Trim a Double to a compact decimal string (drops a trailing .0 for whole numbers). */
    fun trimDecimal(v: Double): String =
        if (v == v.toLong().toDouble()) v.toLong().toString() else v.toString()

    /** Keep digits + a single decimal point, capped to a sane length. */
    fun sanitizeDecimal(v: String): String {
        val filtered = v.filter { it.isDigit() || it == '.' }
        val firstDot = filtered.indexOf('.')
        val cleaned = if (firstDot < 0) filtered else {
            filtered.substring(0, firstDot + 1) + filtered.substring(firstDot + 1).replace(".", "")
        }
        return cleaned.take(24)
    }
}
