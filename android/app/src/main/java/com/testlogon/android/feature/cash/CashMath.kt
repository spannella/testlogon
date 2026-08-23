package com.testlogon.android.feature.cash

import java.math.BigDecimal
import java.math.RoundingMode

/**
 * Pure, Android-free money math for the FIAT (USD) Cash screen. Kept out of the ViewModel so the
 * money-correctness rules (dollars<->cents parse/format, min-$1 deposit, withdraw <= balance) are unit
 * testable without Compose/Hilt. Money is integer cents everywhere; parsing uses BigDecimal so
 * "10.99" -> 1099 exactly (no binary-float drift).
 */
object CashMath {

    /** Minimum deposit / withdrawal, in cents ($1.00). */
    const val MIN_CENTS: Long = 100L

    /**
     * Parse a user-entered dollar string to integer cents, or null when blank / non-numeric / negative.
     * Accepts an optional leading "$", commas, and up to 2 decimal places (extra precision is truncated
     * toward zero). Zero parses to 0 (callers enforce the min separately).
     */
    fun parseDollarsToCents(text: String): Long? {
        val cleaned = text.trim().removePrefix("$").replace(",", "").trim()
        if (cleaned.isEmpty()) return null
        val dec = cleaned.toBigDecimalOrNull() ?: return null
        if (dec.signum() < 0) return null
        return dec.movePointRight(2).setScale(0, RoundingMode.DOWN).toLong()
    }

    /** Format integer cents as a plain dollar string with 2 decimals (e.g. 1099 -> "10.99"). No symbol. */
    fun formatCents(cents: Long): String =
        BigDecimal(cents).movePointLeft(2).setScale(2, RoundingMode.UNNECESSARY).toPlainString()

    /** Format integer cents as a currency amount with the symbol (e.g. 1099 -> "$10.99"). */
    fun formatCentsUsd(cents: Long): String = "$" + formatCents(cents)

    /** Keep digits + a single decimal point, cap to 2 fractional digits, drop stray input. */
    fun sanitizeAmountInput(v: String): String {
        val filtered = v.filter { it.isDigit() || it == '.' }
        val firstDot = filtered.indexOf('.')
        if (firstDot < 0) return filtered.take(12)
        val intPart = filtered.substring(0, firstDot).take(12)
        val fracPart = filtered.substring(firstDot + 1).replace(".", "").take(2)
        return "$intPart.$fracPart"
    }

    /** A deposit is valid when it parses to >= the $1 minimum. */
    fun isDepositValid(amountText: String): Boolean {
        val cents = parseDollarsToCents(amountText) ?: return false
        return cents >= MIN_CENTS
    }

    /** A withdrawal is valid when it parses to >= $1 AND does not exceed [balanceCents]. */
    fun isWithdrawValid(amountText: String, balanceCents: Long): Boolean {
        val cents = parseDollarsToCents(amountText) ?: return false
        return cents in MIN_CENTS..balanceCents
    }
}
