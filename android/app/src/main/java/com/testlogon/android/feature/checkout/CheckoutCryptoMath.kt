package com.testlogon.android.feature.checkout

import com.testlogon.android.data.fees.FeeQuote

/**
 * FE-152 - pure, framework-free money/countdown math for the "Pay with crypto balance" checkout path.
 *
 * All functions are deterministic and side-effect free (no clock, no I/O): the caller passes the
 * current wall-clock ms so the rate-lock countdown is fully testable. Native coin amounts are integer
 * base units (Long); the shown FX rate + conversion-fee percent are display-only Doubles carried
 * straight from the server quote. Nothing here rounds money for charging - the server charges the
 * signed [FeeQuote.quoteToken] at the locked rate; this only formats + compares for the UI.
 *
 * Mirrors the web helper describeQuote() in frontend/src/api/endpoints/fees.ts (same rate/fee/total
 * lines + the "locked for Ns" countdown + the stale-on-expiry gate).
 */
object CheckoutCryptoMath {

    /** USD sign kept as a constant so string building never trips Kotlin's dollar interpolation. */
    private const val USD = "$"

    /**
     * Seconds remaining on the locked rate, clamped to >= 0. [expiresAtEpochSeconds] is the server
     * unix-seconds lock expiry; [nowMs] the client wall clock in millis. A 0/absent expiry (or any
     * past expiry) yields 0 so the caller re-quotes before charging.
     */
    fun quoteExpirySeconds(expiresAtEpochSeconds: Long, nowMs: Long): Long {
        if (expiresAtEpochSeconds <= 0L) return 0L
        val remaining = expiresAtEpochSeconds - (nowMs / 1000L)
        return if (remaining < 0L) 0L else remaining
    }

    /** True once the locked rate has lapsed (no seconds remain) - re-quote before charging. */
    fun isQuoteExpired(expiresAtEpochSeconds: Long, nowMs: Long): Boolean =
        quoteExpirySeconds(expiresAtEpochSeconds, nowMs) <= 0L

    /**
     * True when the vault balance cannot cover the quote total. Both operands are integer native base
     * units of the SAME coin. A non-positive total is never "insufficient" (nothing to pay); a
     * negative balance is treated as 0.
     */
    fun insufficientForQuote(balanceBaseUnits: Long, totalCoinBaseUnits: Long): Boolean {
        if (totalCoinBaseUnits <= 0L) return false
        val bal = if (balanceBaseUnits < 0L) 0L else balanceBaseUnits
        return bal < totalCoinBaseUnits
    }

    /**
     * Display "1 COIN = $X" rate line. Prefers the whole-coin USD price when the server provided it;
     * else derives it from usd-cents-per-native; the USD-wallet (non-convertible) path shows the 1:1
     * note. Returns e.g. "1 SOL = $150.00".
     */
    fun rateLine(quote: FeeQuote): String {
        if (quote.convertible == false) return "Paid from USD wallet (1:1)"
        val whole = quote.usdPerWholeCoin
        if (whole != null && whole > 0.0) {
            return "1 " + quote.payWith + " = " + USD + formatUsd(whole)
        }
        val perNativeUsd = quote.usdCentsPerCoinNative / 100.0
        return "1 " + quote.payWith + " unit = " + USD + formatUsd(perNativeUsd, maxFractionDigits = 6)
    }

    /** Conversion-fee line: "1.75% conversion fee (SOL)" or "No conversion fee". */
    fun feeLine(quote: FeeQuote): String =
        if (quote.conversionFeeBps > 0) {
            formatPct(quote.conversionFeePct) + "% conversion fee (" + quote.payWith + ")"
        } else {
            "No conversion fee"
        }

    /** Total line: "Pay 11 SOL for $15.00" (or the USD-wallet variant). */
    fun totalLine(quote: FeeQuote): String {
        val usd = formatUsd(quote.amountCents / 100.0)
        return if (quote.convertible == false) {
            "Pay " + USD + usd + " from wallet"
        } else {
            "Pay " + quote.totalNative + " " + quote.payWith + " for " + USD + usd
        }
    }

    /** "locked for 42s" - the live countdown label for the rate-lock chip. */
    fun lockedForLabel(secondsRemaining: Long): String = "locked for " + secondsRemaining + "s"

    /**
     * Two-decimal (default) USD formatting without locale/currency-symbol coupling. Half-up rounding
     * on a scaled integer so there is no binary-float display drift (e.g. 150.005 -> "150.01").
     */
    fun formatUsd(value: Double, maxFractionDigits: Int = 2): String {
        val safe = if (value.isNaN() || value.isInfinite()) 0.0 else value
        val digits = if (maxFractionDigits < 0) 0 else maxFractionDigits
        var scale = 1L
        repeat(digits) { scale *= 10L }
        val scaled = Math.round(safe * scale)
        val intPart = scaled / scale
        val frac = scaled % scale
        if (digits == 0) return intPart.toString()
        val fracStr = frac.toString().padStart(digits, '0')
        return intPart.toString() + "." + fracStr
    }

    /** Percent with up to two decimals, trailing zeros/point trimmed ("1.75", "2", "0.5"). */
    fun formatPct(pct: Double): String {
        val safe = if (pct.isNaN() || pct.isInfinite()) 0.0 else pct
        val scaled = Math.round(safe * 100.0)
        val intPart = scaled / 100L
        val frac = (if (scaled < 0) -scaled else scaled) % 100L
        if (frac == 0L) return intPart.toString()
        val fracStr = frac.toString().padStart(2, '0').trimEnd('0')
        return intPart.toString() + "." + fracStr
    }
}
