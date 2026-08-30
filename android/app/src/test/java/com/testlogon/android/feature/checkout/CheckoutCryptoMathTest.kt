package com.testlogon.android.feature.checkout

import com.testlogon.android.data.fees.FeeQuote
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FE-152 - money/countdown correctness for the "Pay with crypto balance" checkout path: the rate-lock
 * countdown clamps at 0, insufficient-balance is a pure integer compare on native base units, and the
 * rate/fee/total display lines match the shipped web describeQuote() semantics. Pure + deterministic
 * (the clock is injected as nowMs).
 */
class CheckoutCryptoMathTest {

    private val dollar = "$"

    private fun quote(
        payWith: String = "SOL",
        amountCents: Long = 1500L,
        usdCentsPerCoinNative: Long = 15000L,
        usdPerWholeCoin: Double? = 150.0,
        conversionFeeBps: Int = 175,
        conversionFeePct: Double = 1.75,
        coinNative: Long = 10L,
        conversionFeeNative: Long = 1L,
        totalNative: Long = 11L,
        expiresAt: Long = 0L,
        lockedSeconds: Int = 60,
        quoteToken: String = "tok",
        convertible: Boolean? = null,
        note: String? = null,
    ) = FeeQuote(
        payWith = payWith,
        amountCents = amountCents,
        usdCentsPerCoinNative = usdCentsPerCoinNative,
        usdPerWholeCoin = usdPerWholeCoin,
        rateSource = "book_mid",
        conversionFeeBps = conversionFeeBps,
        conversionFeePct = conversionFeePct,
        coinNative = coinNative,
        conversionFeeNative = conversionFeeNative,
        totalNative = totalNative,
        expiresAt = expiresAt,
        lockedSeconds = lockedSeconds,
        quoteToken = quoteToken,
        convertible = convertible,
        note = note,
    )

    // ---- quoteExpirySeconds ----

    @Test
    fun expiry_futureLockCountsDownInSeconds() {
        assertEquals(42L, CheckoutCryptoMath.quoteExpirySeconds(1_000_000_042L, 1_000_000_000_000L))
    }

    @Test
    fun expiry_pastLockClampsToZero() {
        assertEquals(0L, CheckoutCryptoMath.quoteExpirySeconds(1_000_000_000L, 1_000_000_050_000L))
    }

    @Test
    fun expiry_zeroOrNegativeExpiryIsZero() {
        assertEquals(0L, CheckoutCryptoMath.quoteExpirySeconds(0L, 1_000_000_000_000L))
        assertEquals(0L, CheckoutCryptoMath.quoteExpirySeconds(-5L, 1_000_000_000_000L))
    }

    @Test
    fun expiry_exactlyNowIsZero() {
        assertEquals(0L, CheckoutCryptoMath.quoteExpirySeconds(1_000_000_000L, 1_000_000_000_000L))
    }

    // ---- isQuoteExpired ----

    @Test
    fun expired_trueOnlyWhenNoSecondsRemain() {
        assertFalse(CheckoutCryptoMath.isQuoteExpired(1_000_000_010L, 1_000_000_000_000L))
        assertTrue(CheckoutCryptoMath.isQuoteExpired(1_000_000_000L, 1_000_000_000_000L))
        assertTrue(CheckoutCryptoMath.isQuoteExpired(0L, 1_000_000_000_000L))
    }

    // ---- insufficientForQuote ----

    @Test
    fun insufficient_balanceBelowTotalIsTrue() {
        assertTrue(CheckoutCryptoMath.insufficientForQuote(balanceBaseUnits = 10L, totalCoinBaseUnits = 11L))
    }

    @Test
    fun insufficient_balanceMeetsOrExceedsTotalIsFalse() {
        assertFalse(CheckoutCryptoMath.insufficientForQuote(11L, 11L))
        assertFalse(CheckoutCryptoMath.insufficientForQuote(12L, 11L))
    }

    @Test
    fun insufficient_zeroTotalIsNeverInsufficient() {
        assertFalse(CheckoutCryptoMath.insufficientForQuote(0L, 0L))
    }

    @Test
    fun insufficient_negativeBalanceTreatedAsZero() {
        assertTrue(CheckoutCryptoMath.insufficientForQuote(-5L, 1L))
    }

    // ---- rateLine ----

    @Test
    fun rateLine_prefersWholeCoinPrice() {
        assertEquals("1 SOL = " + dollar + "150.00", CheckoutCryptoMath.rateLine(quote(usdPerWholeCoin = 150.0)))
    }

    @Test
    fun rateLine_usdWalletShows1To1() {
        assertEquals(
            "Paid from USD wallet (1:1)",
            CheckoutCryptoMath.rateLine(quote(payWith = "USD", convertible = false)),
        )
    }

    @Test
    fun rateLine_fallsBackToPerNativeWhenNoWholePrice() {
        val line = CheckoutCryptoMath.rateLine(quote(usdPerWholeCoin = null, usdCentsPerCoinNative = 15000L))
        assertTrue(line.startsWith("1 SOL unit = " + dollar + "150"))
    }

    // ---- feeLine ----

    @Test
    fun feeLine_showsPercentWhenFeePresent() {
        assertEquals("1.75% conversion fee (SOL)", CheckoutCryptoMath.feeLine(quote(conversionFeeBps = 175, conversionFeePct = 1.75)))
    }

    @Test
    fun feeLine_noFeeWhenZeroBps() {
        assertEquals("No conversion fee", CheckoutCryptoMath.feeLine(quote(conversionFeeBps = 0)))
    }

    // ---- totalLine ----

    @Test
    fun totalLine_showsCoinAndUsd() {
        assertEquals("Pay 11 SOL for " + dollar + "15.00", CheckoutCryptoMath.totalLine(quote(totalNative = 11L, amountCents = 1500L)))
    }

    @Test
    fun totalLine_usdWalletVariant() {
        assertEquals("Pay " + dollar + "15.00 from wallet", CheckoutCryptoMath.totalLine(quote(convertible = false, amountCents = 1500L)))
    }

    // ---- formatting helpers ----

    @Test
    fun formatUsd_roundsHalfUpNoFloatDrift() {
        assertEquals("150.01", CheckoutCryptoMath.formatUsd(150.005))
        assertEquals("0.00", CheckoutCryptoMath.formatUsd(0.0))
        assertEquals("1234.50", CheckoutCryptoMath.formatUsd(1234.5))
    }

    @Test
    fun formatPct_trimsTrailingZeros() {
        assertEquals("1.75", CheckoutCryptoMath.formatPct(1.75))
        assertEquals("2", CheckoutCryptoMath.formatPct(2.0))
        assertEquals("0.5", CheckoutCryptoMath.formatPct(0.5))
    }

    @Test
    fun lockedForLabel_formatsSeconds() {
        assertEquals("locked for 42s", CheckoutCryptoMath.lockedForLabel(42L))
    }
}
