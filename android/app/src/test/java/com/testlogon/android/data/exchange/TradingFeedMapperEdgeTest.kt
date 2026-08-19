package com.testlogon.android.data.exchange

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Edge cases for the three REAL feed DTO -> domain mappers (fills-fees / liquidations / funding),
 * complementing the wire/contract coverage in [TradingFeesContractTest]. These exercise the mappers
 * directly (no MockWebServer) on the sign/flag/enum branches: funding `received` sign-derivation
 * including the exactly-zero boundary, liquidation signed PnL on the green (>=0) side, and the fills
 * maker/taker/UNKNOWN liquidity resolution + null-field defaulting.
 */
class TradingFeedMapperEdgeTest {

    // ---- funding: received sign-derivation ----

    @Test
    fun funding_zeroPayment_derivesReceivedFalse() {
        // payment == 0 is NOT a receipt: derivation is strictly `> 0`.
        val fp = FundingPaymentDto(payment = 0L).toDomain()
        assertEquals(0L, fp.payment)
        assertFalse(fp.received)
    }

    @Test
    fun funding_positivePayment_derivesReceivedTrue() {
        assertTrue(FundingPaymentDto(payment = 12L).toDomain().received)
    }

    @Test
    fun funding_negativePayment_derivesReceivedFalse() {
        assertFalse(FundingPaymentDto(payment = -12L).toDomain().received)
    }

    @Test
    fun funding_explicitFlagOverridesSign() {
        // A negative payment explicitly flagged received=true trusts the flag, not the sign.
        assertTrue(FundingPaymentDto(payment = -5L, received = true).toDomain().received)
        // And a positive payment flagged received=false trusts the flag.
        assertFalse(FundingPaymentDto(payment = 5L, received = false).toDomain().received)
    }

    @Test
    fun funding_nullFields_defaultToZeroAndNotReceived() {
        val fp = FundingPaymentDto().toDomain()
        assertEquals(0, fp.symbolId)
        assertEquals(0L, fp.payment)
        assertFalse(fp.received)
    }

    // ---- liquidations: signed PnL ----

    @Test
    fun liquidation_positivePnl_isPreservedSigned() {
        val e = LiquidationDto(symbolId = 2, qty = 4L, markPrice = 3000L, realizedPnl = 250L, fee = 3L).toDomain()
        assertEquals(250L, e.realizedPnl)
        assertTrue(e.realizedPnl >= 0L)
    }

    @Test
    fun liquidation_negativePnl_isPreservedSigned() {
        assertEquals(-750L, LiquidationDto(realizedPnl = -750L).toDomain().realizedPnl)
    }

    @Test
    fun liquidations_emptyList_isEmptyAndCountsZero() {
        val liq = LiquidationsDto(liquidations = emptyList()).toDomain()
        assertTrue(liq.isEmpty)
        assertEquals(0, liq.count)
    }

    @Test
    fun liquidations_countFallsBackToListSize_whenNull() {
        val liq = LiquidationsDto(count = null, liquidations = listOf(LiquidationDto(), LiquidationDto())).toDomain()
        assertEquals(2, liq.count)
    }

    // ---- fills: maker/taker/UNKNOWN liquidity ----

    @Test
    fun fill_makerLiquidity() {
        assertEquals(Liquidity.MAKER, FillFeeDto(liquidity = "maker").toDomain().liquidity)
        // case-insensitive.
        assertEquals(Liquidity.MAKER, FillFeeDto(liquidity = "MAKER").toDomain().liquidity)
    }

    @Test
    fun fill_takerLiquidity() {
        assertEquals(Liquidity.TAKER, FillFeeDto(liquidity = "taker").toDomain().liquidity)
    }

    @Test
    fun fill_unknownOrMissingLiquidity_mapsToUnknown() {
        assertEquals(Liquidity.UNKNOWN, FillFeeDto(liquidity = null).toDomain().liquidity)
        assertEquals(Liquidity.UNKNOWN, FillFeeDto(liquidity = "cross").toDomain().liquidity)
    }

    @Test
    fun fill_nullFields_defaultCleanly() {
        val f = FillFeeDto().toDomain()
        assertEquals(0, f.symbolId)
        assertEquals(0L, f.fee)
        assertEquals(Liquidity.UNKNOWN, f.liquidity)
    }

    @Test
    fun fillsFees_countFallsBackToListSize_whenNull() {
        val ff = FillsFeesDto(count = null, fills = listOf(FillFeeDto(), FillFeeDto(), FillFeeDto())).toDomain()
        assertEquals(3, ff.count)
        assertFalse(ff.isEmpty)
    }
}
