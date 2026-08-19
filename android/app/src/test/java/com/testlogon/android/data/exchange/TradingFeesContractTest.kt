package com.testlogon.android.data.exchange

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.testutil.testMoshi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Contract tests for the REAL fee schedule + enriched fills-fees data layer. The fee schedule is now
 * GET me/fees/schedule?symbolid=<n> returning {maker/taker/liq bps, source ("engine"|"venue_default"),
 * configured}; the fills-fees / liquidations / funding feeds are REAL (per-fill fee + maker/taker).
 */
class TradingFeesContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi = testMoshi()

    private fun repo(): TradingRepository {
        val api = backend.retrofit(moshi).create(TradingApi::class.java)
        return TradingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun feeSchedule_engineSource_isConfigured() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"status":"ok","type":"fee_schedule","symbolid":3,"maker_fee_bps":10,"taker_fee_bps":20,"liquidation_fee_bps":100,"source":"engine","configured":true}""",
            ),
        )
        val r = repo().feeSchedule(3)
        assertTrue(r is ApiResult.Success)
        val fee = (r as ApiResult.Success).data
        assertEquals(10, fee.makerFeeBps)
        assertEquals(20, fee.takerFeeBps)
        assertEquals(100, fee.liquidationFeeBps)
        assertFalse(fee.isVenueDefault)
        assertEquals("engine", fee.sourceLabel)
        assertEquals("0.20%", fee.takerPct())
        // round(price*qty*taker_bps/10000) = round(100*5*20/10000) = round(1.0) = 1
        assertEquals(1L, fee.takerFeeFor(100L, 5L))

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/me/fees/schedule", req.requestUrl?.encodedPath)
        assertEquals("3", req.requestUrl?.queryParameter("symbolid"))
    }

    @Test
    fun feeSchedule_venueDefault_flaggedAndLabeled() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"status":"ok","type":"fee_schedule","symbolid":7,"maker_fee_bps":10,"taker_fee_bps":20,"liquidation_fee_bps":100,"source":"venue_default","configured":false}""",
            ),
        )
        val r = repo().feeSchedule(7)
        assertTrue(r is ApiResult.Success)
        val fee = (r as ApiResult.Success).data
        assertTrue(fee.isVenueDefault)
        assertEquals("venue default", fee.sourceLabel)
    }

    @Test
    fun feeSchedule_toleratesStringifiedBps() = runTest {
        backend.enqueue(Fixtures.okBody("""{"symbolid":3,"maker_fee_bps":"10","taker_fee_bps":"20","liquidation_fee_bps":"100","source":"engine","configured":true}"""))
        val r = repo().feeSchedule(3)
        assertTrue(r is ApiResult.Success)
        val fee = (r as ApiResult.Success).data
        assertEquals(20, fee.takerFeeBps)
    }

    @Test
    fun feeSchedule_missingFields_fallsBackToVenueDefaults() = runTest {
        backend.enqueue(Fixtures.okBody("""{"symbolid":3}"""))
        val r = repo().feeSchedule(3)
        assertTrue(r is ApiResult.Success)
        val fee = (r as ApiResult.Success).data
        assertEquals(10, fee.makerFeeBps)
        assertEquals(20, fee.takerFeeBps)
        assertEquals(100, fee.liquidationFeeBps)
        assertTrue(fee.isVenueDefault)
    }

    @Test
    fun feeSchedule_404_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().feeSchedule(3)
        assertTrue(r is ApiResult.Failure)
        assertEquals(404, (r as ApiResult.Failure).error.status)
    }

    @Test
    fun fillsFees_emptyFeed_mapsToEmpty() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ok","type":"fills","count":0,"fills":[]}"""))
        val r = repo().fillsFees()
        assertTrue(r is ApiResult.Success)
        val ff = (r as ApiResult.Success).data
        assertTrue(ff.isEmpty)
        assertEquals(0, ff.count)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/me/fills/fees", req.requestUrl?.encodedPath)
    }

    @Test
    fun fillsFees_populatedFeed_mapsRealFeeAndLiquidity() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"status":"ok","type":"fills","count":1,"fills":[{"symbolid":3,"price":100,"qty":5,"side":"buy","liquidity":"maker","fee":2,"fee_asset":0,"ts":1700000000000000000}]}""",
            ),
        )
        val r = repo().fillsFees()
        assertTrue(r is ApiResult.Success)
        val ff = (r as ApiResult.Success).data
        assertEquals(1, ff.fills.size)
        val f = ff.fills.first()
        assertEquals(3, f.symbolId)
        assertEquals(2L, f.fee)
        assertEquals(OrderSide.BUY, f.side)
        assertEquals(Liquidity.MAKER, f.liquidity)
        assertEquals(1700000000000000000L, f.tsNs)
    }

    @Test
    fun fillsFees_toleratesStringifiedNumbers() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"type":"fills","count":"1","fills":[{"symbolid":"1","price":"100","qty":"5","side":"sell","liquidity":"taker","fee":"3","ts":"1700000000000000000"}]}""",
            ),
        )
        val r = repo().fillsFees()
        assertTrue(r is ApiResult.Success)
        val ff = (r as ApiResult.Success).data
        assertEquals(1, ff.fills.size)
        assertEquals(3L, ff.fills.first().fee)
        assertEquals(Liquidity.TAKER, ff.fills.first().liquidity)
    }

    @Test
    fun fillsFees_404_mapsToEmptyFeed() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().fillsFees()
        assertTrue(r is ApiResult.Success)
        assertTrue((r as ApiResult.Success).data.isEmpty)
    }

    @Test
    fun liquidations_populatedFeed_mapsSignedPnl() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"status":"ok","type":"liquidations","count":1,"liquidations":[{"symbolid":2,"qty":10,"mark_price":3000,"realized_pnl":-500,"fee":7,"ts":1700000000000000000}]}""",
            ),
        )
        val r = repo().liquidations()
        assertTrue(r is ApiResult.Success)
        val liq = (r as ApiResult.Success).data
        assertEquals(1, liq.events.size)
        val e = liq.events.first()
        assertEquals(2, e.symbolId)
        assertEquals(-500L, e.realizedPnl)
        assertEquals(7L, e.fee)

        val req = backend.takeRequest()
        assertEquals("/me/liquidations", req.requestUrl?.encodedPath)
    }

    @Test
    fun liquidations_404_mapsToEmpty() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().liquidations()
        assertTrue(r is ApiResult.Success)
        assertTrue((r as ApiResult.Success).data.isEmpty)
    }

    @Test
    fun fundingPayments_signedPayment_derivesReceivedFromSign() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"status":"ok","type":"funding","count":2,"funding":[{"symbolid":1,"funding_rate_bps":5,"mark_price":100,"position_qty":10,"payment":-25,"received":false,"ts":1700000000000000000},{"symbolid":1,"funding_rate_bps":-3,"mark_price":100,"position_qty":10,"payment":15,"ts":1700000000000000001}]}""",
            ),
        )
        val r = repo().fundingPayments()
        assertTrue(r is ApiResult.Success)
        val fp = (r as ApiResult.Success).data
        assertEquals(2, fp.payments.size)
        assertEquals(-25L, fp.payments[0].payment)
        assertFalse(fp.payments[0].received)
        // second row omits `received`; derived from the positive sign.
        assertEquals(15L, fp.payments[1].payment)
        assertTrue(fp.payments[1].received)

        val req = backend.takeRequest()
        assertEquals("/me/funding/payments", req.requestUrl?.encodedPath)
    }

    @Test
    fun fundingPayments_404_mapsToEmpty() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().fundingPayments()
        assertTrue(r is ApiResult.Success)
        assertTrue((r as ApiResult.Success).data.isEmpty)
    }

    @Test
    fun feeFor_formulaMatchesBackend() {
        // round(250*4*20/10000) = round(2.0) = 2
        assertEquals(2L, feeFor(250L * 4L, 20))
        // round(333*3*20/10000) = round(1.998) = 2
        assertEquals(2L, feeFor(333L * 3L, 20))
    }
}
