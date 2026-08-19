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
 * configured}; the fills-fees feed stays a client-side estimate (its stub flag is genuine).
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
    fun fillsFees_emptyFeed_carriesFormulaAndStub() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"fills":[],"taker_fee_bps":20,"fee_formula":"round(price*qty*taker_fee_bps/10000)","source":"stub","stub":true,"note":"engine exposes no per-fill fee"}""",
            ),
        )
        val r = repo().fillsFees()
        assertTrue(r is ApiResult.Success)
        val ff = (r as ApiResult.Success).data
        assertTrue(ff.fills.isEmpty())
        assertEquals(20, ff.takerFeeBps)
        assertTrue(ff.isStub)
        assertEquals("round(price*qty*taker_fee_bps/10000)", ff.feeFormula)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/me/fills/fees", req.requestUrl?.encodedPath)
    }

    @Test
    fun fillsFees_populatedFeed_mapsFee() = runTest {
        backend.enqueue(Fixtures.okBody("""{"fills":[{"price":100,"qty":5,"fee":1,"ts_ns":1700000000000000000,"side":"buy"}],"taker_fee_bps":20,"source":"real"}"""))
        val r = repo().fillsFees()
        assertTrue(r is ApiResult.Success)
        val ff = (r as ApiResult.Success).data
        assertEquals(1, ff.fills.size)
        assertEquals(1L, ff.fills.first().fee)
        assertEquals(OrderSide.BUY, ff.fills.first().side)
        assertFalse(ff.isStub)
    }

    @Test
    fun feeFor_formulaMatchesBackend() {
        // round(250*4*20/10000) = round(2.0) = 2
        assertEquals(2L, feeFor(250L * 4L, 20))
        // round(333*3*20/10000) = round(1.998) = 2
        assertEquals(2L, feeFor(333L * 3L, 20))
    }
}
