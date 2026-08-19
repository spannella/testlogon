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
 * Contract tests for the admin engine-config data layer (exchange-admin-config). Verifies the shared
 * [EngineConfigAckDto] -> [EngineConfigAck] mapping (ack/rejected/result) and that an undeployed route
 * (404) degrades to an un-applied ack instead of failing.
 */
class EngineConfigContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi = testMoshi()

    private fun repo(): TradingRepository {
        val api = backend.retrofit(moshi).create(TradingApi::class.java)
        return TradingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun matchingAlgo_ackResultZero_isApplied() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ack","type":"matching_algo","symbolid":3,"result":0}"""))
        val r = repo().matchingAlgo(3, 1, null, null)
        assertTrue(r is ApiResult.Success)
        val ack = (r as ApiResult.Success).data
        assertTrue(ack.applied)
        assertEquals(3, ack.symbolId)
        assertEquals(0, ack.result)
    }

    @Test
    fun spreadConfig_rejected_isNotApplied_withMessage() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"rejected","type":"spread_config","result":7,"error":"bad legs"}"""))
        val r = repo().spreadConfig(9, 1, 2, 1, -1)
        assertTrue(r is ApiResult.Success)
        val ack = (r as ApiResult.Success).data
        assertFalse(ack.applied)
        assertEquals(7, ack.result)
        assertEquals("bad legs", ack.message)
    }

    @Test
    fun ackWithNoResultField_defaultsAppliedOnAck() = runTest {
        // result absent -> treated as 0 (applied) when status is "ack".
        backend.enqueue(Fixtures.okBody("""{"status":"ack","type":"risk_config"}"""))
        val r = repo().riskConfig(1_000_000L, 60, null)
        assertTrue(r is ApiResult.Success)
        assertTrue((r as ApiResult.Success).data.applied)
    }

    @Test
    fun undeployedRoute_404_degradesToUnappliedAck() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().spotConfig(3, 100, 200)
        assertTrue(r is ApiResult.Success)
        val ack = (r as ApiResult.Success).data
        assertFalse(ack.applied)
    }

    @Test
    fun spotIndex_ack_maps() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ack","type":"spot_index","symbolid":5,"result":0}"""))
        val r = repo().spotIndex(5, 4_200_000L)
        assertTrue(r is ApiResult.Success)
        assertTrue((r as ApiResult.Success).data.applied)
    }
}
