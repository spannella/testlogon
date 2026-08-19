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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Contract + mapper tests for the admin prediction-markets data layer (exchange-admin-config):
 * pm_config / pm_group_config / pm_resolve / pm_group_resolve acks and the pm_resolutions log. Covers
 * the ack/rejected/result mapping, the resolver 403, the 404 degrade, and the binary/categorical
 * resolution-row mapping.
 */
class PmAdminContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi = testMoshi()

    private fun repo(): TradingRepository {
        val api = backend.retrofit(moshi).create(TradingApi::class.java)
        return TradingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun pmConfig_ackResultZero_isApplied() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ack","type":"pm_config","symbolid":7,"result":0}"""))
        val r = repo().pmConfig(7, 100L, "resolver1")
        assertTrue(r is ApiResult.Success)
        val ack = (r as ApiResult.Success).data
        assertTrue(ack.applied)
        assertEquals(7, ack.symbolId)
        assertEquals(0, ack.result)
    }

    @Test
    fun pmGroupConfig_rejected_isNotApplied_withMessage() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"rejected","type":"pm_group_config","group_id":3,"result":9,"error":"need >= 2 outcomes"}"""))
        val r = repo().pmGroupConfig(3, listOf(11, 12), 100L, null)
        assertTrue(r is ApiResult.Success)
        val ack = (r as ApiResult.Success).data
        assertFalse(ack.applied)
        assertEquals(3, ack.groupId)
        assertEquals("need >= 2 outcomes", ack.message)
    }

    @Test
    fun pmResolve_ack_maps() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ack","type":"pm_resolve","symbolid":7}"""))
        val r = repo().pmResolve(7, "yes", "reuters")
        assertTrue(r is ApiResult.Success)
        // result absent -> treated as 0 (applied) when status is "ack".
        assertTrue((r as ApiResult.Success).data.applied)
    }

    @Test
    fun pmResolve_403_notDesignatedResolver_isFailure() = runTest {
        backend.enqueue(Fixtures.error("\"not the designated resolver\"", 403))
        val r = repo().pmResolve(7, "no", null)
        assertTrue(r is ApiResult.Failure)
    }

    @Test
    fun pmGroupResolve_ack_maps() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ack","type":"pm_group_resolve","group_id":3,"result":0}"""))
        val r = repo().pmGroupResolve(3, 12, "oracle")
        assertTrue(r is ApiResult.Success)
        val ack = (r as ApiResult.Success).data
        assertTrue(ack.applied)
        assertEquals(3, ack.groupId)
    }

    @Test
    fun undeployedRoute_404_degradesToUnappliedAck() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().pmConfig(7, 100L, null)
        assertTrue(r is ApiResult.Success)
        assertFalse((r as ApiResult.Success).data.applied)
    }

    @Test
    fun pmResolutions_parsesBinaryAndCategoricalRows() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """[
                    {"symbolid":7,"outcome":"yes","resolver_id":"resolver1","ts":1710000000000,"source":"reuters"},
                    {"group_id":3,"winning_symbolid":12,"resolver_id":"oracle","ts":"1710000001000","source":"oracle"}
                ]""",
            ),
        )
        val r = repo().pmResolutions()
        assertTrue(r is ApiResult.Success)
        val rows = (r as ApiResult.Success).data
        assertEquals(2, rows.size)

        val binary = rows[0]
        assertFalse(binary.isGroup)
        assertEquals(7, binary.symbolId)
        assertEquals(true, binary.outcomeYes)
        assertEquals("#7", binary.marketLabel)
        assertEquals("YES", binary.outcomeLabel)
        assertEquals("resolver1", binary.resolverId)

        val group = rows[1]
        assertTrue(group.isGroup)
        assertEquals(3, group.groupId)
        assertEquals(12, group.winningSymbolId)
        // ts arrived as a JSON string -> lenient long parse.
        assertEquals(1710000001000L, group.ts)
        assertEquals("group 3", group.marketLabel)
        assertEquals("#12", group.outcomeLabel)
    }

    @Test
    fun pmResolutions_404_degradesToEmptyList() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().pmResolutions()
        assertTrue(r is ApiResult.Success)
        assertTrue((r as ApiResult.Success).data.isEmpty())
    }

    @Test
    fun pmResolutionDto_binaryNo_mapsOutcomeFalse() {
        val dto = PmResolutionDto(symbolId = 5, outcome = "no", resolverId = "r", ts = 1L, source = "s")
        val m = dto.toDomain()
        assertFalse(m.isGroup)
        assertEquals(false, m.outcomeYes)
        assertEquals("NO", m.outcomeLabel)
        assertNull(dto.groupId)
    }
}
