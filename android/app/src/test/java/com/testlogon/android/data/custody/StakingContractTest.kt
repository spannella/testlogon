package com.testlogon.android.data.custody

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
 * Contract tests for the custody staking data layer (providers + positions read; stake write) against
 * MockWebServer with the production Retrofit/Moshi. Covers the DTO -> domain mapping (string amounts
 * preserved), the graceful 404/403 -> unavailable degrade, and the stake ack (ok + reason).
 */
class StakingContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi = testMoshi()

    private fun repo(): CustodyRepository {
        val api = backend.retrofit(moshi).create(CustodyApi::class.java)
        return CustodyRepository(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun getStaking_mapsProvidersAndPositions() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"providers":[
                    {"id":"lido","chain":"1","contract":"0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84","kind":"liquid","asset":"ETH"}
                ]}""",
            ),
        )
        backend.enqueue(
            Fixtures.okBody(
                """{"vault":"vault-abc","count":1,"positions":[
                    {"position_id":"pos-1","vault":"vault-abc","provider":"lido","chain":"1","asset":"ETH","principal":"1.5","rewards":"0.03","total":"1.53","status":"active"}
                ]}""",
            ),
        )
        val r = repo().getStaking()
        assertTrue(r is ApiResult.Success)
        val d = (r as ApiResult.Success).data
        assertFalse(d.unavailable)
        assertEquals("vault-abc", d.vault)
        assertEquals(1, d.providers.size)
        assertEquals("lido", d.providers.first().id)
        assertEquals("ETH", d.providers.first().asset)
        assertEquals(1, d.positions.size)
        val pos = d.positions.first()
        assertEquals("1.5", pos.principal)
        assertEquals("0.03", pos.rewards)
        assertEquals("1.53", pos.total)
        assertEquals("active", pos.status)

        val req1 = backend.takeRequest()
        assertEquals("GET", req1.method)
        assertEquals("/me/staking/providers", req1.requestUrl?.encodedPath)
        val req2 = backend.takeRequest()
        assertEquals("/me/staking/positions", req2.requestUrl?.encodedPath)
    }

    @Test
    fun getStaking_404_degradesToUnavailable() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().getStaking()
        assertTrue(r is ApiResult.Success)
        val d = (r as ApiResult.Success).data
        assertTrue(d.unavailable)
        assertTrue(d.providers.isEmpty())
        assertTrue(d.positions.isEmpty())
    }

    @Test
    fun getStaking_403_degradesToUnavailable() = runTest {
        backend.enqueue(Fixtures.error("\"forbidden\"", 403))
        val d = (repo().getStaking() as ApiResult.Success).data
        assertTrue(d.unavailable)
    }

    @Test
    fun getStaking_missingAmounts_defaultToZeroStrings() = runTest {
        backend.enqueue(Fixtures.okBody("""{"providers":[]}"""))
        backend.enqueue(Fixtures.okBody("""{"positions":[{"position_id":"p","provider":"x"}]}"""))
        val d = (repo().getStaking() as ApiResult.Success).data
        val pos = d.positions.first()
        assertEquals("0", pos.principal)
        assertEquals("0", pos.rewards)
        assertEquals("0", pos.total)
    }

    @Test
    fun stake_ok_mapsResult() = runTest {
        backend.enqueue(Fixtures.okBody("""{"staked":true,"position_id":"pos-9","provider":"lido","amount":"2.0","status":"pending"}"""))
        val r = repo().stake("lido", "2.0")
        assertTrue(r is ApiResult.Success)
        val res = (r as ApiResult.Success).data
        assertTrue(res.ok)
        assertEquals("pos-9", res.positionId)
        assertEquals("lido", res.provider)
        assertEquals("2.0", res.amount)
        assertEquals("pending", res.status)
        assertNull(res.reason)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/me/staking/stake", req.requestUrl?.encodedPath)
    }

    @Test
    fun stake_rejected_surfacesReason() = runTest {
        backend.enqueue(Fixtures.okBody("""{"staked":false,"reason":"insufficient_balance"}"""))
        val res = (repo().stake("lido", "999") as ApiResult.Success).data
        assertFalse(res.ok)
        assertEquals("insufficient_balance", res.reason)
    }
}