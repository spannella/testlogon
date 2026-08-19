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
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Contract tests for the REAL custody sub-accounts + bridge data layer against MockWebServer
 * (production Retrofit/Moshi). Sub-accounts are now {label, vault}; the vault<->vault transfer is real
 * (transferred + echoed balances); the custody<->trading bridge is four routes (fund/settle x
 * spot/margin) with {token, amount} bodies. Also covers the graceful 404 -> unavailable degrade and
 * the 422 rejection path.
 */
class CustodySubAccountsContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi = testMoshi()

    private fun repo(): CustodyRepository {
        val api = backend.retrofit(moshi).create(CustodyApi::class.java)
        return CustodyRepository(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun getSubAccounts_mapsLabelAndVault() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"subaccounts":[
                    {"label":"savings","vault":"vault-base-abc-savings"},
                    {"label":"trading","vault":"vault-base-abc-trading"}
                ]}""",
            ),
        )
        val r = repo().getSubAccounts()
        assertTrue(r is ApiResult.Success)
        val data = (r as ApiResult.Success).data
        assertFalse(data.unavailable)
        assertEquals(2, data.subAccounts.size)
        val savings = data.subAccounts.first { it.label == "savings" }
        assertEquals("vault-base-abc-savings", savings.vault)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/me/custody/subaccounts", req.requestUrl?.encodedPath)
    }

    @Test
    fun getSubAccounts_404_degradesToUnavailable() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().getSubAccounts()
        assertTrue(r is ApiResult.Success)
        assertTrue((r as ApiResult.Success).data.unavailable)
    }

    @Test
    fun getSubAccounts_transportFailure_isNetworkError() = runTest {
        backend.enqueue(Fixtures.disconnect())
        val r = repo().getSubAccounts()
        assertTrue(r is ApiResult.NetworkError)
    }

    @Test
    fun createSubAccount_returnsCreatedVaultWithLabel() = runTest {
        backend.enqueue(Fixtures.okBody("""{"created":true,"label":"savings","vault":"vault-base-abc-savings"}"""))
        val r = repo().createSubAccount("savings")
        assertTrue(r is ApiResult.Success)
        val sub = (r as ApiResult.Success).data
        assertEquals("vault-base-abc-savings", sub.vault)
        assertEquals("savings", sub.label)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/me/custody/subaccounts", req.requestUrl?.encodedPath)
        assertTrue(req.body.readUtf8().contains("\"label\":\"savings\""))
    }

    @Test
    fun createSubAccount_400_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"empty label\"", 400))
        val r = repo().createSubAccount("!!!")
        assertTrue(r is ApiResult.Failure)
        assertEquals(400, (r as ApiResult.Failure).error.status)
    }

    @Test
    fun subAccountTransfer_real_echoesBalances() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"transferred":true,"asset":"ETH","amount":"1","from":"vault-base-abc","to":"vault-base-abc-savings","from_balance":"4","to_balance":"1"}""",
            ),
        )
        val r = repo().subAccountTransfer(fromLabel = null, toLabel = "savings", asset = "ETH", amount = "1")
        assertTrue(r is ApiResult.Success)
        val res = (r as ApiResult.Success).data
        assertTrue(res.ok)
        assertEquals("ETH", res.asset)
        assertEquals("4", res.fromBalance)
        assertEquals("1", res.toBalance)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/me/custody/subaccounts/transfer", req.requestUrl?.encodedPath)
    }

    @Test
    fun fundSpot_reportsFundedAndLedger() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"funded":true,"token":"ETH","asset_id":"3","amount":"1","me_amount":"1","spot":"5"}""",
            ),
        )
        val r = repo().bridge(BridgeAction.FUND_SPOT, token = "ETH", amount = "1")
        assertTrue(r is ApiResult.Success)
        val res = (r as ApiResult.Success).data
        assertTrue(res.ok)
        assertEquals(BridgeAction.FUND_SPOT, res.action)
        assertEquals("ETH", res.token)
        assertEquals("5", res.ledger)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/me/custody/fund-spot", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"token\":\"ETH\""))
        assertTrue(body.contains("\"amount\":\"1\""))
    }

    @Test
    fun settleSpot_insufficient_surfacesReason() = runTest {
        backend.enqueue(
            Fixtures.error("""{"settled":false,"reason":"insufficient_spot_available"}""", 422),
        )
        val r = repo().bridge(BridgeAction.SETTLE_SPOT, token = "ETH", amount = "100")
        assertTrue(r is ApiResult.Failure)
        assertEquals(422, (r as ApiResult.Failure).error.status)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/me/custody/settle-spot", req.requestUrl?.encodedPath)
    }

    @Test
    fun fundMargin_hitsMarginRoute() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"funded":true,"token":"USDC","asset_id":"5","amount":"10","me_amount":"10","margin":"10"}"""),
        )
        val r = repo().bridge(BridgeAction.FUND_MARGIN, token = "USDC", amount = "10")
        assertTrue(r is ApiResult.Success)
        val res = (r as ApiResult.Success).data
        assertTrue(res.ok)
        assertEquals("10", res.ledger)

        val req = backend.takeRequest()
        assertEquals("/me/custody/fund-margin", req.requestUrl?.encodedPath)
    }

    @Test
    fun settleMargin_reportsCustodyBalance() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"settled":true,"token":"USDC","amount":"10","me_amount":"10","margin":"0","custody":"20"}"""),
        )
        val r = repo().bridge(BridgeAction.SETTLE_MARGIN, token = "USDC", amount = "10")
        assertTrue(r is ApiResult.Success)
        val res = (r as ApiResult.Success).data
        assertTrue(res.ok)
        assertEquals("20", res.custody)
        assertEquals("0", res.ledger)

        val req = backend.takeRequest()
        assertEquals("/me/custody/settle-margin", req.requestUrl?.encodedPath)
    }
}
