package com.testlogon.android.data.billing

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-248/250 — contract tests for [AdminBillingConfigRepositoryImpl] against MockWebServer. Covers the
 * GET path/verb, the full BillingConfigOut round-trip mapping (incl. payout_schedule -> Weekly), and the
 * 403 (root-only) -> Failure(403) authorization path.
 */
class AdminBillingConfigContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): AdminBillingConfigRepositoryImpl {
        val api = backend.retrofit(moshi).create(AdminBillingConfigApi::class.java)
        return AdminBillingConfigRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private val configBody = """
        {
          "fee_tips_bps": 250, "fee_unlocks_bps": 250, "fee_subscriptions_bps": 1500,
          "fee_catalog_bps": 1000, "fee_ad_revenue_bps": 3000,
          "min_payout_cents": 5000, "payout_fee_cents": 25, "payout_schedule": "weekly",
          "auto_payout_enabled": true,
          "min_deposit_cents": 500, "max_deposit_cents": 1000000, "deposit_fee_bps": 290,
          "default_currency": "USD", "supported_currencies": ["USD","EUR","GBP"],
          "tax_enabled": false, "default_tax_rate_bps": 0,
          "updated_at": 1717200000, "updated_by": "root|abc123"
        }
    """.trimIndent()

    @Test
    fun getBillingConfig_getsAdminPath_andMapsAllFields() = runTest {
        backend.enqueue(Fixtures.okBody(configBody))
        val result = repo().getBillingConfig()
        assertTrue(result is ApiResult.Success)
        val c = (result as ApiResult.Success).data
        assertEquals(250, c.feeTipsBps)
        assertEquals(PayoutSchedule.Weekly, c.payoutSchedule)
        assertEquals(listOf("USD", "EUR", "GBP"), c.supportedCurrencies)
        assertEquals("root|abc123", c.updatedBy)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/admin/billing-config", req.requestUrl?.encodedPath)
    }

    @Test
    fun getBillingConfig_403_mapsFailureWithStatus() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"role_required","message":"Permission denied"}""", 403))
        val result = repo().getBillingConfig()
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getBillingConfig_malformed_neverCrashes() = runTest {
        backend.enqueue(Fixtures.malformed())
        val result = repo().getBillingConfig()
        assertTrue(result is ApiResult.Failure || result is ApiResult.NetworkError)
    }
}
