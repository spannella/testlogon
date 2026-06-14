package com.testlogon.android.data.discounts

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-267/269 — repository round-trips for [AffiliateDiscountsRepositoryImpl] over the real
 * Retrofit/Moshi stack + MockWebServer. Verifies the ApiResult split (Success / Failure / NetworkError),
 * the cached snapshot used for the stale UI, and that a malformed body becomes a mapped Failure (not a
 * crash) via the JsonDataException catch.
 */
class AffiliateDiscountsRepositoryTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): AffiliateDiscountsRepositoryImpl {
        val api = backend.retrofit(moshi).create(AffiliateDiscountsApi::class.java)
        return AffiliateDiscountsRepositoryImpl(api, ApiErrorParser(moshi))
    }

    @Test
    fun loadDiscounts_success_mapsAndCachesSnapshot() = runTest {
        backend.enqueue(Fixtures.okBody(LIST_ONE))
        val repo = repo()
        val result = repo.loadDiscounts()
        assertTrue(result is ApiResult.Success)
        val data = (result as ApiResult.Success).data
        assertEquals(1, data.items.size)
        assertEquals("cr_1", data.items[0].creativeId)
        // Snapshot is retained for the stale/offline UI.
        assertEquals(data, repo.cached())
    }

    @Test
    fun loadDiscounts_httpError_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"Not enrolled\"", code = 403))
        val result = repo().loadDiscounts()
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun loadDiscounts_malformedBody_mapsToFailure_notCrash() = runTest {
        backend.enqueue(Fixtures.malformed())
        val result = repo().loadDiscounts()
        assertTrue(result is ApiResult.Failure)
    }

    @Test
    fun loadDiscounts_disconnect_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.disconnect())
        val result = repo().loadDiscounts()
        assertTrue(result is ApiResult.NetworkError)
    }

    @Test
    fun loadDiscount_byCreativeId_success() = runTest {
        backend.enqueue(Fixtures.okBody(SINGLE))
        val result = repo().loadDiscount("cr_1")
        assertTrue(result is ApiResult.Success)
        assertEquals("cr_1", (result as ApiResult.Success).data.creativeId)
    }

    @Test
    fun clear_dropsSnapshot() = runTest {
        backend.enqueue(Fixtures.okBody(LIST_ONE))
        val repo = repo()
        repo.loadDiscounts()
        repo.clear()
        assertNull(repo.cached())
    }

    private companion object {
        val LIST_ONE = """
            {"items":[{"creative_id":"cr_1","campaign_id":"cmp_1","owner_sub":"u",
              "promo_code":"SAVE10","promo_value_display":"10% off",
              "click_count":42,"redemption_count":7,"created_at":1717230000,"updated_at":1717233600}]}
        """.trimIndent()

        val SINGLE = """
            {"creative_id":"cr_1","campaign_id":"cmp_1","owner_sub":"u",
              "promo_code":"SAVE10","click_count":1,"redemption_count":0,
              "created_at":1717230000,"updated_at":1717230000}
        """.trimIndent()
    }
}
