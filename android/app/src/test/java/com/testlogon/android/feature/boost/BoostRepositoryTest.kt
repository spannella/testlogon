package com.testlogon.android.feature.boost

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.BoostStatus
import com.testlogon.android.core.network.ads.ContentBoostApi
import com.testlogon.android.core.network.ads.ContentBoostCancelOut
import com.testlogon.android.core.network.ads.ContentBoostCreateIn
import com.testlogon.android.core.network.ads.ContentBoostListResponse
import com.testlogon.android.core.network.ads.ContentBoostOut
import com.testlogon.android.core.network.ads.ContentBoostSpendOut
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.boost.data.BoostRepositoryImpl
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-364 - unit tests for [BoostRepositoryImpl] against a FAKE [ContentBoostApi]. The :app test classpath
 * has no moshi-kotlin reflective adapter, so a MockWebServer + reflective decode is avoided; the fake
 * returns canned DTOs (and RECORDS the create body BEFORE it can throw). Confirms create / get / spend /
 * cancel map to domain and that an HttpException surfaces as ApiResult.Failure with the status preserved.
 */
class BoostRepositoryTest {

    /** Recording fake: stores the create body, then returns the canned result or throws the canned error. */
    private class FakeBoostApi : ContentBoostApi {
        var createResult: ContentBoostOut = ContentBoostOut(
            boostId = "bst_1",
            status = "active",
            budgetCents = 500L,
            spentCents = 0L,
            remainingCents = 500L,
            durationSeconds = 3600L,
            endsAt = 1700003600L,
        )
        var getResult: ContentBoostOut = createResult.copy(status = "completed")
        var spendResult: ContentBoostSpendOut = ContentBoostSpendOut(spentCents = 250L, remainingCents = 250L)
        var cancelResult: ContentBoostCancelOut =
            ContentBoostCancelOut(boostId = "bst_1", status = "cancelled", refundedCents = 250L)

        /** When set, the next matching call records its input then throws this instead of returning. */
        var throwOnCreate: Throwable? = null

        var lastCreateBody: ContentBoostCreateIn? = null
        var lastGetId: String? = null

        override suspend fun createBoost(body: ContentBoostCreateIn): ContentBoostOut {
            lastCreateBody = body // record BEFORE throwing
            throwOnCreate?.let { throw it }
            return createResult
        }

        override suspend fun getBoost(boostId: String): ContentBoostOut {
            lastGetId = boostId
            return getResult
        }

        override suspend fun getBoostSpend(boostId: String): ContentBoostSpendOut = spendResult

        override suspend fun cancelBoost(boostId: String): ContentBoostCancelOut = cancelResult

        override suspend fun listBoosts(): ContentBoostListResponse = ContentBoostListResponse()
    }

    private fun repo(api: ContentBoostApi): BoostRepositoryImpl =
        BoostRepositoryImpl(api = api, errorParser = ApiErrorParser(Moshi.Builder().build()))

    private fun http422(): HttpException =
        HttpException(Response.error<Any>(422, """{"detail":"bad"}""".toResponseBody("application/json".toMediaType())))

    @Test
    fun createBoost_sendsExactBody_mapsDomain() = runTest {
        val api = FakeBoostApi()
        val result = repo(api).createBoost(
            contentType = "post",
            contentId = "post_9",
            budgetCents = 500L,
            durationSeconds = 3600L,
        )

        assertEquals(ContentBoostCreateIn("post", "post_9", 500L, 3600L), api.lastCreateBody)
        assertTrue(result is ApiResult.Success)
        val boost = (result as ApiResult.Success).data
        assertEquals("bst_1", boost.boostId)
        assertEquals(BoostStatus.ACTIVE, boost.statusEnum)
        assertEquals(500L, boost.budgetCents)
    }

    @Test
    fun getBoost_mapsDomain() = runTest {
        val api = FakeBoostApi()
        val result = repo(api).getBoost("bst_1")
        assertEquals("bst_1", api.lastGetId)
        assertTrue(result is ApiResult.Success)
        assertEquals(BoostStatus.COMPLETED, (result as ApiResult.Success).data.statusEnum)
    }

    @Test
    fun getSpend_mapsDomain() = runTest {
        val result = repo(FakeBoostApi()).getSpend("bst_1")
        assertTrue(result is ApiResult.Success)
        assertEquals(250L, (result as ApiResult.Success).data.spentCents)
    }

    @Test
    fun cancelBoost_mapsRefund() = runTest {
        val result = repo(FakeBoostApi()).cancelBoost("bst_1")
        assertTrue(result is ApiResult.Success)
        assertEquals(250L, (result as ApiResult.Success).data.refundedCents)
    }

    @Test
    fun createBoost_httpError_surfacesFailure_withStatus() = runTest {
        val api = FakeBoostApi().apply { throwOnCreate = http422() }
        val result = repo(api).createBoost("post", "post_9", 500L, 3600L)

        // Body was recorded before the throw.
        assertEquals("post_9", api.lastCreateBody?.contentId)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
