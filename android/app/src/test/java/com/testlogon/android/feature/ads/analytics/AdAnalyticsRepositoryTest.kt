package com.testlogon.android.feature.ads.analytics

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.BreakdownDimension
import com.testlogon.android.core.model.ads.DateRange
import com.testlogon.android.core.network.ads.AdAccountDto
import com.testlogon.android.core.network.ads.AdAnalyticsSummaryDto
import com.testlogon.android.core.network.ads.AdBillingEntryDto
import com.testlogon.android.core.network.ads.AdBreakdownEntryDto
import com.testlogon.android.core.network.ads.AdCampaignDto
import com.testlogon.android.core.network.ads.AdDepositIn
import com.testlogon.android.core.network.ads.AdDepositOut
import com.testlogon.android.core.network.ads.AdTimeSeriesPointDto
import com.testlogon.android.core.network.ads.AdsAccountsApi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.ads.analytics.data.AdAnalyticsRepositoryImpl
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-368 - unit tests for [AdAnalyticsRepositoryImpl] against a FAKE [AdsAccountsApi]. The :app test
 * classpath has no moshi-kotlin reflective adapter, so the fake returns canned DTOs (and RECORDS the query
 * inputs BEFORE it can throw). Confirms summary / timeseries / breakdown map to domain, the breakdown
 * campaign-name join from the AND-363 campaign list, pct kept as-is, cents Long, and that an HttpException
 * surfaces as ApiResult.Failure with the status preserved.
 */
class AdAnalyticsRepositoryTest {

    private val range = DateRange(from = "2026-05-13", to = "2026-06-09")

    /** Recording fake api: stores inputs, then returns the canned result or throws the canned error. */
    private class FakeAnalyticsApi : AdsAccountsApi {
        var summaryResult: AdAnalyticsSummaryDto = AdAnalyticsSummaryDto(
            impressions = 120000L,
            clicks = 3400L,
            spendCents = 250000L,
            ctrPct = 2.83,
            completionRatePct = 88.2,
        )
        var timeseriesResult: List<AdTimeSeriesPointDto> = listOf(
            AdTimeSeriesPointDto(date = "2026-06-08", impressions = 1000L, clicks = 30L, spendCents = 2500L),
        )
        var breakdownResult: List<AdBreakdownEntryDto> = listOf(
            AdBreakdownEntryDto(key = "cmp_1", impressions = 80000L, clicks = 2400L, spendCents = 180000L, ctrPct = 3.0),
            AdBreakdownEntryDto(key = "cmp_2", impressions = 40000L, clicks = 1000L, spendCents = 70000L),
        )
        var campaignsResult: List<AdCampaignDto> = listOf(
            AdCampaignDto(campaignId = "cmp_1", name = "Spring Launch"),
        )

        var throwOnSummary: Throwable? = null
        var throwOnCampaigns: Throwable? = null

        var lastSummaryAccountId: String? = null
        var lastSummaryFrom: String? = null
        var lastSummaryTo: String? = null
        var lastBreakdownDimension: String? = null

        override suspend fun listAdsAccounts(): List<AdAccountDto> = emptyList()
        override suspend fun getAdsAccount(accountId: String): AdAccountDto =
            AdAccountDto(accountId = accountId, balanceCents = 0L, lifetimeSpendCents = 0L)
        override suspend fun getAdsAccountBilling(accountId: String, limit: Int): List<AdBillingEntryDto> =
            emptyList()

        override suspend fun listAdsAccountCampaigns(accountId: String): List<AdCampaignDto> {
            throwOnCampaigns?.let { throw it }
            return campaignsResult
        }

        override suspend fun getInvoice(accountId: String, month: String) =
            throw UnsupportedOperationException("unused")

        override suspend fun deposit(accountId: String, body: AdDepositIn): AdDepositOut =
            throw UnsupportedOperationException("unused")

        override suspend fun getAnalyticsSummary(
            accountId: String,
            from: String,
            to: String,
        ): AdAnalyticsSummaryDto {
            lastSummaryAccountId = accountId // record BEFORE throwing
            lastSummaryFrom = from
            lastSummaryTo = to
            throwOnSummary?.let { throw it }
            return summaryResult
        }

        override suspend fun getAnalyticsTimeseries(
            accountId: String,
            from: String,
            to: String,
        ): List<AdTimeSeriesPointDto> = timeseriesResult

        override suspend fun getAnalyticsBreakdown(
            accountId: String,
            dimension: String,
            from: String,
            to: String,
        ): List<AdBreakdownEntryDto> {
            lastBreakdownDimension = dimension
            return breakdownResult
        }

        // ADV-107/108/109/501 — create/mutate/ROAS endpoints; not exercised by the analytics-read tests.
        override suspend fun createAdsAccount(body: com.testlogon.android.core.network.ads.AdAccountCreateIn) = error("unused")
        override suspend fun createCampaign(accountId: String, body: com.testlogon.android.core.network.ads.AdCampaignCreateIn) = error("unused")
        override suspend fun submitCampaign(accountId: String, campaignId: String) = error("unused")
        override suspend fun getCampaign(accountId: String, campaignId: String) = error("unused")
        override suspend fun updateCampaign(accountId: String, campaignId: String, body: com.testlogon.android.core.network.ads.AdCampaignUpdateIn) = error("unused")
        override suspend fun createCreative(campaignId: String, body: com.testlogon.android.core.network.ads.AdCreativeCreateIn) = error("unused")
        override suspend fun uploadCreativeAsset(campaignId: String, creativeId: String, file: okhttp3.MultipartBody.Part, assetType: okhttp3.RequestBody) = error("unused")
        override suspend fun submitCreative(campaignId: String, creativeId: String) = error("unused")
        override suspend fun getRoas(accountId: String, campaignId: String?, days: Int) = error("unused")
    }

    private fun repo(api: AdsAccountsApi): AdAnalyticsRepositoryImpl =
        AdAnalyticsRepositoryImpl(api = api, errorParser = ApiErrorParser(Moshi.Builder().build()))

    private fun http500(): HttpException = HttpException(
        Response.error<Any>(500, """{"detail":"boom"}""".toResponseBody("application/json".toMediaType())),
    )

    @Test
    fun getSummary_mapsDomain_pctKeptAsIs_andSendsRange() = runTest {
        val api = FakeAnalyticsApi()
        val result = repo(api).getSummary("acc_1", range)

        assertEquals("acc_1", api.lastSummaryAccountId)
        assertEquals("2026-05-13", api.lastSummaryFrom)
        assertEquals("2026-06-09", api.lastSummaryTo)
        assertTrue(result is ApiResult.Success)
        val summary = (result as ApiResult.Success).data
        assertEquals(120000L, summary.impressions)
        assertEquals(250000L, summary.spendCents)
        // ctr_pct already a percentage - NOT multiplied by 100.
        assertEquals(2.83, summary.ctrPct, 0.0001)
        assertEquals(88.2, summary.completionRatePct!!, 0.0001)
    }

    @Test
    fun getTimeseries_mapsBareArray() = runTest {
        val result = repo(FakeAnalyticsApi()).getTimeseries("acc_1", range)
        assertTrue(result is ApiResult.Success)
        val points = (result as ApiResult.Success).data
        assertEquals(1, points.size)
        assertEquals("2026-06-08", points[0].date)
        assertEquals(2500L, points[0].spendCents)
    }

    @Test
    fun getBreakdown_mapsRows_joinsCampaignName_sendsCreativeDimension() = runTest {
        val api = FakeAnalyticsApi()
        val result = repo(api).getBreakdown("acc_1", BreakdownDimension.CREATIVE, range)

        assertEquals("creative", api.lastBreakdownDimension)
        assertTrue(result is ApiResult.Success)
        val rows = (result as ApiResult.Success).data
        assertEquals(2, rows.size)
        // cmp_1 joined to its campaign name; cmp_2 has no name -> null.
        assertEquals("Spring Launch", rows[0].campaignName)
        assertEquals("cmp_1", rows[0].key)
        assertEquals(180000L, rows[0].spendCents)
        assertEquals(3.0, rows[0].ctrPct!!, 0.0001)
        assertNull(rows[1].campaignName)
    }

    @Test
    fun getBreakdown_campaignListFailure_doesNotFailBreakdown_namesNull() = runTest {
        val api = FakeAnalyticsApi().apply { throwOnCampaigns = http500() }
        val result = repo(api).getBreakdown("acc_1", BreakdownDimension.CREATIVE, range)

        assertTrue(result is ApiResult.Success)
        val rows = (result as ApiResult.Success).data
        assertEquals(2, rows.size)
        assertNull(rows[0].campaignName) // join failed gracefully
    }

    @Test
    fun getSummary_httpError_surfacesFailure_withStatus() = runTest {
        val api = FakeAnalyticsApi().apply { throwOnSummary = http500() }
        val result = repo(api).getSummary("acc_1", range)

        // The query was recorded before the throw.
        assertEquals("acc_1", api.lastSummaryAccountId)
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
    }
}
