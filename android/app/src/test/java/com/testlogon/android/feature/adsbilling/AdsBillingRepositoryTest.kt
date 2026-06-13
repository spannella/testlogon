package com.testlogon.android.feature.adsbilling

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.ads.AdAccountDto
import com.testlogon.android.core.network.ads.AdAccountStatus
import com.testlogon.android.core.network.ads.AdBillingEntryDto
import com.testlogon.android.core.network.ads.AdCampaignDto
import com.testlogon.android.core.network.ads.AdCampaignStatus
import com.testlogon.android.core.model.ads.AdCampaignStatusDomain
import com.testlogon.android.core.network.ads.AdDepositIn
import com.testlogon.android.core.network.ads.AdDepositOut
import com.testlogon.android.core.network.ads.AdInvoiceCampaignLineDto
import com.testlogon.android.core.network.ads.AdInvoiceDto
import com.testlogon.android.core.network.ads.AdsAccountsApi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepositoryImpl
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-367 - unit tests for [AdsBillingRepositoryImpl] against a FAKE [AdsAccountsApi]. The :app test
 * classpath has no moshi-kotlin reflective adapter, so a MockWebServer + reflective decode is avoided; the
 * fake returns canned DTOs (and RECORDS the deposit body BEFORE it can throw). Confirms account / ledger /
 * invoice / deposit map to domain and that an HttpException (incl. a 400) surfaces as ApiResult.Failure with
 * the status preserved.
 */
class AdsBillingRepositoryTest {

    /** Recording fake api: stores inputs, then returns the canned result or throws the canned error. */
    private class FakeAdsApi : AdsAccountsApi {
        var accountResult: AdAccountDto = AdAccountDto(
            accountId = "acc_1",
            name = "Acme Ads",
            status = AdAccountStatus.ACTIVE,
            balanceCents = 150000L,
            lifetimeSpendCents = 9_500_000_000L,
        )
        var billingResult: List<AdBillingEntryDto> = listOf(
            AdBillingEntryDto(entryType = "charge", amountCents = 2500L, state = "settled", reason = "spend"),
        )
        var invoiceResult: AdInvoiceDto = AdInvoiceDto(
            month = "2026-06",
            totalChargesCents = 750000L,
            totalDepositsCents = 100000L,
            entryCount = 1,
            campaigns = listOf(AdInvoiceCampaignLineDto(campaignId = "cmp_1", totalCents = 500000L)),
        )
        var depositResult: AdDepositOut = AdDepositOut(newBalanceCents = 200000L, status = "ok")

        // AND-369 - canned campaigns list + throw seams for the accounts-list / campaigns reads.
        var campaignsResult: List<AdCampaignDto> = listOf(
            AdCampaignDto(
                campaignId = "cmp_1",
                accountId = "acc_1",
                status = AdCampaignStatus.ACTIVE,
                budgetCents = 500000L,
                dailyBudgetCents = 50000L,
            ),
        )
        var throwOnListAccounts: Throwable? = null
        var throwOnCampaigns: Throwable? = null

        var throwOnDeposit: Throwable? = null

        var lastDepositAccountId: String? = null
        var lastDepositBody: AdDepositIn? = null

        override suspend fun listAdsAccounts(): List<AdAccountDto> {
            throwOnListAccounts?.let { throw it }
            return listOf(accountResult)
        }

        override suspend fun getAdsAccount(accountId: String): AdAccountDto = accountResult

        override suspend fun getAdsAccountBilling(
            accountId: String,
            limit: Int,
        ): List<AdBillingEntryDto> = billingResult

        override suspend fun listAdsAccountCampaigns(accountId: String): List<AdCampaignDto> {
            throwOnCampaigns?.let { throw it }
            return campaignsResult
        }

        override suspend fun getInvoice(accountId: String, month: String): AdInvoiceDto = invoiceResult

        override suspend fun deposit(accountId: String, body: AdDepositIn): AdDepositOut {
            lastDepositAccountId = accountId // record BEFORE throwing
            lastDepositBody = body
            throwOnDeposit?.let { throw it }
            return depositResult
        }

        // AND-368 - analytics endpoints are unused by the billing repo; stubbed so the fake satisfies the
        // extended interface.
        override suspend fun getAnalyticsSummary(
            accountId: String,
            from: String,
            to: String,
        ): com.testlogon.android.core.network.ads.AdAnalyticsSummaryDto =
            com.testlogon.android.core.network.ads.AdAnalyticsSummaryDto(
                impressions = 0L,
                clicks = 0L,
                spendCents = 0L,
                ctrPct = 0.0,
            )

        override suspend fun getAnalyticsTimeseries(
            accountId: String,
            from: String,
            to: String,
        ): List<com.testlogon.android.core.network.ads.AdTimeSeriesPointDto> = emptyList()

        override suspend fun getAnalyticsBreakdown(
            accountId: String,
            dimension: String,
            from: String,
            to: String,
        ): List<com.testlogon.android.core.network.ads.AdBreakdownEntryDto> = emptyList()
    }

    private fun repo(api: AdsAccountsApi): AdsBillingRepositoryImpl =
        AdsBillingRepositoryImpl(api = api, errorParser = ApiErrorParser(Moshi.Builder().build()))

    private fun http400(): HttpException = HttpException(
        Response.error<Any>(
            400,
            """{"detail":"Minimum deposit is 5000 cents"}""".toResponseBody("application/json".toMediaType()),
        ),
    )

    @Test
    fun getAccount_mapsSummary() = runTest {
        val result = repo(FakeAdsApi()).getAccount("acc_1")
        assertTrue(result is ApiResult.Success)
        val summary = (result as ApiResult.Success).data
        assertEquals("Acme Ads", summary.companyName)
        assertEquals(150000L, summary.balanceCents)
        assertEquals(9_500_000_000L, summary.lifetimeSpendCents)
    }

    @Test
    fun getBillingHistory_mapsLedger() = runTest {
        val result = repo(FakeAdsApi()).getBillingHistory("acc_1")
        assertTrue(result is ApiResult.Success)
        val ledger = (result as ApiResult.Success).data
        assertEquals(1, ledger.size)
        assertEquals("charge", ledger[0].entryType)
        assertEquals(2500L, ledger[0].amountCents)
    }

    @Test
    fun getInvoice_mapsInvoiceAndLines() = runTest {
        val result = repo(FakeAdsApi()).getInvoice("acc_1", "2026-06")
        assertTrue(result is ApiResult.Success)
        val invoice = (result as ApiResult.Success).data
        assertEquals("2026-06", invoice.month)
        assertEquals(750000L, invoice.totalChargesCents)
        assertEquals(1, invoice.campaigns.size)
        assertEquals(500000L, invoice.campaigns[0].totalCents)
    }

    @Test
    fun deposit_sendsBody_mapsNewBalance() = runTest {
        val api = FakeAdsApi()
        val result = repo(api).deposit("acc_1", amountCents = 50000L, paymentMethodId = "pm_9")

        assertEquals("acc_1", api.lastDepositAccountId)
        assertEquals(AdDepositIn(amountCents = 50000L, paymentMethodId = "pm_9"), api.lastDepositBody)
        assertTrue(result is ApiResult.Success)
        assertEquals(200000L, (result as ApiResult.Success).data.newBalanceCents)
    }

    @Test
    fun deposit_400_surfacesFailure_withStatus_bodyRecorded() = runTest {
        val api = FakeAdsApi().apply { throwOnDeposit = http400() }
        val result = repo(api).deposit("acc_1", amountCents = 100L)

        // Body was recorded before the throw.
        assertEquals(100L, api.lastDepositBody?.amountCents)
        assertTrue(result is ApiResult.Failure)
        assertEquals(400, (result as ApiResult.Failure).error.status)
    }

    // ---- AND-369 - accounts-list + campaigns reads ----

    @Test
    fun listAccounts_mapsRows() = runTest {
        val result = repo(FakeAdsApi()).listAccounts()
        assertTrue(result is ApiResult.Success)
        val rows = (result as ApiResult.Success).data
        assertEquals(1, rows.size)
        assertEquals("acc_1", rows[0].accountId)
        assertEquals("Acme Ads", rows[0].companyName)
        assertEquals("active", rows[0].status)
        assertEquals(150000L, rows[0].balanceCents)
    }

    @Test
    fun listAccounts_httpError_surfacesFailure_withStatus() = runTest {
        val api = FakeAdsApi().apply { throwOnListAccounts = http400() }
        val result = repo(api).listAccounts()
        assertTrue(result is ApiResult.Failure)
        assertEquals(400, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getCampaigns_mapsRows_statusEnumAndCents() = runTest {
        val result = repo(FakeAdsApi()).getCampaigns("acc_1")
        assertTrue(result is ApiResult.Success)
        val rows = (result as ApiResult.Success).data
        assertEquals(1, rows.size)
        assertEquals("cmp_1", rows[0].campaignId)
        assertEquals("active", rows[0].status)
        assertEquals(AdCampaignStatusDomain.ACTIVE, rows[0].statusEnum)
        assertEquals(500000L, rows[0].budgetCents)
        assertEquals(50000L, rows[0].dailyBudgetCents)
    }

    @Test
    fun getCampaigns_unknownStatus_mapsUnknownSafely() = runTest {
        val api = FakeAdsApi().apply {
            campaignsResult = listOf(AdCampaignDto(campaignId = "cmp_x", status = AdCampaignStatus.UNKNOWN))
        }
        val rows = (repo(api).getCampaigns("acc_1") as ApiResult.Success).data
        assertEquals(AdCampaignStatusDomain.UNKNOWN, rows[0].statusEnum)
        assertEquals("unknown", rows[0].status)
    }

    @Test
    fun getCampaigns_httpError_surfacesFailure_withStatus() = runTest {
        val api = FakeAdsApi().apply { throwOnCampaigns = http400() }
        val result = repo(api).getCampaigns("acc_1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(400, (result as ApiResult.Failure).error.status)
    }
}
