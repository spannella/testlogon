package com.testlogon.android.core.network.ads

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-363 - hermetic request-shape / decode tests for the [AdsAccountsApi] (mirrors AND-353 OrgsApiTest).
 *
 * Everything is hermetic: MockWebServer only, a production-style Moshi (BigDecimalAdapter + the two ads
 * enum adapters + the reflective KotlinJsonAdapterFactory, like NetworkModule.provideMoshi), and runTest.
 * No real dev host. core-network has no test dependency on :core-testing, so the JSON bodies are inline.
 * Focus: each endpoint hits the right METHOD + relative PATH, {accountId} is substituted, billing sends
 * ?limit=, the bare-array bodies decode into List<>, and a 422 surfaces as HttpException. KDoc avoids the
 * comment-terminator character pair.
 */
class AdsAccountsApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(AdAccountStatusAdapter)
        .add(AdCampaignStatusAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun adsApi(): AdsAccountsApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(AdsAccountsApi::class.java)

    private fun jsonResponse(body: String, code: Int = 200) =
        MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)

    @Before
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    // ---- listAdsAccounts: GET ui/ads/accounts -> BARE ARRAY ----

    @Test
    fun listAdsAccounts_getsAccountsPath_decodesBareArray() = runTest {
        server.enqueue(
            jsonResponse(
                """[
                    {"account_id":"acc_1","name":"Acme Ads","status":"active",
                     "balance_cents":12345,"lifetime_spend_cents":99999},
                    {"account_id":"acc_2","balance_cents":0,"lifetime_spend_cents":0}
                ]""",
            ),
        )

        val accounts = adsApi().listAdsAccounts()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/accounts", recorded.requestUrl?.encodedPath)
        assertEquals(2, accounts.size)
        assertEquals("acc_1", accounts[0].accountId)
        assertEquals(AdAccountStatus.ACTIVE, accounts[0].status)
        assertEquals(12345L, accounts[0].balanceCents)
        // sparse row: status defaults to UNKNOWN, name null
        assertEquals(AdAccountStatus.UNKNOWN, accounts[1].status)
    }

    // ---- getAdsAccount: GET ui/ads/accounts/{accountId} -> single DTO ----

    @Test
    fun getAdsAccount_substitutesAccountIdPath_decodesSingle() = runTest {
        server.enqueue(
            jsonResponse(
                """{"account_id":"acc_1","name":"Acme Ads","status":"suspended",
                    "balance_cents":500,"lifetime_spend_cents":7000,"created_at":1700000000}""",
            ),
        )

        val account = adsApi().getAdsAccount("acc_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/accounts/acc_1", recorded.requestUrl?.encodedPath)
        assertEquals("acc_1", account.accountId)
        assertEquals(AdAccountStatus.SUSPENDED, account.status)
        assertEquals(1700000000L, account.createdAt)
    }

    // ---- getAdsAccountBilling: GET ui/ads/accounts/{accountId}/billing?limit= -> BARE ARRAY ----

    @Test
    fun getAdsAccountBilling_sendsLimitQuery_decodesBareArray() = runTest {
        server.enqueue(
            jsonResponse(
                """[
                    {"entry_id":"ent_1","amount_cents":2500,"type":"charge","description":"daily spend"},
                    {"amount_cents":-1000,"type":"credit"}
                ]""",
            ),
        )

        val entries = adsApi().getAdsAccountBilling("acc_1", limit = 25)

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/accounts/acc_1/billing", recorded.requestUrl?.encodedPath)
        assertEquals("25", recorded.requestUrl?.queryParameter("limit"))
        assertEquals(2, entries.size)
        assertEquals(2500L, entries[0].amountCents)
        assertEquals(-1000L, entries[1].amountCents)
    }

    @Test
    fun getAdsAccountBilling_defaultsLimitTo50() = runTest {
        server.enqueue(jsonResponse("""[]"""))

        adsApi().getAdsAccountBilling("acc_1")

        val recorded = server.takeRequest()
        assertEquals("/ui/ads/accounts/acc_1/billing", recorded.requestUrl?.encodedPath)
        assertEquals("50", recorded.requestUrl?.queryParameter("limit"))
    }

    // ---- listAdsAccountCampaigns: GET ui/ads/accounts/{accountId}/campaigns -> BARE ARRAY ----

    @Test
    fun listAdsAccountCampaigns_getsCampaignsPath_decodesBareArray() = runTest {
        server.enqueue(
            jsonResponse(
                """[
                    {"campaign_id":"cmp_1","account_id":"acc_1","name":"Spring","status":"active",
                     "budget_cents":100000,"spent_today_cents":2500}
                ]""",
            ),
        )

        val campaigns = adsApi().listAdsAccountCampaigns("acc_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/accounts/acc_1/campaigns", recorded.requestUrl?.encodedPath)
        assertEquals(1, campaigns.size)
        assertEquals("cmp_1", campaigns[0].campaignId)
        assertEquals(AdCampaignStatus.ACTIVE, campaigns[0].status)
        assertEquals(100000L, campaigns[0].budgetCents)
    }

    // ---- error surfacing ----

    @Test
    fun getAdsAccount_422_surfacesAsHttpException() = runTest {
        server.enqueue(
            jsonResponse(
                """{"detail":[{"loc":["path","accountId"],"msg":"not found","type":"value_error"}]}""",
                code = 422,
            ),
        )

        val error = runCatching { adsApi().getAdsAccount("missing") }.exceptionOrNull()

        val recorded = server.takeRequest()
        assertEquals("/ui/ads/accounts/missing", recorded.requestUrl?.encodedPath)
        assertTrue(error is HttpException)
        assertEquals(422, (error as HttpException).code())
    }

    @Test
    fun listAdsAccounts_500_surfacesAsHttpException() = runTest {
        server.enqueue(MockResponse().setResponseCode(500))

        val error = runCatching { adsApi().listAdsAccounts() }.exceptionOrNull()

        assertTrue(error is HttpException)
        assertEquals(500, (error as HttpException).code())
    }

    // ---- AND-367: getInvoice GET ui/ads/accounts/{accountId}/invoices/{month} -> AdInvoiceDto ----

    @Test
    fun getInvoice_substitutesAccountIdAndMonth_decodesCampaignLines() = runTest {
        server.enqueue(
            jsonResponse(
                """{"month":"2026-06","total_charges_cents":750000,"total_deposits_cents":100000,
                    "entry_count":3,
                    "campaigns":[
                        {"campaign_id":"cmp_1","impressions":12000,"clicks":340,"conversions":12,
                         "total_cents":500000},
                        {"campaign_id":"cmp_2","total_cents":250000}
                    ]}""",
            ),
        )

        val invoice = adsApi().getInvoice("acc_1", "2026-06")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/accounts/acc_1/invoices/2026-06", recorded.requestUrl?.encodedPath)
        assertEquals("2026-06", invoice.month)
        assertEquals(750000L, invoice.totalChargesCents)
        assertEquals(100000L, invoice.totalDepositsCents)
        assertEquals(3, invoice.entryCount)
        assertEquals(2, invoice.campaigns.size)
        assertEquals("cmp_1", invoice.campaigns[0].campaignId)
        assertEquals(12000L, invoice.campaigns[0].impressions)
        assertEquals(500000L, invoice.campaigns[0].totalCents)
        // sparse line: counts null
        assertEquals("cmp_2", invoice.campaigns[1].campaignId)
        assertEquals(null, invoice.campaigns[1].impressions)
    }

    // ---- AND-367: deposit POST ui/ads/accounts/{accountId}/deposit ----

    @Test
    fun deposit_postsAmountAndPaymentMethod_decodesNewBalance() = runTest {
        server.enqueue(jsonResponse("""{"new_balance_cents":155000,"status":"ok"}"""))

        val out = adsApi().deposit("acc_1", AdDepositIn(amountCents = 50000L, paymentMethodId = "pm_9"))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/ads/accounts/acc_1/deposit", recorded.requestUrl?.encodedPath)
        val body = recorded.body.readUtf8()
        assertTrue(body.contains("\"amount_cents\":50000"))
        assertTrue(body.contains("\"payment_method_id\":\"pm_9\""))
        assertEquals(155000L, out.newBalanceCents)
        assertEquals("ok", out.status)
    }

    @Test
    fun deposit_omitsNullPaymentMethod() = runTest {
        server.enqueue(jsonResponse("""{"new_balance_cents":50000}"""))

        adsApi().deposit("acc_1", AdDepositIn(amountCents = 50000L))

        val recorded = server.takeRequest()
        val body = recorded.body.readUtf8()
        assertTrue(body.contains("\"amount_cents\":50000"))
        // null payment_method_id is omitted by Moshi's non-serialize-nulls default.
        assertTrue(!body.contains("payment_method_id"))
    }

    @Test
    fun deposit_400_surfacesAsHttpException() = runTest {
        server.enqueue(
            jsonResponse("""{"detail":"Minimum deposit is 5000 cents"}""", code = 400),
        )

        val error = runCatching {
            adsApi().deposit("acc_1", AdDepositIn(amountCents = 100L))
        }.exceptionOrNull()

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/ads/accounts/acc_1/deposit", recorded.requestUrl?.encodedPath)
        assertTrue(error is HttpException)
        assertEquals(400, (error as HttpException).code())
    }

    // ---- AND-368: getAnalyticsSummary GET ui/ads/analytics/summary?account_id=&from=&to= ----

    @Test
    fun getAnalyticsSummary_sendsAccountAndRangeQuery_decodesSingle() = runTest {
        server.enqueue(
            jsonResponse(
                """{"impressions":120000,"clicks":3400,"spend_cents":250000,"ctr_pct":2.83,
                    "cpa_cents":7350,"effective_cpm_cents":2083,"completes":900,"skips":120,
                    "completion_rate_pct":88.2,"impressions_change_pct":4.5,"ctr_change_pct":-1.2}""",
            ),
        )

        val summary = adsApi().getAnalyticsSummary("acc_1", from = "2026-05-13", to = "2026-06-09")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/analytics/summary", recorded.requestUrl?.encodedPath)
        assertEquals("acc_1", recorded.requestUrl?.queryParameter("account_id"))
        assertEquals("2026-05-13", recorded.requestUrl?.queryParameter("from"))
        assertEquals("2026-06-09", recorded.requestUrl?.queryParameter("to"))
        assertEquals(120000L, summary.impressions)
        assertEquals(3400L, summary.clicks)
        assertEquals(250000L, summary.spendCents)
        // ctr_pct is already a percentage (decoded as-is, NOT multiplied).
        assertEquals(2.83, summary.ctrPct, 0.0001)
        assertEquals(88.2, summary.completionRatePct!!, 0.0001)
        assertEquals(4.5, summary.impressionsChangePct!!, 0.0001)
        assertEquals(-1.2, summary.ctrChangePct!!, 0.0001)
    }

    // ---- AND-368: getAnalyticsTimeseries GET ui/ads/analytics/timeseries -> BARE ARRAY ----

    @Test
    fun getAnalyticsTimeseries_sendsRangeQuery_decodesBareArray() = runTest {
        server.enqueue(
            jsonResponse(
                """[
                    {"date":"2026-06-08","impressions":1000,"clicks":30,"spend_cents":2500},
                    {"ts":1749513600,"impressions":1200,"clicks":36,"spend_cents":3000}
                ]""",
            ),
        )

        val points = adsApi().getAnalyticsTimeseries("acc_1", from = "2026-06-08", to = "2026-06-09")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/analytics/timeseries", recorded.requestUrl?.encodedPath)
        assertEquals("acc_1", recorded.requestUrl?.queryParameter("account_id"))
        assertEquals("2026-06-08", recorded.requestUrl?.queryParameter("from"))
        assertEquals(2, points.size)
        assertEquals("2026-06-08", points[0].date)
        assertEquals(2500L, points[0].spendCents)
        // second point identifies its bucket via ts, not date.
        assertEquals(1749513600L, points[1].ts)
        assertEquals(36L, points[1].clicks)
    }

    // ---- AND-368: getAnalyticsBreakdown GET ui/ads/analytics/breakdown?dimension= -> BARE ARRAY ----

    @Test
    fun getAnalyticsBreakdown_sendsDimensionQuery_decodesBareArray() = runTest {
        server.enqueue(
            jsonResponse(
                """[
                    {"key":"cmp_1","impressions":80000,"clicks":2400,"spend_cents":180000,"ctr_pct":3.0},
                    {"dimension_value":"cmp_2","impressions":40000,"clicks":1000,"spend_cents":70000}
                ]""",
            ),
        )

        val rows = adsApi().getAnalyticsBreakdown(
            "acc_1",
            dimension = "creative",
            from = "2026-05-13",
            to = "2026-06-09",
        )

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/analytics/breakdown", recorded.requestUrl?.encodedPath)
        assertEquals("acc_1", recorded.requestUrl?.queryParameter("account_id"))
        assertEquals("creative", recorded.requestUrl?.queryParameter("dimension"))
        assertEquals(2, rows.size)
        assertEquals("cmp_1", rows[0].key)
        assertEquals(180000L, rows[0].spendCents)
        assertEquals(3.0, rows[0].ctrPct!!, 0.0001)
        // second row carries dimension_value instead of key; ctr omitted.
        assertEquals("cmp_2", rows[1].dimensionValue)
        assertEquals(null, rows[1].ctrPct)
    }
}
