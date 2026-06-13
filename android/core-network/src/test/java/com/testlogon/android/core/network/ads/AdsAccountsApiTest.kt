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
}
