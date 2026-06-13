package com.testlogon.android.core.network.sponsorship

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-365 - hermetic request-shape / decode tests for the [SponsorshipApi] (mirrors AND-363 AdsAccountsApiTest).
 *
 * Everything is hermetic: MockWebServer only, a production-style Moshi (BigDecimalAdapter + the reflective
 * KotlinJsonAdapterFactory, like NetworkModule.provideMoshi - no enum adapter needed since status decodes as a
 * raw String), and runTest. core-network has no test dependency on core-testing, so the JSON bodies are
 * inline. Focus: the single GET hits the right METHOD + relative PATH with NO query params, the bare-array
 * body decodes into a List, and a 500 surfaces as HttpException. KDoc avoids the comment-terminator pair.
 */
class SponsorshipApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun sponsorshipApi(): SponsorshipApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(SponsorshipApi::class.java)

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

    @Test
    fun listDeals_getsSponsorshipsPath_noQueryParams_decodesBareArray() = runTest {
        server.enqueue(
            jsonResponse(
                """[
                    {"deal_id":"d1","advertiser_sub":"adv_1","brief":"Promote our new app",
                     "status":"proposed","compensation_cents":250000,"deadline":"2026-07-01",
                     "created_at":1700000000},
                    {"deal_id":"d2","status":"accepted","compensation_cents":0}
                ]""",
            ),
        )

        val deals = sponsorshipApi().listDeals()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/sponsorships", recorded.requestUrl?.encodedPath)
        // single GET, no query params
        assertNull(recorded.requestUrl?.query)
        assertEquals(2, deals.size)
        assertEquals("d1", deals[0].dealId)
        assertEquals("adv_1", deals[0].advertiserSub)
        assertEquals("proposed", deals[0].status)
        assertEquals(250000L, deals[0].compensationCents)
        assertEquals("2026-07-01", deals[0].deadline)
        assertEquals(1700000000L, deals[0].createdAt)
        // sparse row: optional fields null
        assertNull(deals[1].advertiserSub)
        assertNull(deals[1].brief)
        assertNull(deals[1].deadline)
    }

    @Test
    fun listDeals_emptyArray_decodesEmptyList() = runTest {
        server.enqueue(jsonResponse("""[]"""))

        val deals = sponsorshipApi().listDeals()

        val recorded = server.takeRequest()
        assertEquals("/ui/ads/sponsorships", recorded.requestUrl?.encodedPath)
        assertTrue(deals.isEmpty())
    }

    @Test
    fun listDeals_500_surfacesAsHttpException() = runTest {
        server.enqueue(MockResponse().setResponseCode(500))

        val error = runCatching { sponsorshipApi().listDeals() }.exceptionOrNull()

        assertTrue(error is HttpException)
        assertEquals(500, (error as HttpException).code())
    }
}
