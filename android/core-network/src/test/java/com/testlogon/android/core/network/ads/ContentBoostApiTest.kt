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
 * AND-364 - hermetic request-shape / decode tests for the [ContentBoostApi] (mirrors AND-363
 * AdsAccountsApiTest).
 *
 * Everything is hermetic: MockWebServer only, a production-style Moshi (BigDecimalAdapter + the reflective
 * KotlinJsonAdapterFactory, like NetworkModule.provideMoshi - boost DTOs need no enum adapter since status
 * is a raw String), and runTest. Focus: createBoost POSTs ui/ads/boost with EXACTLY
 * {content_type, content_id, budget_cents, duration_seconds} (no payment / account fields); get / spend /
 * cancel hit the right method + path with {boostId} substituted; bare + object bodies decode; a 422 errors.
 * KDoc avoids the comment-terminator character pair.
 */
class ContentBoostApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun boostApi(): ContentBoostApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(ContentBoostApi::class.java)

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

    // ---- createBoost: POST ui/ads/boost ----

    @Test
    fun createBoost_postsBoostPath_withExactBody_decodesOut() = runTest {
        server.enqueue(
            jsonResponse(
                """{"boost_id":"bst_1","status":"active","content_type":"post","content_id":"post_9",
                    "budget_cents":500,"spent_cents":0,"remaining_cents":500,"duration_seconds":3600,
                    "ends_at":1700003600,"created_at":1700000000}""",
            ),
        )

        val out = boostApi().createBoost(
            ContentBoostCreateIn(
                contentType = "post",
                contentId = "post_9",
                budgetCents = 500L,
                durationSeconds = 3600L,
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/ads/boost", recorded.requestUrl?.encodedPath)
        val body = recorded.body.readUtf8()
        assertTrue(body.contains("\"content_type\":\"post\""))
        assertTrue(body.contains("\"content_id\":\"post_9\""))
        assertTrue(body.contains("\"budget_cents\":500"))
        assertTrue(body.contains("\"duration_seconds\":3600"))
        // NO payment / account / currency / daily-budget fields on the wire.
        assertTrue(!body.contains("ads_account"))
        assertTrue(!body.contains("payment_method"))
        assertTrue(!body.contains("currency"))
        assertTrue(!body.contains("daily_budget"))
        assertEquals("bst_1", out.boostId)
        assertEquals("active", out.status)
        assertEquals(500L, out.budgetCents)
        assertEquals(1700003600L, out.endsAt)
    }

    // ---- getBoost: GET ui/ads/boost/{boostId} ----

    @Test
    fun getBoost_substitutesBoostIdPath_decodesOut() = runTest {
        server.enqueue(
            jsonResponse(
                """{"boost_id":"bst_1","status":"completed","budget_cents":500,"spent_cents":500,
                    "remaining_cents":0}""",
            ),
        )

        val out = boostApi().getBoost("bst_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/boost/bst_1", recorded.requestUrl?.encodedPath)
        assertEquals("completed", out.status)
        assertEquals(0L, out.remainingCents)
    }

    // ---- getBoostSpend: GET ui/ads/boost/{boostId}/spend ----

    @Test
    fun getBoostSpend_getsSpendPath_decodesSnapshot() = runTest {
        server.enqueue(
            jsonResponse("""{"boost_id":"bst_1","spent_cents":250,"remaining_cents":250}"""),
        )

        val spend = boostApi().getBoostSpend("bst_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/boost/bst_1/spend", recorded.requestUrl?.encodedPath)
        assertEquals(250L, spend.spentCents)
        assertEquals(250L, spend.remainingCents)
    }

    // ---- cancelBoost: POST ui/ads/boost/{boostId}/cancel ----

    @Test
    fun cancelBoost_postsCancelPath_decodesRefund() = runTest {
        server.enqueue(
            jsonResponse("""{"boost_id":"bst_1","status":"cancelled","refunded_cents":250}"""),
        )

        val cancel = boostApi().cancelBoost("bst_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/ads/boost/bst_1/cancel", recorded.requestUrl?.encodedPath)
        assertEquals("cancelled", cancel.status)
        assertEquals(250L, cancel.refundedCents)
    }

    // ---- listBoosts: GET ui/ads/boost (optional convenience) ----

    @Test
    fun listBoosts_getsBoostPath_decodesEnvelope() = runTest {
        server.enqueue(
            jsonResponse("""{"items":[{"boost_id":"bst_1","status":"active","budget_cents":500}]}"""),
        )

        val list = boostApi().listBoosts()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/boost", recorded.requestUrl?.encodedPath)
        assertEquals(1, list.all.size)
        assertEquals("bst_1", list.all[0].boostId)
    }

    // ---- error surfacing ----

    @Test
    fun getBoost_422_surfacesAsHttpException() = runTest {
        server.enqueue(
            jsonResponse(
                """{"detail":[{"loc":["path","boostId"],"msg":"not found","type":"value_error"}]}""",
                code = 422,
            ),
        )

        val error = runCatching { boostApi().getBoost("missing") }.exceptionOrNull()

        val recorded = server.takeRequest()
        assertEquals("/ui/ads/boost/missing", recorded.requestUrl?.encodedPath)
        assertTrue(error is HttpException)
        assertEquals(422, (error as HttpException).code())
    }
}
