package com.testlogon.android.core.network.donation

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-393 - contract tests for [DonationApi] (the PUBLIC, session-free surface) against MockWebServer with
 * the production-style reflective Moshi. Asserts the verb / path / body / decode for all three endpoints,
 * AND that NO Authorization / Cookie / X-CSRF-Token headers are sent (the api is built on a plain
 * cookieless client here, just as DonationNetworkModule builds a cookieless Retrofit in production). The
 * recorded body is read ONCE; no nested runTest.
 */
class DonationApiContractTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private val mapAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    /** A plain client with NO cookie jar / CSRF / auth interceptor (mirrors the production cookieless one). */
    private fun api(): DonationApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(DonationApi::class.java)

    private fun RecordedRequest.bodyJson(): Map<String, Any?> {
        val raw = body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        return mapAdapter.fromJson(raw) ?: emptyMap()
    }

    private fun RecordedRequest.assertSessionFree() {
        assertNull(getHeader("Authorization"))
        assertNull(getHeader("Cookie"))
        assertNull(getHeader("X-CSRF-Token"))
    }

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
    fun getFundraiser_verb_path_sessionFree_decode() = runTest {
        server.enqueue(jsonResponse(FUNDRAISER_BODY))

        val out = api().getFundraiser("fr_123")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/public/fundraisers/fr_123", recorded.requestUrl?.encodedPath)
        recorded.assertSessionFree()
        val dto = out.body()!!
        assertEquals("fr_123", dto.fundraiserId)
        assertEquals("Westside Library Friends", dto.groupName)
        assertEquals("active", dto.status)
        assertEquals(500000L, dto.goalCents)
        assertEquals(132500L, dto.raisedCents)
        assertEquals(42, dto.donationCount)
        assertEquals("https://x/cover.jpg", dto.coverImageUrl)
    }

    @Test
    fun donate_verb_path_body_sessionFree_decode() = runTest {
        server.enqueue(jsonResponse(DONATION_BODY, code = 201))

        val out = api().donate("fr_123", DonateRequestDto(amountCents = 2500L))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/public/fundraisers/fr_123/donate", recorded.requestUrl?.encodedPath)
        recorded.assertSessionFree()
        val body = recorded.bodyJson()
        assertEquals(2500.0, body["amount_cents"] as Double, 0.0)
        // A truly anonymous donate omits donor fields (null -> not serialized).
        assertTrue(!body.containsKey("donor_email") || body["donor_email"] == null)
        val dto = out.body()!!
        assertEquals("don_789", dto.donationId)
        assertEquals("pending", dto.status)
        assertNull(dto.checkoutUrl)
    }

    @Test
    fun getReceipt_verb_path_sessionFree_decode() = runTest {
        server.enqueue(jsonResponse(RECEIPT_BODY))

        val out = api().getReceipt("fr_123", "don_789")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/public/fundraisers/fr_123/donations/don_789/receipt", recorded.requestUrl?.encodedPath)
        recorded.assertSessionFree()
        val dto = out.body()!!
        assertEquals("don_789", dto.donationId)
        assertEquals("Help Build the Library", dto.fundraiserTitle)
        assertEquals("completed", dto.status)
        assertEquals("usd", dto.currency)
    }

    private companion object {
        val FUNDRAISER_BODY = """
            {
              "fundraiser_id": "fr_123",
              "group_id": "grp_1",
              "group_name": "Westside Library Friends",
              "title": "Help Build the Library",
              "description": "Short blurb",
              "currency": "usd",
              "goal_cents": 500000,
              "raised_cents": 132500,
              "donation_count": 42,
              "status": "active",
              "cover_image_url": "https://x/cover.jpg",
              "ends_at": 1735689600
            }
        """.trimIndent()

        val DONATION_BODY = """
            {
              "donation_id": "don_789",
              "amount_cents": 2500,
              "status": "pending",
              "created_at": 1717804800,
              "donor_name": "Sean P.",
              "is_external": true,
              "checkout_url": null
            }
        """.trimIndent()

        val RECEIPT_BODY = """
            {
              "donation_id": "don_789",
              "amount_cents": 2500,
              "currency": "usd",
              "donor_name": "Sean P.",
              "group_name": "Westside Library Friends",
              "fundraiser_title": "Help Build the Library",
              "created_at": 1717804800,
              "status": "completed"
            }
        """.trimIndent()
    }
}
