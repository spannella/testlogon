package com.testlogon.android.core.network.collaborations

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-358 - hermetic request-shape / decode tests for the [CollaborationsApi] (mirrors AND-356
 * SyndicateApiTest).
 *
 * Everything is hermetic: MockWebServer only, a production-style Moshi (BigDecimalAdapter + the reflective
 * KotlinJsonAdapterFactory, like NetworkModule.provideMoshi), and runTest. core-network has no test dependency
 * on core-testing, so the JSON bodies are inline. KDoc avoids the comment-terminator pair.
 */
class CollaborationsApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun api(): CollaborationsApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(CollaborationsApi::class.java)

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
    fun listCollaborations_decodesItems_andNextCursor() = runTest {
        server.enqueue(
            jsonResponse(
                """{"items":[
                     {"collab_id":"c1","title":"Track","status":"active",
                      "initiator_id":"usr_a","recipient_id":"usr_b",
                      "split":{"usr_a":60,"usr_b":40},"created_at":1780000000},
                     {"collab_id":"c2","title":"Photo","status":"proposed"}
                   ],"next_cursor":"cur2"}""",
            ),
        )

        val out = api().listCollaborations(cursor = "cur1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/collaborations", recorded.requestUrl?.encodedPath)
        assertEquals("cur1", recorded.requestUrl?.queryParameter("cursor"))
        assertEquals(2, out.items?.size)
        assertEquals("c1", out.items?.get(0)?.collabId)
        assertEquals("cur2", out.nextCursor)
    }

    @Test
    fun listCollaborations_decodesCollaborationsKeyVariant() = runTest {
        server.enqueue(
            jsonResponse("""{"collaborations":[{"collab_id":"c9","title":"X"}]}""")
        )

        val out = api().listCollaborations()

        server.takeRequest()
        assertEquals(1, out.collaborations?.size)
        assertEquals("c9", out.collaborations?.get(0)?.collabId)
    }

    @Test
    fun getCollaboration_decodesSplitMap_andSubstitutesCollabIdPath() = runTest {
        server.enqueue(
            jsonResponse(
                """{"collab_id":"c1","title":"Track","description":"a song",
                    "status":"active","initiator_id":"usr_a","recipient_id":"usr_b",
                    "split":{"usr_a":60,"usr_b":40},"created_at":1780000000,
                    "updated_at":1780000500}""",
            ),
        )

        val collab = api().getCollaboration("c1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/collaborations/c1", recorded.requestUrl?.encodedPath)
        assertEquals("Track", collab.title)
        assertEquals("active", collab.status)
        assertEquals("usr_a", collab.initiatorId)
        assertEquals("usr_b", collab.recipientId)
        assertEquals(60, collab.split?.get("usr_a"))
        assertEquals(40, collab.split?.get("usr_b"))
        assertEquals(1780000000L, collab.createdAt)
        assertEquals(1780000500L, collab.updatedAt)
    }

    @Test
    fun getSplits_decodesDistributions_withAmountCents_andSubstitutesPath() = runTest {
        server.enqueue(
            jsonResponse(
                """{"records":[
                     {"record_id":"r1","created_at":1780000000,"distributions":[
                       {"user_id":"usr_a","percentage":60,"amount_cents":6000},
                       {"user_id":"usr_b","percentage":40,"amount_cents":4000}
                     ]}
                   ]}""",
            ),
        )

        val out = api().getSplits("c1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/collaborations/c1/splits", recorded.requestUrl?.encodedPath)
        val dists = out.records?.single()?.distributions
        assertEquals(2, dists?.size)
        assertEquals("usr_a", dists?.get(0)?.userId)
        assertEquals(60, dists?.get(0)?.percentage)
        assertEquals(6000, dists?.get(0)?.amountCents)
        assertEquals(4000, dists?.get(1)?.amountCents)
    }
}
