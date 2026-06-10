package com.testlogon.android.data.messaging.mass

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-160 — contract tests for [MassMessageRepositoryImpl] against MockWebServer, asserting the REAL
 * wire contract: list cursor paging, create request shape (conversation_ids + content.text +
 * idempotency_key), 422 failure, and the cancel path/shape.
 */
class MassMessageRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): MassMessageRepositoryImpl {
        val api = backend.retrofit(moshi).create(MassMessageApi::class.java)
        return MassMessageRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun listPage_mapsItemsAndCursor() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"items":[
                  {"campaign_id":"mmc_1","mode":"scheduled","status":"processing",
                   "send_at":1760003600,"created_at":1760003500,"updated_at":1760003600,
                   "counters":{"total":3,"queued":1,"sent":1,"failed":0,"cancelled":1}}
                ],"next_cursor":"CUR2"}
                """.trimIndent(),
            ),
        )
        val r = repo().listPage(cursor = null, limit = 20, status = null, mode = null)
        assertTrue(r is ApiResult.Success)
        val page = (r as ApiResult.Success).data
        assertEquals(1, page.items.size)
        assertEquals("mmc_1", page.items.single().id)
        assertEquals(CampaignStatus.PROCESSING, page.items.single().status)
        assertEquals("CUR2", page.nextCursor)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/mass-messages", req.requestUrl?.encodedPath)
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun listPage_nullCursorWhenAbsent() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[],"next_cursor":null}"""))
        val r = repo().listPage(cursor = "X", limit = 20, status = "processing", mode = "immediate")
        assertTrue(r is ApiResult.Success)
        assertNull((r as ApiResult.Success).data.nextCursor)
        val req = backend.takeRequest()
        assertEquals("X", req.requestUrl?.queryParameter("cursor"))
        assertEquals("processing", req.requestUrl?.queryParameter("status"))
        assertEquals("immediate", req.requestUrl?.queryParameter("mode"))
    }

    @Test
    fun create_postsConversationIdsAndContentText() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"campaign_id":"mmc_9","mode":"immediate","status":"pending","accepted_count":2,
                 "accepted_conversation_ids":["c1","c2"],
                 "rejected":[{"conversation_id":"c3","reason":"not_a_participant"}],
                 "send_at":null,"created_at":1760000000,"updated_at":1760000000,
                 "counters":{"total":2,"queued":2,"sent":0,"failed":0,"cancelled":0}}
                """.trimIndent(),
                code = 201,
            ),
        )
        val r = repo().create(
            CreateCampaignDraft(
                text = "hi there",
                conversationIds = listOf("c1", "c2", "c3"),
                mode = CampaignMode.IMMEDIATE,
                idempotencyKey = "idem12345678",
            ),
        )
        assertTrue(r is ApiResult.Success)
        val result = (r as ApiResult.Success).data
        assertEquals(2, result.acceptedCount)
        assertEquals(1, result.rejected.size)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/mass-messages", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals(listOf("c1", "c2", "c3"), body["conversation_ids"])
        @Suppress("UNCHECKED_CAST")
        val content = body["content"] as Map<String, Any?>
        assertEquals("text", content["kind"])
        assertEquals("hi there", content["text"])
        assertEquals("immediate", body["mode"])
        assertEquals("idem12345678", body["idempotency_key"])
    }

    @Test
    fun create_scheduledSendsSendAt() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"campaign_id":"m","mode":"scheduled","status":"scheduled","accepted_count":1,
                   "accepted_conversation_ids":["c1"],"rejected":[],"send_at":1760003600,
                   "created_at":1,"updated_at":1,"counters":{"total":1}}""",
                code = 201,
            ),
        )
        repo().create(
            CreateCampaignDraft(
                text = "later",
                conversationIds = listOf("c1"),
                mode = CampaignMode.SCHEDULED,
                sendAtEpochSeconds = 1760003600,
                idempotencyKey = "idem12345678",
            ),
        )
        val body = backend.takeRequest().bodyJson()
        assertEquals("scheduled", body["mode"])
        assertEquals(1760003600L, (body["send_at"] as Number).toLong()) // JSON number
    }

    @Test
    fun create_422_isFailure() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["body","content","text"],"msg":"too short","type":"string_too_short"}]""", 422),
        )
        val r = repo().create(CreateCampaignDraft(text = "", conversationIds = listOf("c1")))
        assertTrue(r is ApiResult.Failure)
        assertEquals(422, (r as ApiResult.Failure).error.status)
    }

    @Test
    fun cancel_postsCorrectPathAndMapsStatus() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"campaign_id":"mmc_5","status":"cancelled","cancelled_destinations":4,
                   "updated_at":1760005000,"counters":{"total":10,"sent":6,"cancelled":4}}""",
            ),
        )
        val r = repo().cancel("mmc_5")
        assertTrue(r is ApiResult.Success)
        assertEquals(CampaignStatus.CANCELLED, (r as ApiResult.Success).data.status)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/mass-messages/mmc_5/cancel", req.requestUrl?.encodedPath)
    }
}
