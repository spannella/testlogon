package com.testlogon.android.data.messaging

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import retrofit2.HttpException

/**
 * AND-151 / AND-152 — MockWebServer contract tests for the two message-search endpoints.
 *
 * Verifies (against the real OpenAPI contract): the resolved path, GET verb, query params
 * (q + limit; sender_id + after_ts for global), and decode of the BARE MessageOut[] array including a
 * null `text` item and integer (epoch-seconds) `created_at`. There is no envelope / no next_cursor.
 */
class MessageSearchApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): MessagingApi = backend.retrofit(moshi).create(MessagingApi::class.java)

    @Test
    fun searchInConversation_decodesBareArray_sendsQueryAndLimit() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [
                  {"conversation_id":"conv_1","message_id":"m1","sender_id":"usr_1",
                   "created_at":1746210060,"kind":"text","text":"we deploy to prod"},
                  {"conversation_id":"conv_1","message_id":"m2","sender_id":"usr_2",
                   "created_at":1746210070,"kind":"image","text":null}
                ]
                """.trimIndent(),
            ),
        )
        val list = api().searchInConversation("conv_1", "deploy", limit = 200)
        assertEquals(2, list.size)
        assertEquals("m1", list[0].messageId)
        assertEquals(1746210060L, list[0].createdAt)
        assertNull(list[1].text) // null text decodes

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/conversations/conv_1/messages/search", req.requestUrl?.encodedPath)
        assertEquals("deploy", req.requestUrl?.queryParameter("q"))
        assertEquals("200", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun searchAll_decodesCrossConversationArray_sendsAllParams() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [
                  {"conversation_id":"conv_a","message_id":"m1","sender_id":"usr_1",
                   "created_at":1746210060,"kind":"text","text":"deploy a"},
                  {"conversation_id":"conv_b","message_id":"m2","sender_id":"usr_1",
                   "created_at":1746210070,"kind":"text","text":"deploy b"}
                ]
                """.trimIndent(),
            ),
        )
        val list = api().searchAllMessages(
            query = "deploy",
            senderId = "usr_1",
            afterTs = 1746057600L,
            limit = 200,
        )
        assertEquals(2, list.size)
        assertEquals(setOf("conv_a", "conv_b"), list.map { it.conversationId }.toSet())

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/messages/search", req.requestUrl?.encodedPath)
        assertEquals("deploy", req.requestUrl?.queryParameter("q"))
        assertEquals("usr_1", req.requestUrl?.queryParameter("sender_id"))
        assertEquals("1746057600", req.requestUrl?.queryParameter("after_ts"))
        assertEquals("200", req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("cursor")) // no pagination
    }

    @Test
    fun searchAll_omitsNullFilters() = runTest {
        backend.enqueue(Fixtures.okBody("[]"))
        api().searchAllMessages(query = "hi", senderId = null, afterTs = null, limit = 200)
        val req = backend.takeRequest()
        assertNull(req.requestUrl?.queryParameter("sender_id"))
        assertNull(req.requestUrl?.queryParameter("after_ts"))
    }

    @Test
    fun searchInConversation_422_throwsHttpException() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["query","q"],"msg":"too long","type":"value_error"}]""",
                code = 422,
            ),
        )
        var threw = false
        try {
            api().searchInConversation("conv_1", "x".repeat(201), limit = 200)
        } catch (e: HttpException) {
            threw = true
            assertEquals(422, e.code())
        }
        assertTrue(threw)
    }
}
