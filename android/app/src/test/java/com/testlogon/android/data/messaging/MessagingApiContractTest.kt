package com.testlogon.android.data.messaging

import com.squareup.moshi.Moshi
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
import retrofit2.HttpException

/**
 * AND-120 — MockWebServer contract tests for [MessagingApi]: verb, resolved path, query params,
 * request body, and decode-vs-payload for each endpoint. Verifies the verified wire shapes
 * (bare arrays, epoch-second Long timestamps, `text` body, empty markRead body).
 */
class MessagingApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): MessagingApi = backend.retrofit(moshi).create(MessagingApi::class.java)

    @Test
    fun config_decodesFeatureFlags() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"messaging_gallery_enabled":true,"messaging_pins_enabled":true}""",
            ),
        )
        val config = api().config()
        assertTrue(config.galleryEnabled)
        assertTrue(config.pinsEnabled)
        assertEquals("/messaging/config", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun listConversations_decodesBareArray_noQueryParams() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [
                  {"conversation_id":"conv_1","type":"dm","created_at":1749126600,
                   "created_by":"usr_1","participant_count":2,"status":"active",
                   "unread_count":2,"last_message_at":1749126600,
                   "last_message_preview":"see you then",
                   "last_message":{"message_id":"m9","conversation_id":"conv_1",
                     "sender_id":"usr_2","created_at":1749126600,"kind":"text","text":"see you then"}}
                ]
                """.trimIndent(),
            ),
        )
        val list = api().listConversations()
        assertEquals(1, list.size)
        assertEquals("conv_1", list[0].conversationId)
        assertEquals(2, list[0].unreadCount)
        assertEquals(1749126600L, list[0].createdAt)
        assertEquals("usr_2", list[0].lastMessage?.senderId)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/conversations", req.requestUrl?.encodedPath)
        assertNull(req.requestUrl?.query)
    }

    @Test
    fun listMessages_sendsLimitAndBefore_decodesBareArray() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """[{"message_id":"m98","conversation_id":"conv_1","sender_id":"usr_1",
                    "created_at":1749124800,"kind":"text","text":"lunch?"}]""",
            ),
        )
        val list = api().listMessages("conv_1", limit = 50, before = "m99")
        assertEquals("m98", list[0].messageId)
        assertEquals(1749124800L, list[0].createdAt)
        assertEquals("lunch?", list[0].text)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/conversations/conv_1/messages", req.requestUrl?.encodedPath)
        assertEquals("50", req.requestUrl?.queryParameter("limit"))
        assertEquals("m99", req.requestUrl?.queryParameter("before"))
        assertNull(req.requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun listMessages_nullArgs_omitsQueryParams() = runTest {
        backend.enqueue(Fixtures.okBody("[]"))
        api().listMessages("conv_1")
        val req = backend.takeRequest()
        assertNull(req.requestUrl?.query)
    }

    @Test
    fun sendMessage_serializesTextOnly_decodesMessageOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m100","conversation_id":"conv_1","sender_id":"usr_1",
                    "created_at":1749126660,"kind":"text","text":"on my way"}""",
            ),
        )
        val message = api().sendMessage("conv_1", SendTextMessageReq("on my way"))
        assertEquals("m100", message.messageId)
        assertEquals("text", message.kind)
        assertEquals(1749126660L, message.createdAt)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/conv_1/messages", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("on my way", body["text"])
        assertNull(body["client_id"])
    }

    @Test
    fun markRead_serializesLastReadId_returnsUnitOnEmptyBody() = runTest {
        backend.enqueue(Fixtures.okBody(""))
        api().markRead("conv_1", MarkReadReq(lastReadMessageId = "m100"))
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/conv_1/read", req.requestUrl?.encodedPath)
        assertEquals("m100", req.bodyJson()["last_read_message_id"])
    }

    @Test
    fun markRead_serializesLastReadAt_whenProvided() = runTest {
        backend.enqueue(Fixtures.okBody(""))
        api().markRead("conv_1", MarkReadReq(lastReadAt = 1749126660L))
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/conv_1/read", req.requestUrl?.encodedPath)
        // Moshi serializes the Long as a JSON number; bodyJson decodes it as Double.
        assertEquals(1749126660.0, req.bodyJson()["last_read_at"])
        assertNull(req.bodyJson()["last_read_message_id"])
    }

    @Test
    fun findOrCreateDm_postsUserId_decodesConversationOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"conversation_id":"conv_new","type":"dm","status":"active",
                 "participant_count":2,"created_at":1749124800,"created_by":"usr_self",
                 "unread_count":0,"last_message":null,"last_message_at":null,
                 "participants":[
                   {"user_id":"usr_self","status":"active","role":"member","display_name":"You"},
                   {"user_id":"usr_peer","status":"active","role":"member","display_name":"Ada"}
                 ]}
                """.trimIndent(),
            ),
        )
        val conversation = api().findOrCreateDm(FindOrCreateDmReq("usr_peer"))
        assertEquals("conv_new", conversation.conversationId)
        assertEquals(1749124800L, conversation.createdAt)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/dm/find-or-create", req.requestUrl?.encodedPath)
        assertEquals("usr_peer", req.bodyJson()["user_id"])
    }

    @Test
    fun getConversation_404_throwsHttpException() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"not_found"}""", code = 404))
        val error = runCatching { api().getConversation("missing") }.exceptionOrNull()
        assertTrue(error is HttpException)
        assertEquals(404, (error as HttpException).code())
    }
}
