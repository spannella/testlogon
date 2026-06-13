package com.testlogon.android.core.network.delegates

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
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-360 - hermetic request-shape / decode tests for the AND-360 delegate-PATH APIs (feed / messaging /
 * broadcast). Asserts attribution is the @Path segment (creatorId / postId / cid / sid substituted), the
 * distinct delegate paths, the BARE-ARRAY list shape with ?limit=, and the verb mapping. MockWebServer
 * only + a production-style Moshi; KDoc avoids the comment-terminator character pair.
 */
class DelegateFeatureApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun retrofit(): Retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()

    private fun feedApi(): DelegateFeedApi = retrofit().create(DelegateFeedApi::class.java)
    private fun messagingApi(): DelegateMessagingApi = retrofit().create(DelegateMessagingApi::class.java)
    private fun broadcastApi(): DelegateBroadcastApi = retrofit().create(DelegateBroadcastApi::class.java)

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

    // ---- Feed ----

    @Test
    fun createPost_postsDelegatePostsPath_withCreatorIdSubstituted() = runTest {
        server.enqueue(jsonResponse("""{"post_id":"p_1","text":"hi","approval_status":"pending"}"""))

        val out = feedApi().createPost("cr_1", DelegatedPostCreateIn(text = "hi"))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/newsfeed/delegate/cr_1/posts", recorded.requestUrl?.encodedPath)
        assertTrue(recorded.body.readUtf8().contains("\"text\":\"hi\""))
        assertEquals("p_1", out.postId)
        assertEquals("pending", out.approvalStatus)
    }

    @Test
    fun listPosts_getsBareArray_withLimitQuery() = runTest {
        server.enqueue(jsonResponse("""[{"post_id":"p_1","text":"a"},{"post_id":"p_2"}]"""))

        val posts = feedApi().listPosts("cr_1", limit = 25)

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/newsfeed/delegate/cr_1/posts", recorded.requestUrl?.encodedPath)
        assertEquals("25", recorded.requestUrl?.queryParameter("limit"))
        assertEquals(2, posts.size)
        assertEquals("p_1", posts[0].postId)
    }

    @Test
    fun deletePost_deletesPostPath_withPostIdSubstituted() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))

        val response = feedApi().deletePost("cr_1", "p_9")

        val recorded = server.takeRequest()
        assertEquals("DELETE", recorded.method)
        assertEquals("/ui/newsfeed/delegate/cr_1/posts/p_9", recorded.requestUrl?.encodedPath)
        assertTrue(response.isSuccessful)
    }

    // ---- Messaging ----

    @Test
    fun conversations_getsDelegateConversationsPath() = runTest {
        server.enqueue(jsonResponse("""[{"conversation_id":"c_1","title":"Acme"}]"""))

        val conversations = messagingApi().conversations("cr_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/messaging/delegate/cr_1/conversations", recorded.requestUrl?.encodedPath)
        assertEquals("c_1", conversations.single().conversationId)
    }

    @Test
    fun messages_getsConversationMessagesPath_withCidSubstituted() = runTest {
        server.enqueue(
            jsonResponse(
                """[{"message_id":"m_1","text":"yo","sent_by_delegate":true,
                    "delegate_display_name":"Sam","delegate_tag":"agent"}]""",
            ),
        )

        val messages = messagingApi().messages("cr_1", "c_7")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/messaging/delegate/cr_1/conversations/c_7/messages", recorded.requestUrl?.encodedPath)
        assertEquals(true, messages.single().sentByDelegate)
        assertEquals("Sam", messages.single().delegateDisplayName)
    }

    @Test
    fun send_postsMessage_withCreatorAndCidSubstituted_andBody() = runTest {
        server.enqueue(jsonResponse("""{"message_id":"m_2","text":"hi","sent_by_delegate":true}"""))

        val out = messagingApi().send(
            "cr_1",
            "c_7",
            DelegatedSendMessageIn(text = "hi", replyToMessageId = "m_1"),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/messaging/delegate/cr_1/conversations/c_7/messages", recorded.requestUrl?.encodedPath)
        val body = recorded.body.readUtf8()
        assertTrue(body.contains("\"text\":\"hi\""))
        assertTrue(body.contains("\"reply_to_message_id\":\"m_1\""))
        assertEquals("m_2", out.messageId)
    }

    // ---- Broadcast ----

    @Test
    fun startSession_postsStartPath_withCreatorAndSidSubstituted() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))

        val response = broadcastApi().startSession("cr_1", "sess_5")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/broadcast/delegate/cr_1/sessions/sess_5/start", recorded.requestUrl?.encodedPath)
        assertTrue(response.isSuccessful)
    }

    @Test
    fun stopSession_postsStopPath_withCreatorAndSidSubstituted() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))

        broadcastApi().stopSession("cr_1", "sess_5")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/broadcast/delegate/cr_1/sessions/sess_5/stop", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun banViewer_postsBanPath_withModerationBody() = runTest {
        server.enqueue(MockResponse().setResponseCode(204))

        broadcastApi().banViewer("cr_1", "sess_5", DelegatedModerationIn(userId = "u_9", reason = "spam"))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/broadcast/delegate/cr_1/sessions/sess_5/ban", recorded.requestUrl?.encodedPath)
        assertTrue(recorded.body.readUtf8().contains("\"user_id\":\"u_9\""))
    }
}
