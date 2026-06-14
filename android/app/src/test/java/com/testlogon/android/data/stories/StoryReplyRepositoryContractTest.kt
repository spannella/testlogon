package com.testlogon.android.data.stories

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.messaging.MessagingApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-200 — contract tests for [StoryReplyRepositoryImpl]. A reply/reaction resolves the author DM
 * (POST /messaging/conversations/dm/find-or-create -> FindOrCreateDmIn{user_id}) then sends a text
 * message (POST /messaging/conversations/{id}/messages -> SendTextMessageIn{text}); POSTs are not
 * retried, and the message body carries ONLY `text` (no fabricated story-context keys).
 */
class StoryReplyRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): StoryReplyRepositoryImpl {
        val api = backend.retrofit(moshi).create(MessagingApi::class.java)
        return StoryReplyRepositoryImpl(messagingApi = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun replyToStory_resolvesDmThenSendsText() = runTest {
        backend.enqueue(Fixtures.okBody("""{"conversation_id":"c1","kind":"dm","participants":[]}"""))
        backend.enqueue(Fixtures.okBody("""{"message_id":"m1","conversation_id":"c1","sender_id":"me","created_at":1,"kind":"text","text":"hi"}"""))

        val result = repo().replyToStory(storyId = "s1", authorId = "author42", text = "hi")
        assertTrue(result is ApiResult.Success)

        val dmReq = backend.takeRequest()
        assertEquals("POST", dmReq.method)
        assertEquals("/messaging/conversations/dm/find-or-create", dmReq.requestUrl?.encodedPath)
        assertTrue(dmReq.body.readUtf8().contains("\"user_id\":\"author42\""))

        val sendReq = backend.takeRequest()
        assertEquals("POST", sendReq.method)
        assertEquals("/messaging/conversations/c1/messages", sendReq.requestUrl?.encodedPath)
        val sendBody = sendReq.body.readUtf8()
        assertTrue(sendBody.contains("\"text\":\"hi\""))
        assertTrue(!sendBody.contains("is_reaction"))
        assertTrue(!sendBody.contains("context"))
    }

    @Test
    fun reactToStory_sendsEmojiAsText() = runTest {
        backend.enqueue(Fixtures.okBody("""{"conversation_id":"c9","kind":"dm","participants":[]}"""))
        backend.enqueue(Fixtures.okBody("""{"message_id":"m2","conversation_id":"c9","sender_id":"me","created_at":1,"kind":"text","text":"🔥"}"""))

        val result = repo().reactToStory(storyId = "s1", authorId = "a1", emoji = "🔥")
        assertTrue(result is ApiResult.Success)
        backend.takeRequest() // dm
        val sendReq = backend.takeRequest()
        assertTrue(sendReq.body.readUtf8().contains("🔥"))
    }

    @Test
    fun replyToStory_dmFailure_isFailure_andNoSecondPost() = runTest {
        backend.enqueue(Fixtures.error("\"forbidden\"", 403))
        val result = repo().replyToStory("s1", "a1", "hi")
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
        assertEquals(1, backend.requestCount) // send-message never attempted
    }

    @Test
    fun replyToStory_sendFailure_isFailure_notRetried() = runTest {
        backend.enqueue(Fixtures.okBody("""{"conversation_id":"c1","kind":"dm","participants":[]}"""))
        backend.enqueue(Fixtures.error("\"boom\"", 503))
        val result = repo().replyToStory("s1", "a1", "hi")
        assertTrue(result is ApiResult.Failure)
        assertEquals(2, backend.requestCount) // exactly one dm + one send, no retry
    }
}
