package com.testlogon.android.data.broadcast.chat

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-281 — MockWebServer contract test for [BroadcastChatApi]. Verifies verb/path, the {text} send
 * body (NO client_id), the singular react path + {emoji,action} body, the history limit/before query +
 * { messages, has_more, oldest_sort_key } envelope, and BroadcastChatMessageOut parsing (epoch-second
 * created_at, reactions_counts/my_reactions).
 */
class BroadcastChatApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): BroadcastChatApi = backend.retrofit(moshi).create(BroadcastChatApi::class.java)

    @Test
    fun send_postsTextBody_noClientId_parsesMessage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"cm1","session_id":"s1","sender_id":"u9","sender_display_name":"Mira",
                   "text":"hi","kind":"text","created_at":1749164470,"deleted":false,
                   "reactions_counts":{"🔥":2},"my_reactions":["🔥"]}""",
                code = 201,
            ),
        )
        val resp = api().send("s1", SendChatDto(text = "hi"))
        assertTrue(resp.isSuccessful)
        val body = resp.body()!!
        assertEquals("cm1", body.messageId)
        assertEquals(1749164470L, body.createdAt)
        assertEquals(2, body.reactionsCounts?.get("🔥"))

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/s1/chat", req.requestUrl?.encodedPath)
        val sentBody = req.body.readUtf8()
        assertTrue(sentBody.contains("\"text\":\"hi\""))
        assertFalse(sentBody.contains("client_id"))
    }

    @Test
    fun react_singularPath_emojiActionBody() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"reactions_counts":{"🔥":12}}"""))
        val resp = api().reactToMessage("s1", "cm1", ReactionDto(emoji = "🔥", action = "add"))
        assertTrue(resp.isSuccessful)
        assertEquals(12, resp.body()!!.reactionsCounts["🔥"])

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/s1/chat/cm1/react", req.requestUrl?.encodedPath)
        val sentBody = req.body.readUtf8()
        assertTrue(sentBody.contains("\"emoji\":\"🔥\""))
        assertTrue(sentBody.contains("\"action\":\"add\""))
    }

    @Test
    fun history_limitBeforeQuery_envelope() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"messages":[{"message_id":"cm1","session_id":"s1","sender_id":"u9",
                   "sender_display_name":"Mira","text":"hi","created_at":1749164470,"deleted":false}],
                   "has_more":true,"oldest_sort_key":"sk_1"}""",
            ),
        )
        val resp = api().history("s1", limit = 100, before = "sk_0")
        assertTrue(resp.isSuccessful)
        val body = resp.body()!!
        assertEquals(1, body.messages.size)
        assertTrue(body.hasMore)
        assertEquals("sk_1", body.oldestSortKey)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/s1/chat", req.requestUrl?.encodedPath)
        assertEquals("100", req.requestUrl?.queryParameter("limit"))
        assertEquals("sk_0", req.requestUrl?.queryParameter("before"))
    }
}
