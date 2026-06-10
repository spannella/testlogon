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

/**
 * AND-147 / AND-150 — MockWebServer contract tests for the read-receipt endpoints: the conversation-
 * scoped /view POST (ViewMessageIn -> ViewAckOut, epoch-integer viewed_at) and the /views GET (a BARE
 * array of MessageViewOut, limit only, no cursor). Verifies the verified wire shapes (spec §5).
 */
class ReceiptApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): MessagingApi = backend.retrofit(moshi).create(MessagingApi::class.java)

    @Test
    fun reportView_postsConversationScopedPath_decodesAck() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"conversation_id":"c1","message_id":"m1","viewer_id":"u_self","viewed_at":1749124800}""",
            ),
        )
        val ack = api().reportView("c1", "m1", ViewMessageIn())
        assertTrue(ack.ok)
        assertEquals("u_self", ack.viewerId)
        assertEquals(1749124800L, ack.viewedAt)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1/view", req.requestUrl?.encodedPath)
        // ViewMessageIn with a null viewed_at serializes as an empty object (Moshi omits null fields);
        // bodyJson() reads the buffer ONCE and returns a map — no viewed_at key is present.
        val body = req.bodyJson()
        assertNull(body["viewed_at"])
    }

    @Test
    fun getViews_decodesBareArray_withLimit_noCursor() = runTest {
        backend.enqueue(
            Fixtures.okBody("""[{"user_id":"u_9","last_viewed_at":1749124801,"view_count":3}]"""),
        )
        val rows = api().getViews("c1", "m1", limit = 200)
        assertEquals(1, rows.size)
        assertEquals("u_9", rows[0].userId)
        assertEquals(1749124801L, rows[0].lastViewedAt)
        assertEquals(3, rows[0].viewCount)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1/views", req.requestUrl?.encodedPath)
        assertEquals("200", req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("cursor"))
    }
}
