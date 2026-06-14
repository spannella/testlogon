package com.testlogon.android.data.messaging

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/**
 * AND-140 / AND-142 — MockWebServer contract tests for the per-message action endpoints. Pins the
 * verb/path/body/response shape so backend or client drift breaks the build.
 */
class MessageActionsApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private fun api(): MessagingApi = backend.retrofit(moshi).create(MessagingApi::class.java)

    @Test
    fun react_postsEmojiAndAction_toReactionsPath() = runTest {
        backend.enqueue(Fixtures.okBody("", code = 200))
        api().react("c1", "m1", ReactIn("👍", "add"))

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1/reactions", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("👍", body["emoji"])
        assertEquals("add", body["action"])
    }

    @Test
    fun reactionDetails_decodesEmojiKeyedReactors() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"reactions":{"👍":[{"user_sub":"u_2","display_name":"Ann","profile_photo_url":null}]}}""",
            ),
        )
        val out = api().reactionDetails("c1", "m1")
        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/m1/reactions/details", req.requestUrl?.encodedPath)
        assertEquals("u_2", out.reactions["👍"]?.first()?.userSub)
        assertEquals("Ann", out.reactions["👍"]?.first()?.displayName)
    }

    @Test
    fun pin_postsToPinPath_decodesControlAction() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"ok":true,"conversation_id":"c1","message_id":"m1","action":"pinned","updated_at":100}"""),
        )
        val out = api().pinMessage("c1", "m1")
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1/pin", req.requestUrl?.encodedPath)
        assertEquals("pinned", out.action)
    }

    @Test
    fun unpin_deletesPinPath() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"ok":true,"conversation_id":"c1","message_id":"m1","action":"unpinned","updated_at":100}"""),
        )
        val out = api().unpinMessage("c1", "m1")
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1/pin", req.requestUrl?.encodedPath)
        assertEquals("unpinned", out.action)
    }

    @Test
    fun listPins_decodesPinRefs() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[{"conversation_id":"c1","message_id":"m1","pinned_by_user_id":"u2",
                    "pinned_at":100,"is_active":true}],"next_cursor":null}""",
            ),
        )
        val out = api().listPins("c1")
        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/pins", req.requestUrl?.encodedPath)
        assertEquals("m1", out.items.first().messageId)
    }

    @Test
    fun edit_patchesTextField_decodesMessageOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m1","conversation_id":"c1","sender_id":"u1","created_at":100,
                    "kind":"text","text":"hi there","edited_at":200}""",
            ),
        )
        val msg = api().editMessage("c1", "m1", EditMessageIn("hi there"))
        val req = backend.takeRequest()
        assertEquals("PATCH", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("hi there", body["text"])
        assertEquals(200L, msg.editedAt)
    }

    @Test
    fun delete_usesDeleteVerb_baseMessagePath() = runTest {
        backend.enqueue(Fixtures.okBody("", code = 200))
        api().deleteMessage("c1", "m1")
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1", req.requestUrl?.encodedPath)
    }

    @Test
    fun revoke_usesDeleteOnRevokePath_decodesMessageOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m1","conversation_id":"c1","sender_id":"u1","created_at":100,
                    "kind":"text","text":"x","revoked_at":300}""",
            ),
        )
        val msg = api().revokeMessage("c1", "m1")
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1/revoke", req.requestUrl?.encodedPath)
        assertEquals(300L, msg.revokedAt)
    }

    @Test
    fun hide_postsToHidePath() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"ok":true,"conversation_id":"c1","message_id":"m1","action":"hidden","updated_at":100}"""),
        )
        val out = api().hideMessage("c1", "m1")
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1/hide", req.requestUrl?.encodedPath)
        assertEquals("hidden", out.action)
    }

    @Test
    fun unhide_deletesHidePath() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"ok":true,"conversation_id":"c1","message_id":"m1","action":"visible","updated_at":100}"""),
        )
        val out = api().unhideMessage("c1", "m1")
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1/hide", req.requestUrl?.encodedPath)
        assertEquals("visible", out.action)
    }

    @Test
    fun hiddenMessages_decodesMessageItems() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[{"message_id":"m1","conversation_id":"c1","sender_id":"u1",
                    "created_at":100,"kind":"text","text":"secret"}],"next_cursor":null}""",
            ),
        )
        val out = api().listHiddenMessages("c1")
        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/hidden-messages", req.requestUrl?.encodedPath)
        assertEquals("m1", out.items.first().messageId)
    }
}
