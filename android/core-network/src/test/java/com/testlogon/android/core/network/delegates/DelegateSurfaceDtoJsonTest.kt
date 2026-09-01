package com.testlogon.android.core.network.delegates

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-360 - DTO-level Moshi tests for the AND-360 delegate-PATH surface DTOs (feed / messaging). Focus:
 * approval_status read-back, the delegate attribution echo (sent_by_delegate / delegate_display_name /
 * delegate_tag) + the delegate_cannot_decrypt flag, OPTIONAL-field defaults, and BARE-ARRAY decoding. The
 * Moshi is built like NetworkModule.provideMoshi; the JSON is inline. KDoc avoids the comment terminator.
 */
class DelegateSurfaceDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun postListAdapter() = moshi.adapter<List<DelegatedPostOut>>(
        Types.newParameterizedType(List::class.java, DelegatedPostOut::class.java),
    )

    private fun messageListAdapter() = moshi.adapter<List<DelegatedMessageOut>>(
        Types.newParameterizedType(List::class.java, DelegatedMessageOut::class.java),
    )

    @Test
    fun post_decodesApprovalStatus_andDefaultsOptionals() {
        val posts = requireNotNull(
            postListAdapter().fromJson(
                """[
                    {"post_id":"p_1","text":"hi","approval_status":"pending","created_at":"2026-01-01"},
                    {"post_id":"p_2"}
                ]""",
            ),
        )
        assertEquals("pending", posts[0].approvalStatus)
        assertEquals("hi", posts[0].text)
        // sparse row: optional fields default to null
        assertNull(posts[1].text)
        assertNull(posts[1].approvalStatus)
    }

    @Test
    fun message_decodesDelegateAttribution_andCannotDecryptFlag() {
        val messages = requireNotNull(
            messageListAdapter().fromJson(
                """[
                    {"message_id":"m_1","text":"yo","sent_by_delegate":true,
                     "delegate_display_name":"Sam","delegate_tag":"agent"},
                    {"message_id":"m_2","delegate_cannot_decrypt":true}
                ]""",
            ),
        )
        assertEquals(true, messages[0].sentByDelegate)
        assertEquals("Sam", messages[0].delegateDisplayName)
        assertEquals("agent", messages[0].delegateTag)
        assertEquals(true, messages[1].delegateCannotDecrypt)
        // a missing flag defaults to null (not false) - the UI treats null as "not flagged"
        assertNull(messages[0].delegateCannotDecrypt)
    }

    @Test
    fun sendMessageIn_serializesOptionalReplyTo() {
        val adapter = moshi.adapter(DelegatedSendMessageIn::class.java)
        val withReply = adapter.toJson(DelegatedSendMessageIn(text = "hi", replyToMessageId = "m_1"))
        assertTrue(withReply.contains("\"reply_to_message_id\":\"m_1\""))
        assertTrue(withReply.contains("\"text\":\"hi\""))
    }

    @Test
    fun conversation_decodesRequiredId_andOptionalMeta() {
        val adapter = moshi.adapter(DelegatedConversationOut::class.java)
        val decoded = requireNotNull(
            adapter.fromJson("""{"conversation_id":"c_1","title":"Acme","extra":"ignored"}"""),
        )
        assertEquals("c_1", decoded.conversationId)
        assertEquals("Acme", decoded.title)
        assertNull(decoded.lastMessagePreview)
    }

    // ---- AND-360 broadcast moderation read DTOs (added) ----

    private fun moderatorListAdapter() = moshi.adapter<List<DelegatedBroadcastModeratorOut>>(
        Types.newParameterizedType(List::class.java, DelegatedBroadcastModeratorOut::class.java),
    )

    private fun banListAdapter() = moshi.adapter<List<DelegatedBroadcastBanOut>>(
        Types.newParameterizedType(List::class.java, DelegatedBroadcastBanOut::class.java),
    )

    private fun logListAdapter() = moshi.adapter<List<DelegatedBroadcastModLogEntry>>(
        Types.newParameterizedType(List::class.java, DelegatedBroadcastModLogEntry::class.java),
    )

    @Test
    fun moderator_decodesRequiredId_andDefaultsOptionals() {
        val mods = requireNotNull(
            moderatorListAdapter().fromJson(
                """[
                    {"delegate_id":"d_1","display_name":"Sam","connected_at":123,"status":"online","actions_count":4},
                    {"delegate_id":"d_2"}
                ]""",
            ),
        )
        assertEquals("d_1", mods[0].delegateId)
        assertEquals("Sam", mods[0].displayName)
        assertEquals(4, mods[0].actionsCount)
        assertNull(mods[1].displayName)
        assertNull(mods[1].connectedAt)
    }

    @Test
    fun ban_decodesRequiredFields_andDefaultsOptionals() {
        val bans = requireNotNull(
            banListAdapter().fromJson(
                """[
                    {"user_id":"u_1","banned_by":"d_1","banned_by_display_name":"Sam","banned_at":99,"reason":"spam"},
                    {"user_id":"u_2","banned_by":"d_1"}
                ]""",
            ),
        )
        assertEquals("u_1", bans[0].userId)
        assertEquals("d_1", bans[0].bannedBy)
        assertEquals("spam", bans[0].reason)
        assertNull(bans[1].reason)
        assertNull(bans[1].bannedAt)
    }

    @Test
    fun modLog_decodesEntry_withOptionalTargets() {
        val log = requireNotNull(
            logListAdapter().fromJson(
                """[
                    {"event_id":"e_1","moderator_id":"d_1","moderation_type":"ban","target_user_id":"u_9","ts":42},
                    {"event_id":"e_2","moderator_id":"d_1","moderation_type":"pin","target_message_id":"m_3"}
                ]""",
            ),
        )
        assertEquals("e_1", log[0].eventId)
        assertEquals("ban", log[0].moderationType)
        assertEquals("u_9", log[0].targetUserId)
        assertNull(log[0].targetMessageId)
        assertEquals("m_3", log[1].targetMessageId)
        assertNull(log[1].targetUserId)
    }

    @Test
    fun announcementIn_serializesText() {
        val adapter = moshi.adapter(DelegatedAnnouncementIn::class.java)
        val json = adapter.toJson(DelegatedAnnouncementIn(text = "attention"))
        assertTrue(json.contains("\"text\":\"attention\""))
    }

}
