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
}
