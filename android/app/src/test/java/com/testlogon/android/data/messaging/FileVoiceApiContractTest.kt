package com.testlogon.android.data.messaging

import com.testlogon.android.testutil.testMoshi

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test

/** AND-132/133 — MockWebServer contract tests for file/file-share + grant/consume + voice. */
class FileVoiceApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = testMoshi()
    private fun api(): MessagingApi = backend.retrofit(moshi).create(MessagingApi::class.java)

    @Test
    fun createFileMessage_postsPathAndKind_decodesMessageOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"msg_789","conversation_id":"c1","sender_id":"u1","created_at":1749124800,
                    "kind":"file","file":{"name":"report.pdf","size":482133,"content_type":"application/pdf",
                    "path":"messages/c1/report.pdf"}}""",
            ),
        )
        val msg = api().createFileMessage("c1", CreateFileMessageReq(path = "messages/c1/report.pdf", kind = "file"))
        assertEquals("file", msg.kind)
        assertEquals(1749124800L, msg.createdAt)
        assertEquals("report.pdf", msg.file?.name)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/file", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("messages/c1/report.pdf", body["path"])
        assertEquals("file", body["kind"])
        assertNull(body["attachment_id"]) // corrected: path, not attachment_id
        assertNull(body["conversation_id"]) // conversation id is a path param
        assertNull(body["client_message_id"]) // no idempotency body field
    }

    @Test
    fun createFileShare_postsFilePathAndPermission() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"msg_1","conversation_id":"c1","sender_id":"u1","created_at":100,
                    "kind":"file_share","file_share":{"name":"shared.pdf","permission":"read",
                    "path":"users/u1/files/shared.pdf"}}""",
            ),
        )
        val msg = api().createFileShareMessage(
            "c1",
            CreateFileShareReq(filePath = "users/u1/files/shared.pdf", permission = "read"),
        )
        assertEquals("file_share", msg.kind)
        assertEquals("shared.pdf", msg.fileShare?.name)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/file-share", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("users/u1/files/shared.pdf", body["file_path"])
        assertEquals("read", body["permission"])
        assertNull(body["file_ref"]) // corrected: file_path, not file_ref
    }

    @Test
    fun createAttachmentGrant_emptyBody_decodesGrantOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"grant_token":"g_55abc","expires_at":1749125100,"conversation_id":"c1","message_id":"msg_789"}""",
            ),
        )
        val grant = api().createAttachmentGrant("c1", "msg_789")
        assertEquals("g_55abc", grant.grantToken)
        assertEquals(1749125100L, grant.expiresAt)

        val req = backend.takeRequest()
        assertEquals(
            "/messaging/conversations/c1/messages/msg_789/attachment/grant",
            req.requestUrl?.encodedPath,
        )
        // Empty object body.
        assertEquals(emptyMap<String, Any?>(), req.bodyJson())
    }

    @Test
    fun consumeAttachment_grantTokenIsQuery_bodyHasAttemptAndTrigger() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"conversation_id":"c1","message_id":"msg_789","consumption_state":"consumed",
                    "consumed_at":1749124900,"consumption_attempt_id":"attempt-123456"}""",
            ),
        )
        val resp = api().consumeAttachment(
            id = "c1",
            messageId = "msg_789",
            grantToken = "g1",
            body = ConsumeAttachmentReq(consumptionAttemptId = "attempt-123456", trigger = "open"),
        )
        assertEquals("consumed", resp.consumptionState)

        val req = backend.takeRequest()
        assertEquals(
            "/messaging/conversations/c1/messages/msg_789/attachment/consume",
            req.requestUrl?.encodedPath,
        )
        assertEquals("g1", req.requestUrl?.queryParameter("grant_token"))
        val body = req.bodyJson()
        assertEquals("attempt-123456", body["consumption_attempt_id"])
        assertEquals("open", body["trigger"])
    }

    @Test
    fun presignVoice_postsContentTypeSizeDuration() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m_0123456789abcdef0123456789abcdef","upload_url":"https://s/x","s3_key":"k1"}""",
            ),
        )
        val resp = api().presignVoice(
            "c1",
            PresignVoiceReq(contentType = "audio/mp4", sizeBytes = 184320, durationSeconds = 7.4),
        )
        assertEquals("k1", resp.s3Key)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/voice-message/presign", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("audio/mp4", body["content_type"])
        assertEquals(184320.0, body["size_bytes"]) // Moshi decodes numbers as Double in the test map
        assertEquals(7.4, body["duration_seconds"])
        assertNull(body["duration_ms"]) // corrected: seconds, not ms
    }

    @Test
    fun createVoice_postsWaveformArray_decodesVoiceMessage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m_0123456789abcdef0123456789abcdef","conversation_id":"c1","sender_id":"u1",
                    "created_at":1749124800,"kind":"voice_message","voice_message":{"audio_url":"https://s/a.m4a",
                    "audio_content_type":"audio/mp4","audio_size_bytes":184320,"duration_seconds":7.4,
                    "waveform_data":[0.0,0.12,0.34]}}""",
            ),
        )
        val msg = api().createVoiceMessage(
            "c1",
            CreateVoiceReq(
                messageId = "m_0123456789abcdef0123456789abcdef",
                s3Key = "k1",
                contentType = "audio/mp4",
                sizeBytes = 184320,
                durationSeconds = 7.4,
                waveformData = listOf(0.0f, 0.12f, 0.34f),
            ),
        )
        assertEquals("voice_message", msg.kind)
        assertEquals("https://s/a.m4a", msg.voiceMessage?.audioUrl)
        assertEquals(3, msg.voiceMessage?.waveformData?.size)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/voice-message", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("k1", body["s3_key"])
        @Suppress("UNCHECKED_CAST")
        val waveform = body["waveform_data"] as List<Any?>
        assertEquals(3, waveform.size) // serialized as a JSON number array, not base64
    }
}
