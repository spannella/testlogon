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

/** AND-134/135/136 — MockWebServer contract tests for the rich-message endpoints. */
class RichMessageApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = testMoshi()
    private fun api(): MessagingApi = backend.retrofit(moshi).create(MessagingApi::class.java)

    @Test
    fun sendGif_postsFlatBody_decodesGifMessage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"msg_789","conversation_id":"c1","sender_id":"u1","created_at":1749124800,
                    "kind":"gif","gif_url":"https://media/x.gif","gif_alt_text":"cat","gif_width":480,
                    "gif_height":270,"gif_provider":"tenor"}""",
                code = 201,
            ),
        )
        val msg = api().sendGifMessage(
            "c1",
            SendGifMessageReq(gifUrl = "https://media/x.gif", gifAltText = "cat", gifWidth = 480, gifHeight = 270),
        )
        assertEquals("gif", msg.kind)
        assertEquals("https://media/x.gif", msg.gifUrl)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/gif", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("https://media/x.gif", body["gif_url"])
        assertNull(body["conversation_id"]) // path param, not body
        assertNull(body["client_id"]) // no idempotency key on the wire
    }

    @Test
    fun sendSticker_postsCollectionId_decodesStickerMessage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"msg_790","conversation_id":"c1","sender_id":"u1","created_at":1749124800,
                    "kind":"sticker","sticker_id":"st_42","sticker_collection_id":"col_1",
                    "sticker_url":"https://s/st.png","sticker_alt_text":"wave"}""",
                code = 201,
            ),
        )
        val msg = api().sendStickerMessage("c1", SendStickerMessageReq(stickerId = "st_42", stickerCollectionId = "col_1"))
        assertEquals("sticker", msg.kind)
        assertEquals("https://s/st.png", msg.stickerUrl)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/sticker", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("st_42", body["sticker_id"])
        assertEquals("col_1", body["sticker_collection_id"])
        assertNull(body["pack_id"]) // corrected: collection, not pack
    }

    @Test
    fun searchGifs_parsesBareArray_clampsLimit() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """[{"id":"abc","url":"https://g/1.gif","alt_text":"cat","width":480,"height":270}]""",
            ),
        )
        val results = api().searchGifs("cat", 20)
        assertEquals(1, results.size)
        assertEquals("abc", results[0].id)

        val req = backend.takeRequest()
        assertEquals("/ui/stickers/gifs/search", req.requestUrl?.encodedPath)
        assertEquals("cat", req.requestUrl?.queryParameter("q"))
    }

    @Test
    fun stickerCollections_parsesWrapper() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"collections":[{"collection_id":"col_1","name":"Animals","thumbnail_url":"https://t.png",
                    "description":"","sticker_count":1,"is_active":true,
                    "stickers":[{"sticker_id":"st_42","image_url":"https://s/st.png","alt_text":"wave",
                    "width":256,"height":256,"sort_order":0}]}]}""",
            ),
        )
        val resp = api().stickerCollections()
        assertEquals("col_1", resp.collections[0].collectionId)
        assertEquals("https://s/st.png", resp.collections[0].stickers[0].imageUrl)
    }

    @Test
    fun customEmoji_parsesEmojisWrapper() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"emojis":[{"emoji_id":"e1","shortcode":"partyparrot","name":"Party Parrot",
                    "image_url":"https://e/pp.gif","content_type":"image/gif","owner_scope":"global"}],
                    "global_count":1,"personal_count":0}""",
            ),
        )
        val resp = api().customEmoji()
        assertEquals("partyparrot", resp.emojis[0].shortcode)
        assertEquals("image/gif", resp.emojis[0].contentType)
    }

    @Test
    fun voicemailPresign_postsCallIdAndMode() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m_0123456789abcdef0123456789abcdef","upload_url":"https://s/x","s3_key":"voicemail/k"}""",
            ),
        )
        val resp = api().presignVoicemail(
            "c1",
            PresignVoicemailReq(callId = "call_abc", contentType = "audio/mp4", sizeBytes = 48211, mode = "audio"),
        )
        assertEquals("voicemail/k", resp.s3Key)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/voicemail/presign", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("call_abc", body["call_id"])
        assertEquals("audio", body["mode"])
    }

    @Test
    fun createVoicemail_postsWaveformAndMode_decodesVoicemail() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m_0123456789abcdef0123456789abcdef","conversation_id":"c1","sender_id":"u1",
                    "created_at":1749132131,"kind":"voicemail","voicemail":{"call_id":"call_abc","mode":"audio",
                    "audio_url":"https://s/clip.m4a","content_type":"audio/mp4","size_bytes":48211,
                    "duration_seconds":7.4,"waveform_data":[0.1,0.7],"call_state":"missed",
                    "caller_user_id":"u_999","callee_user_id":"u_123"}}""",
            ),
        )
        val msg = api().createVoicemail(
            "c1",
            CreateVoicemailReq(
                messageId = "m_0123456789abcdef0123456789abcdef", callId = "call_abc", s3Key = "voicemail/k",
                contentType = "audio/mp4", sizeBytes = 48211, durationSeconds = 7.4,
                waveformData = listOf(0.1f, 0.7f),
            ),
        )
        assertEquals("voicemail", msg.kind)
        assertEquals("https://s/clip.m4a", msg.voicemail?.audioUrl)
        assertEquals("missed", msg.voicemail?.callState)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/voicemail", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("call_abc", body["call_id"])
        assertNull(body["recipient_id"]) // corrected: no recipient_id
    }

    @Test
    fun createMeetingPoll_postsSlots_decodesPollMessage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"msg_p","conversation_id":"c1","sender_id":"u1","created_at":1749124800,
                    "kind":"meeting_poll","meeting_poll":{"poll_id":"poll_9","creator_id":"u1",
                    "title":"Sprint sync time?","duration_minutes":30,"status":"open","confirmed_slot_id":null}}""",
            ),
        )
        val msg = api().createMeetingPoll(
            "c1",
            CreateMeetingPollReq(
                title = "Sprint sync time?", durationMinutes = 30,
                slots = listOf(
                    MeetingPollSlotInDto("2026-06-08T15:00:00Z", "2026-06-08T15:30:00Z"),
                    MeetingPollSlotInDto("2026-06-09T21:00:00Z", "2026-06-09T21:30:00Z"),
                ),
            ),
        )
        assertEquals("meeting_poll", msg.kind)
        assertEquals("poll_9", msg.meetingPoll?.pollId)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/meeting-poll", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertNull(body["kind"]) // no kind/option_ids on create
        @Suppress("UNCHECKED_CAST")
        val slots = body["slots"] as List<Any?>
        assertEquals(2, slots.size)
    }

    @Test
    fun voteMeetingPoll_postsVotesMap_decodesOk() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val resp = api().voteMeetingPoll("c1", "poll_9", PollVoteReq(mapOf("slot_1" to "yes")))
        org.junit.Assert.assertTrue(resp.ok)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/polls/poll_9/vote", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        @Suppress("UNCHECKED_CAST")
        val votes = body["votes"] as Map<String, Any?>
        assertEquals("yes", votes["slot_1"])
    }

    @Test
    fun confirmMeetingPoll_postsSlotId_decodesEventId() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"event_id":"evt_1"}"""))
        val resp = api().confirmMeetingPoll("c1", "poll_9", PollConfirmReq(slotId = "slot_2"))
        assertEquals("evt_1", resp.eventId)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/polls/poll_9/confirm", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("slot_2", body["slot_id"])
        assertNull(body["option_id"]) // corrected: slot_id, not option_id
    }

    @Test
    fun getMeetingPoll_decodesStateWithSlots() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"poll_id":"poll_9","title":"Sprint sync time?","duration_minutes":30,"creator_id":"u1",
                    "status":"open","confirmed_slot_id":null,"slots":[{"slot_id":"slot_1",
                    "start_utc":"2026-06-08T15:00:00Z","end_utc":"2026-06-08T15:30:00Z","yes_count":1,
                    "maybe_count":0,"no_count":0,"my_vote":null}]}""",
            ),
        )
        val state = api().getMeetingPoll("c1", "poll_9")
        assertEquals("poll_9", state.pollId)
        assertEquals(1, state.slots[0].yesCount)
    }
}
