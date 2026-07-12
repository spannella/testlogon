package com.testlogon.android.data.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-134/135/136 — DTO -> domain media mapping for the rich message kinds (pure JVM). */
class RichMessageMapperTest {

    @Test
    fun voicemailDto_mapsToVoicemailMedia_audio() {
        val dto = MessageDto(
            messageId = "m1", conversationId = "c1", senderId = "u1", createdAt = 100, kind = "voicemail",
            voicemail = VoicemailDto(
                callId = "call_abc", mode = "audio", audioUrl = "https://s/clip.m4a",
                durationSeconds = 7.4, waveformData = listOf(0.1f, 0.7f), callState = "missed",
            ),
            consumptionPolicy = "listen_once",
        )
        val media = dto.toMedia() as MessageMedia.Voicemail
        assertEquals("https://s/clip.m4a", media.mediaUrl)
        assertFalse(media.isVideo)
        assertEquals("missed", media.callState)
        assertEquals("call_abc", media.callId)
        assertEquals(7.4, media.durationSeconds, 0.001)
    }

    @Test
    fun voicemailDto_video_prefersVideoUrl() {
        val dto = MessageDto(
            messageId = "m2", conversationId = "c1", senderId = "u1", createdAt = 100, kind = "voicemail",
            voicemail = VoicemailDto(mode = "video", videoUrl = "https://s/v.mp4", audioUrl = null),
        )
        val media = dto.toMedia() as MessageMedia.Voicemail
        assertTrue(media.isVideo)
        assertEquals("https://s/v.mp4", media.mediaUrl)
    }

    @Test
    fun gifDto_mapsToGifMedia_fromFlatFields() {
        val dto = MessageDto(
            messageId = "m3", conversationId = "c1", senderId = "u1", createdAt = 100, kind = "gif",
            gifUrl = "https://media/x.gif", gifAltText = "a waving cat", gifWidth = 480, gifHeight = 270,
            gifProvider = "tenor",
        )
        val media = dto.toMedia() as MessageMedia.Gif
        assertEquals("https://media/x.gif", media.url)
        assertEquals("a waving cat", media.altText)
        assertEquals(480, media.width)
        assertEquals("tenor", media.provider)
    }

    @Test
    fun stickerDto_mapsToStickerMedia_fromFlatFields() {
        val dto = MessageDto(
            messageId = "m4", conversationId = "c1", senderId = "u1", createdAt = 100, kind = "sticker",
            stickerUrl = "https://s/st.png", stickerAltText = "wave", stickerId = "st_42",
            stickerCollectionId = "col_1",
        )
        val media = dto.toMedia() as MessageMedia.Sticker
        assertEquals("https://s/st.png", media.url)
        assertEquals("wave", media.altText)
        assertEquals("st_42", media.stickerId)
        assertEquals("col_1", media.collectionId)
    }

    @Test
    fun meetingPollDto_mapsToPollEnvelope() {
        val dto = MessageDto(
            messageId = "m5", conversationId = "c1", senderId = "u1", createdAt = 100, kind = "meeting_poll",
            meetingPoll = MeetingPollAttachmentDto(
                pollId = "poll_9", creatorId = "user_1", title = "Sprint sync time?",
                durationMinutesRaw = 30, status = "open", confirmedSlotId = null,
            ),
        )
        val media = dto.toMedia() as MessageMedia.MeetingPoll
        assertEquals("poll_9", media.pollId)
        assertEquals("user_1", media.creatorId)
        assertEquals("open", media.status)
        assertNull(media.confirmedSlotId)
    }

    @Test
    fun meetingPollState_mapsToDomain_withSlotsAndMyVote() {
        val state = MeetingPollStateDto(
            pollId = "poll_9", title = "Sprint sync time?", durationMinutes = 30, creatorId = "user_1",
            status = "open", confirmedSlotId = null,
            slots = listOf(
                MeetingPollSlotStateDto("slot_1", "2026-06-08T15:00:00Z", "2026-06-08T15:30:00Z", 1, 0, 0, null),
                MeetingPollSlotStateDto("slot_2", "2026-06-09T21:00:00Z", "2026-06-09T21:30:00Z", 2, 1, 0, "yes"),
            ),
        )
        val poll = state.toDomain()
        assertEquals(MeetingPollStatus.OPEN, poll.status)
        assertEquals(2, poll.slots.size)
        assertNull(poll.slots[0].myVote)
        assertEquals(SlotVote.YES, poll.slots[1].myVote)
        assertEquals(3, poll.slots[1].totalResponses)
    }
}
