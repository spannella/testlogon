package com.testlogon.android.data.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-132/133 — DTO -> domain media mapping + waveform JSON round-trip (pure JVM). */
class FileVoiceMapperTest {

    @Test
    fun fileMessageDto_mapsToFileMedia() {
        val dto = MessageDto(
            messageId = "m1",
            conversationId = "c1",
            senderId = "u1",
            createdAt = 100,
            kind = "file",
            file = MessageFileDto(name = "report.pdf", size = 482133, contentType = "application/pdf", path = "p/report.pdf"),
            consumptionPolicy = "none",
        )
        val media = dto.toMedia()
        assertTrue(media is MessageMedia.File)
        media as MessageMedia.File
        assertEquals("report.pdf", media.fileName)
        assertEquals(482133L, media.sizeBytes)
        assertEquals("application/pdf", media.mimeType)
        assertEquals(false, media.isShare)
    }

    @Test
    fun fileShareDto_mapsToShareFileMedia() {
        val dto = MessageDto(
            messageId = "m2", conversationId = "c1", senderId = "u1", createdAt = 100,
            kind = "file_share",
            fileShare = MessageFileDto(name = "shared.pdf", permission = "read", path = "u/shared.pdf"),
        )
        val media = dto.toMedia() as MessageMedia.File
        assertTrue(media.isShare)
        assertEquals("shared.pdf", media.fileName)
    }

    @Test
    fun voiceMessageDto_mapsToVoiceMedia() {
        val dto = MessageDto(
            messageId = "m3", conversationId = "c1", senderId = "u1", createdAt = 100,
            kind = "voice_message",
            voiceMessage = VoiceMessageDto(
                audioUrl = "https://s/a.m4a",
                durationSeconds = 7.4,
                waveformData = listOf(0.1f, 0.5f, 0.9f),
            ),
        )
        val media = dto.toMedia() as MessageMedia.Voice
        assertEquals("https://s/a.m4a", media.audioUrl)
        assertEquals(7.4, media.durationSeconds, 0.001)
        assertEquals(3, media.waveform.size)
    }

    @Test
    fun waveform_jsonRoundTrip() {
        val original = listOf(0.0f, 0.123f, 0.5f, 1.0f)
        val json = waveformToJson(original)
        val parsed = waveformFromJson(json)
        assertEquals(original.size, parsed.size)
        original.zip(parsed).forEach { (a, b) -> assertEquals(a, b, 0.001f) }
    }

    @Test
    fun waveform_fromJson_tolerantOfBlankOrGarbage() {
        assertTrue(waveformFromJson(null).isEmpty())
        assertTrue(waveformFromJson("").isEmpty())
        assertTrue(waveformFromJson("[]").isEmpty())
        assertEquals(listOf(0.5f), waveformFromJson("[0.5]"))
    }
}
