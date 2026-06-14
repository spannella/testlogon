package com.testlogon.android.data.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-130/131 — pure JVM tests for the image/video_share DTO -> domain mappers + S3 url derivation. */
class MediaMessageMapperTest {

    @Test
    fun imageMessage_usesExplicitUrl_whenPresent() {
        val dto = MessageDto(
            messageId = "m1",
            conversationId = "c1",
            senderId = "u1",
            createdAt = 100,
            kind = "image",
            image = MessageImageDto(
                bucket = "b",
                key = "conversations/c1/x.jpg",
                url = "https://cdn.example/x.jpg",
                width = 1536,
                height = 2048,
            ),
        )
        val media = dto.toDomain().media
        assertTrue(media is MessageMedia.Image)
        media as MessageMedia.Image
        assertEquals("https://cdn.example/x.jpg", media.url)
        assertEquals(1536, media.width)
        assertEquals(2048, media.height)
    }

    @Test
    fun imageMessage_derivesS3Url_whenNoExplicitUrl() {
        val dto = MessageDto(
            messageId = "m1",
            conversationId = "c1",
            senderId = "u1",
            createdAt = 100,
            kind = "image",
            image = MessageImageDto(bucket = "tl-media", key = "conversations/c1/x.jpg"),
        )
        val media = dto.toDomain().media as MessageMedia.Image
        assertEquals("https://tl-media.s3.amazonaws.com/conversations/c1/x.jpg", media.url)
    }

    @Test
    fun deriveS3Url_nullWhenBucketOrKeyMissing() {
        assertNull(deriveS3Url(null, "k"))
        assertNull(deriveS3Url("b", null))
        assertNull(deriveS3Url("b", ""))
    }

    @Test
    fun videoShareMessage_mapsAllFields() {
        val dto = MessageDto(
            messageId = "m2",
            conversationId = "c1",
            senderId = "u1",
            createdAt = 200,
            kind = "video_share",
            videoShare = VideoShareDto(
                videoId = "vid_1",
                title = "Clip",
                thumbnailUrl = "https://t/poster.jpg",
                durationSeconds = 42,
                width = 1280,
                height = 720,
                drmEnabled = false,
                hlsManifestUrl = "https://h/manifest.m3u8",
                playbackToken = "tok",
                playbackExpiresAt = 999,
            ),
        )
        val media = dto.toDomain().media
        assertTrue(media is MessageMedia.VideoShare)
        media as MessageMedia.VideoShare
        assertEquals("vid_1", media.videoId)
        assertEquals(42, media.durationSeconds)
        assertEquals("https://h/manifest.m3u8", media.hlsManifestUrl)
        assertEquals("tok", media.playbackToken)
        assertEquals(1280, media.width)
    }

    @Test
    fun textMessage_hasNoMedia() {
        val dto = MessageDto(
            messageId = "m3",
            conversationId = "c1",
            senderId = "u1",
            createdAt = 300,
            kind = "text",
            text = "hi",
        )
        val message = dto.toDomain()
        assertEquals(MessageMedia.None, message.media)
        assertEquals("hi", message.text)
    }
}
