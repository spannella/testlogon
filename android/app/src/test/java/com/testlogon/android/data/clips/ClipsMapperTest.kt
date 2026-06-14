package com.testlogon.android.data.clips

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-198 — pure DTO -> domain mapping for clips: status normalization, snake_case fields, blank-row
 * dropping, public attribution, duration rounding, and the playable/processing predicates.
 */
class ClipsMapperTest {

    @Test
    fun clipDto_mapsAllFields_andRoundsDuration() {
        val clip = ClipDto(
            clipId = "clp_1",
            sessionId = "ses_1",
            broadcasterUserId = "b1",
            creatorUserId = "c1",
            creatorDisplayName = "Alex",
            videoId = "vid_1",
            title = "behind the scenes",
            startSeconds = 12.0,
            endSeconds = 26.6,
            durationSeconds = 14.6,
            status = "ready",
            viewCount = 5400,
            shareCount = 12,
            thumbnailUrl = "http://h/p.jpg",
            createdAt = 1_733_443_200L,
        ).toDomain()

        assertEquals("clp_1", clip.clipId)
        assertEquals("vid_1", clip.videoId)
        assertEquals(ClipStatus.READY, clip.status)
        assertEquals(15, clip.durationSec) // 14.6 rounds to 15
        assertEquals("http://h/p.jpg", clip.thumbnailUrl)
        assertTrue(clip.isPlayable)
        assertFalse(clip.isProcessing)
    }

    @Test
    fun status_normalizesKnownValues_andFallsBackToFailed() {
        assertEquals(ClipStatus.PROCESSING, ClipStatus.from("processing"))
        assertEquals(ClipStatus.READY, ClipStatus.from("READY"))
        assertEquals(ClipStatus.DELETED, ClipStatus.from("deleted"))
        assertEquals(ClipStatus.FAILED, ClipStatus.from("failed"))
        assertEquals(ClipStatus.FAILED, ClipStatus.from("something_new"))
    }

    @Test
    fun blankThumbnail_becomesNull_andProcessingClip_isNotPlayable() {
        val clip = ClipDto(clipId = "clp_2", videoId = "vid_2", status = "processing", thumbnailUrl = "  ")
            .toDomain()
        assertNull(clip.thumbnailUrl)
        assertTrue(clip.isProcessing)
        assertFalse(clip.isPlayable)
    }

    @Test
    fun readyClip_withoutSourceVideo_isNotPlayable() {
        val clip = ClipDto(clipId = "clp_3", videoId = "", status = "ready").toDomain()
        assertFalse(clip.isPlayable)
    }

    @Test
    fun publicClipDto_carriesBroadcasterAttribution() {
        val clip = PublicClipDto(
            clipId = "clp_1",
            videoId = "vid_1",
            title = "t",
            status = "ready",
            broadcasterDisplayName = "Casey",
            profileId = "prof_9",
        ).toDomain()
        assertEquals("Casey", clip.broadcasterDisplayName)
        assertEquals("prof_9", clip.profileId)
    }

    @Test
    fun listDto_dropsBlankClipIds_andCarriesNextCursor() {
        val page = ClipListResponseDto(
            clips = listOf(
                ClipDto(clipId = "clp_1", videoId = "v", status = "ready"),
                ClipDto(clipId = "", videoId = "v", status = "ready"),
            ),
            nextCursor = "cur2",
        ).toDomain()
        assertEquals(listOf("clp_1"), page.items.map { it.clipId })
        assertEquals("cur2", page.nextCursor)
    }
}
