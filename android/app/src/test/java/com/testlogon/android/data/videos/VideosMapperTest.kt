package com.testlogon.android.data.videos

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-189 / AND-190 — DTO -> domain mapping (video_id -> id, duration rounding, playback URL rule). */
class VideosMapperTest {

    @Test
    fun listItem_mapsVideoIdAndRoundsDuration() {
        val dto = VideoListItemDto(
            videoId = "vid_1",
            title = "Intro",
            durationSeconds = 372.6,
            thumbnailUrl = "http://h/t.jpg",
        )
        val summary = dto.toSummary()
        assertEquals("vid_1", summary.id)
        assertEquals("Intro", summary.title)
        assertEquals(373, summary.durationSec)
        assertEquals("http://h/t.jpg", summary.thumbnailUrl)
    }

    @Test
    fun listItem_missingDuration_andBlankThumb_mapToNull() {
        val dto = VideoListItemDto(videoId = "vid_2", title = "X", durationSeconds = null, thumbnailUrl = "")
        val summary = dto.toSummary()
        assertNull(summary.durationSec)
        assertNull(summary.thumbnailUrl)
    }

    @Test
    fun listResponse_dropsBlankIdRows_andCarriesCursor() {
        val resp = VideoListResponseDto(
            items = listOf(
                VideoListItemDto(videoId = "vid_1", title = "A"),
                VideoListItemDto(videoId = "", title = "B"),
            ),
            cursor = "c2",
        )
        val page = resp.toDomain()
        assertEquals(listOf("vid_1"), page.items.map { it.id })
        assertEquals("c2", page.cursor)
    }

    @Test
    fun detail_buildsTokenizedPlaybackUrl_whenManifestAndTokenPresent() {
        val dto = VideoDetailDto(
            videoId = "vid_1",
            ownerUserId = "u1",
            title = "T",
            status = "ready",
            visibility = "public",
            hlsManifestUrl = "http://h/master.m3u8",
            playbackToken = "tok123",
        )
        val detail = dto.toDomain()
        assertEquals("http://h/master.m3u8?token=tok123", detail.playbackUrl)
        assertTrue(detail.isPlayable)
        assertFalse(detail.isProcessing)
    }

    @Test
    fun detail_noToken_orNoManifest_yieldsNullPlaybackUrl() {
        val noToken = VideoDetailDto(
            videoId = "v", ownerUserId = "u", title = "T", status = "ready", visibility = "public",
            hlsManifestUrl = "http://h/master.m3u8", playbackToken = null,
        ).toDomain()
        assertNull(noToken.playbackUrl)
        assertFalse(noToken.isPlayable)

        val noManifest = VideoDetailDto(
            videoId = "v", ownerUserId = "u", title = "T", status = "ready", visibility = "public",
            hlsManifestUrl = null, playbackToken = "tok",
        ).toDomain()
        assertNull(noManifest.playbackUrl)
    }

    @Test
    fun detail_processingStatus_isFlagged() {
        val dto = VideoDetailDto(
            videoId = "v", ownerUserId = "u", title = "T", status = "encoding", visibility = "public",
        )
        assertTrue(dto.toDomain().isProcessing)
    }

    @Test
    fun detail_entitlementDefaultsToTrueWhenAbsent_butFalseWhenStated() {
        val absent = VideoDetailDto(videoId = "v", ownerUserId = "u", title = "T", status = "ready", visibility = "public").toDomain()
        assertTrue(absent.isEntitled)
        val gated = VideoDetailDto(videoId = "v", ownerUserId = "u", title = "T", status = "ready", visibility = "public", isEntitled = false).toDomain()
        assertFalse(gated.isEntitled)
    }
}
