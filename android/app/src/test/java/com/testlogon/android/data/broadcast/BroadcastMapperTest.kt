package com.testlogon.android.data.broadcast

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * AND-278 — pure DTO -> domain mapper tests. Status enum (incl. US/UK "cancelled" + unknown/absent),
 * the top-level cloudfront HLS URL carry-through, epoch-second scheduled_at parsing, ISO timestamp
 * parsing with EPOCH fallback, live-without-url safety, and the list/scheduled/playback envelopes.
 */
class BroadcastMapperTest {

    private fun live(playback: String? = "https://stream.testlogon.dev/bcs_01HX1/index.m3u8") =
        BroadcastSessionDto(
            id = "bcs_01HX1", profileId = "prof_9", status = "live", createdBy = "usr_42",
            createdAt = "2026-06-05T22:00:00Z", updatedAt = "2026-06-05T23:00:05Z",
            name = "Friday Night Live", description = "Weekly Q&A",
            startedAt = "2026-06-05T23:00:00Z", cloudfrontPlaybackUrl = playback,
            thumbnailUrl = "https://cdn.testlogon.dev/t/bcs_01HX1.jpg",
            tipTotalCents = 12_500L, tipCount = 37,
        )

    @Test
    fun liveSession_mapsStatus_playbackUrl_name() {
        val s = live().toDomain()
        assertEquals(BroadcastSessionStatus.LIVE, s.status)
        assertEquals("https://stream.testlogon.dev/bcs_01HX1/index.m3u8", s.playbackUrl)
        assertEquals("Friday Night Live", s.name)
        assertEquals("usr_42", s.createdBy)
        assertEquals(Instant.parse("2026-06-05T23:00:00Z"), s.startedAt)
        assertEquals(12_500L, s.tipTotalCents)
    }

    @Test
    fun scheduledSession_epochSecondScheduledAt_nullPlayback() {
        val dto = BroadcastSessionDto(
            id = "bcs_01HX2", profileId = "prof_9", status = "scheduled", createdBy = "usr_42",
            createdAt = "2026-06-01T10:00:00Z", updatedAt = "2026-06-01T10:00:00Z",
            name = "Album listening party", scheduledAt = 1_749_319_200L, scheduleStatus = "scheduled",
        )
        val s = dto.toDomain()
        assertEquals(BroadcastSessionStatus.SCHEDULED, s.status)
        // scheduled_at is an epoch-SECOND integer, not an ISO string.
        assertEquals(Instant.ofEpochSecond(1_749_319_200L), s.scheduledAt)
        assertNull(s.playbackUrl)
        assertNull(s.startedAt)
    }

    @Test
    fun statusEnum_tolerance() {
        assertEquals(BroadcastSessionStatus.CANCELLED, "cancelled".toBroadcastStatus())
        assertEquals(BroadcastSessionStatus.CANCELLED, "canceled".toBroadcastStatus())
        assertEquals(BroadcastSessionStatus.STOPPED, "STOPPED".toBroadcastStatus())
        assertEquals(BroadcastSessionStatus.PROVISIONING, "provisioning".toBroadcastStatus())
        assertEquals(BroadcastSessionStatus.UNKNOWN, "weird".toBroadcastStatus())
        assertEquals(BroadcastSessionStatus.UNKNOWN, null.toBroadcastStatus())
    }

    @Test
    fun liveWithoutUrl_mapsLive_nullPlayback_noThrow() {
        val s = live(playback = null).toDomain()
        assertEquals(BroadcastSessionStatus.LIVE, s.status)
        assertNull(s.playbackUrl)
    }

    @Test
    fun missingTimestamps_fallBackToEpoch_notThrow() {
        val dto = BroadcastSessionDto(
            id = "bcs_x", profileId = "prof_1", status = "draft", createdBy = "usr_1",
            createdAt = null, updatedAt = "garbage-not-iso",
        )
        val s = dto.toDomain()
        assertEquals(Instant.EPOCH, s.createdAt)
        assertEquals(Instant.EPOCH, s.updatedAt)
        assertEquals(BroadcastSessionStatus.DRAFT, s.status)
        assertNull(s.name)
        assertNull(s.tipTotalCents)
    }

    @Test
    fun listEnvelope_mapsItemsAndHasMore() {
        val page = BroadcastSessionListRespDto(items = listOf(live()), hasMore = true).toDomain()
        assertEquals(1, page.items.size)
        assertTrue(page.hasMore)
    }

    @Test
    fun scheduledEnvelope_mapsItemsAndCount() {
        val page = BroadcastScheduledListRespDto(items = listOf(live()), count = 1).toDomain()
        assertEquals(1, page.items.size)
        assertEquals(1, page.count)
    }

    @Test
    fun playbackUrlDto_mapsEpochSecondExpiry() {
        val mint = BroadcastPlaybackUrlDto(
            sessionId = "bcs_01HX1",
            playbackUrl = "https://stream.testlogon.dev/bcs_01HX1/index.m3u8?token=abc",
            expiresAt = 1_749_322_800L,
        ).toDomain()
        assertEquals("bcs_01HX1", mint.sessionId)
        assertEquals(Instant.ofEpochSecond(1_749_322_800L), mint.expiresAt)
    }
}
