package com.testlogon.android.feature.broadcast

import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * AND-279 — pure bucketization + sort tests (TC-AND-279-01..03). Field/status names per the verified
 * contract: started_at/stopped_at, status `stopped` not `ended`; scheduled_at is epoch seconds.
 */
class BroadcastBucketizerTest {

    private val now = Instant.parse("2026-06-09T12:00:00Z")

    private fun session(
        id: String,
        status: BroadcastSessionStatus,
        scheduledAt: Instant? = null,
        startedAt: Instant? = null,
        stoppedAt: Instant? = null,
        cancelledAt: Instant? = null,
        name: String? = "Session $id",
    ) = BroadcastSession(
        id = id,
        profileId = "prof",
        name = name,
        description = null,
        status = status,
        createdBy = "host_$id",
        scheduledAt = scheduledAt,
        scheduleStatus = null,
        startedAt = startedAt,
        stoppedAt = stoppedAt,
        cancelledAt = cancelledAt,
        playbackUrl = null,
        thumbnailUrl = null,
        tipTotalCents = null,
        tipCount = null,
        createdAt = Instant.EPOCH,
        updatedAt = Instant.EPOCH,
    )

    @Test
    fun bucketOf_classifiesEachStatus() {
        // scheduled future -> Upcoming.
        assertEquals(
            BroadcastBucket.UPCOMING,
            BroadcastBucketizer.bucketOf(
                session("a", BroadcastSessionStatus.SCHEDULED, scheduledAt = now.plusSeconds(3600)),
                now,
            ),
        )
        // live (started, not stopped) -> Live.
        assertEquals(
            BroadcastBucket.LIVE,
            BroadcastBucketizer.bucketOf(
                session("b", BroadcastSessionStatus.LIVE, startedAt = now.minusSeconds(60)),
                now,
            ),
        )
        // stopped -> Past.
        assertEquals(
            BroadcastBucket.PAST,
            BroadcastBucketizer.bucketOf(
                session("c", BroadcastSessionStatus.STOPPED, stoppedAt = now.minusSeconds(60)),
                now,
            ),
        )
        // cancelled -> Past.
        assertEquals(
            BroadcastBucket.PAST,
            BroadcastBucketizer.bucketOf(
                session("d", BroadcastSessionStatus.CANCELLED, cancelledAt = now.minusSeconds(60)),
                now,
            ),
        )
        // provisioning (pre-go-live, no started_at) -> Upcoming.
        assertEquals(
            BroadcastBucket.UPCOMING,
            BroadcastBucketizer.bucketOf(session("e", BroadcastSessionStatus.PROVISIONING), now),
        )
        // ready (no started_at) -> Upcoming.
        assertEquals(
            BroadcastBucket.UPCOMING,
            BroadcastBucketizer.bucketOf(session("f", BroadcastSessionStatus.READY), now),
        )
    }

    @Test
    fun bucketOf_boundaryAndMalformed() {
        // At-now with started_at -> Live.
        assertEquals(
            BroadcastBucket.LIVE,
            BroadcastBucketizer.bucketOf(session("g", BroadcastSessionStatus.LIVE, startedAt = now), now),
        )
        // Unknown status, no timestamps -> Past (degrades safely; no throw).
        assertEquals(
            BroadcastBucket.PAST,
            BroadcastBucketizer.bucketOf(session("h", BroadcastSessionStatus.UNKNOWN), now),
        )
        // error status -> Past.
        assertEquals(
            BroadcastBucket.PAST,
            BroadcastBucketizer.bucketOf(session("i", BroadcastSessionStatus.ERROR), now),
        )
    }

    @Test
    fun bucketize_sortsEachBucket() {
        val sessions = listOf(
            session("live_old", BroadcastSessionStatus.LIVE, startedAt = now.minusSeconds(600)),
            session("live_new", BroadcastSessionStatus.LIVE, startedAt = now.minusSeconds(60)),
            session("up_late", BroadcastSessionStatus.SCHEDULED, scheduledAt = now.plusSeconds(7200)),
            session("up_soon", BroadcastSessionStatus.SCHEDULED, scheduledAt = now.plusSeconds(600)),
            session("past_old", BroadcastSessionStatus.STOPPED, stoppedAt = now.minusSeconds(7200)),
            session("past_recent", BroadcastSessionStatus.STOPPED, stoppedAt = now.minusSeconds(600)),
        )
        val (live, upcoming, past) = BroadcastBucketizer.bucketize(sessions, now)

        assertEquals(listOf("live_new", "live_old"), live.map { it.sessionId })
        assertEquals(listOf("up_soon", "up_late"), upcoming.map { it.sessionId })
        assertEquals(listOf("past_recent", "past_old"), past.map { it.sessionId })
    }

    @Test
    fun bucketize_mapsTitleHostAndDefault() {
        val (_, upcoming, _) = BroadcastBucketizer.bucketize(
            listOf(session("x", BroadcastSessionStatus.SCHEDULED, scheduledAt = now.plusSeconds(60), name = null)),
            now,
        )
        val item = upcoming.single()
        assertEquals(BroadcastBucketizer.DEFAULT_TITLE, item.title)
        assertEquals("host_x", item.hostName)
        assertTrue(!item.reminderSet)
    }
}
