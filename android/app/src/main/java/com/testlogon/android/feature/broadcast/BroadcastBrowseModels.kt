package com.testlogon.android.feature.broadcast

import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import java.time.Instant

/**
 * AND-279 — presentation models + the pure bucketizer for the broadcast browse screen.
 *
 * Pure / Android-free so it is fully JVM-unit-testable. Maps the AND-278 [BroadcastSession] domain
 * into the three Live / Upcoming / Past buckets the browse screen renders, derived from
 * `status`/timestamps (there is no `ended` status — ended == STOPPED/CANCELLED; AND-279 §6/§16).
 */

/** The three browse buckets (a port-specific 3-bucket design over the 2 web scheduled buckets). */
enum class BroadcastBucket { LIVE, UPCOMING, PAST }

/** A single browse row. Timestamps are [Instant] (display formatting is the composable's concern). */
data class BroadcastItem(
    val sessionId: String,
    val title: String,
    val hostName: String?,
    val thumbnailUrl: String?,
    val status: BroadcastSessionStatus,
    val scheduledStart: Instant?,
    val actualStart: Instant?,
    val endedAt: Instant?,
    val viewerCount: Int?,
    /** Client/local only (no server flag); reflects the optimistic remind-me toggle. */
    val reminderSet: Boolean = false,
    /** Mutation in-flight — the toggle shows progress and is disabled. */
    val reminderPending: Boolean = false,
)

/**
 * AND-279 — pure, JVM-tested bucketization + per-bucket sort. No Android deps; `now` is injected so
 * tests are deterministic.
 */
object BroadcastBucketizer {

    /**
     * Splits [sessions] into (live, upcoming, past), each sorted per FR-4:
     *  - Live: by actualStart desc (most recently started first).
     *  - Upcoming: by scheduledStart asc (soonest first).
     *  - Past: by endedAt/actualStart desc (most recent first).
     */
    fun bucketize(
        sessions: List<BroadcastSession>,
        now: Instant,
    ): Triple<List<BroadcastItem>, List<BroadcastItem>, List<BroadcastItem>> {
        val live = ArrayList<BroadcastItem>()
        val upcoming = ArrayList<BroadcastItem>()
        val past = ArrayList<BroadcastItem>()
        for (session in sessions) {
            val item = session.toItem()
            when (bucketOf(session, now)) {
                BroadcastBucket.LIVE -> live.add(item)
                BroadcastBucket.UPCOMING -> upcoming.add(item)
                BroadcastBucket.PAST -> past.add(item)
            }
        }
        live.sortByDescending { it.actualStart ?: Instant.EPOCH }
        upcoming.sortBy { it.scheduledStart ?: Instant.MAX }
        past.sortByDescending { it.endedAt ?: it.actualStart ?: Instant.EPOCH }
        return Triple(live, upcoming, past)
    }

    /**
     * Classifies a single session. A terminal/ended session is Past; an actively-streaming session
     * is Live; otherwise it is Upcoming (incl. pre-go-live provisioning/ready and scheduled-future).
     * Sessions with garbage/missing timestamps that are not clearly live/scheduled degrade to Past.
     */
    fun bucketOf(session: BroadcastSession, now: Instant): BroadcastBucket {
        val ended = session.stoppedAt != null ||
            session.cancelledAt != null ||
            session.status in TERMINAL_STATUSES
        if (ended) return BroadcastBucket.PAST

        val live = session.status == BroadcastSessionStatus.LIVE ||
            (session.startedAt != null && session.stoppedAt == null && session.cancelledAt == null)
        if (live) return BroadcastBucket.LIVE

        // Pre-go-live (scheduled / provisioning / ready / draft, not yet started) -> Upcoming.
        if (session.startedAt == null && session.status in UPCOMING_STATUSES) {
            return BroadcastBucket.UPCOMING
        }
        // A bare future schedule with an unknown status still counts as Upcoming.
        if (session.startedAt == null && session.scheduledAt != null && session.scheduledAt.isAfter(now)) {
            return BroadcastBucket.UPCOMING
        }
        // Anything else (unparseable / unknown / past-scheduled-but-never-started) -> Past.
        return BroadcastBucket.PAST
    }

    private val TERMINAL_STATUSES = setOf(
        BroadcastSessionStatus.STOPPING,
        BroadcastSessionStatus.STOPPED,
        BroadcastSessionStatus.CANCELLED,
        BroadcastSessionStatus.ERROR,
    )

    private val UPCOMING_STATUSES = setOf(
        BroadcastSessionStatus.DRAFT,
        BroadcastSessionStatus.SCHEDULED,
        BroadcastSessionStatus.PROVISIONING,
        BroadcastSessionStatus.READY,
    )

    private fun BroadcastSession.toItem(): BroadcastItem = BroadcastItem(
        sessionId = id,
        title = name?.takeIf { it.isNotBlank() } ?: DEFAULT_TITLE,
        hostName = createdBy.takeIf { it.isNotBlank() },
        thumbnailUrl = thumbnailUrl,
        status = status,
        scheduledStart = scheduledAt,
        actualStart = startedAt,
        endedAt = stoppedAt ?: cancelledAt,
        viewerCount = null,
    )

    /** Web fallback title for a session with no `name`. */
    const val DEFAULT_TITLE = "Untitled Broadcast"
}
