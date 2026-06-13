package com.testlogon.android.data.broadcast

import java.time.Instant

/**
 * AND-278 — canonical broadcast (live-streaming) domain models (DTO-free).
 *
 * Mirrors the VERIFIED backend contract (reference/src/api/endpoints/broadcast.ts: BroadcastSession /
 * BroadcastSessionStatus / BroadcastPlaybackUrl / SessionListResponse; reference/src/api/endpoints/
 * broadcastSchedule.ts: ScheduledListResponse; openapi.index.txt BroadcastSessionOut /
 * BroadcastSessionListOut / BroadcastScheduledListOut / BroadcastPlaybackUrlOut). KEY FACTS:
 *  - the wire has NO nested `host` object and NO nested `playback` object: identity is a bare
 *    `created_by` subject string; the HLS URL is the TOP-LEVEL `cloudfront_playback_url`.
 *  - the title field is `name` (nullable), NOT `title`.
 *  - `scheduled_at` is an epoch-SECOND integer (NOT an ISO string); `created_at`/`updated_at`/
 *    `started_at`/`stopped_at`/`cancelled_at` are ISO-8601 strings.
 *  - the terminal state is STOPPED/CANCELLED; there is NO `UPCOMING`/`ENDED` status — "upcoming" is a
 *    dedicated route, not a status value.
 *  - `viewer_count`/`remind_me` are NOT on the session payload — they come from `/viewers/count` and
 *    `/remind-me` (out of scope here; AND-279/AND-286).
 *
 * Timestamps are modeled as [Instant]; money is Long cents. Display formatting/countdowns are a
 * downstream UI concern (AND-279/AND-286).
 */
data class BroadcastSession(
    val id: String,
    val profileId: String,
    val name: String?,
    val description: String?,
    val status: BroadcastSessionStatus,
    val createdBy: String,
    val scheduledAt: Instant?,
    // AND-307 — the host schedule sub-state ("scheduled"/"cancelled"/...), distinct from lifecycle status.
    val scheduleStatus: String?,
    val startedAt: Instant?,
    val stoppedAt: Instant?,
    val cancelledAt: Instant?,
    val playbackUrl: String?,
    val thumbnailUrl: String?,
    val tipTotalCents: Long?,
    val tipCount: Int?,
    // AND-315 — host tip-config (read from GET session / PATCH tips/config response). Additive + defaulted
    // (null = "not reported on this payload") so AND-278/307 construction sites keep compiling.
    val tipEnabled: Boolean? = null,
    val tipMinCents: Long? = null,
    val tipMaxCents: Long? = null,
    val createdAt: Instant,
    val updatedAt: Instant,
)

/**
 * Verified broadcast lifecycle union from `BroadcastSessionStatus` in broadcast.ts. Unknown / absent
 * status strings map to [UNKNOWN] (the mapper never throws). There is deliberately no UPCOMING/ENDED.
 */
enum class BroadcastSessionStatus {
    DRAFT, SCHEDULED, PROVISIONING, READY, LIVE, STOPPING, STOPPED, CANCELLED, ERROR, UNKNOWN
}

/** A page of broadcast sessions (BroadcastSessionListOut = { items, has_more }). */
data class BroadcastSessionPage(
    val items: List<BroadcastSession>,
    val hasMore: Boolean,
)

/** A scheduled / upcoming list (BroadcastScheduledListOut = { items, count }). */
data class BroadcastScheduledPage(
    val items: List<BroadcastSession>,
    val count: Int,
)

/** A freshly minted short-lived signed playback URL (BroadcastPlaybackUrlOut). */
data class BroadcastPlaybackUrl(
    val sessionId: String,
    val playbackUrl: String,
    val expiresAt: Instant,
)
