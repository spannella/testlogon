package com.testlogon.android.data.contacts

/**
 * Pure, dependency-free logic for the social graph (follow / snooze) surfaces.
 *
 * Everything here is a stateless function so it is trivially unit-testable on the JVM (no Android,
 * no coroutines, no network). It covers three concerns the UI/repository layers repeatedly need:
 *
 *  1. Relationship-state mapping — collapse the backend's bidirectional booleans
 *     (is_following / is_followed_by / is_mutual + block flags) into a single [SocialRelationship]
 *     the UI can switch on to pick the primary follow affordance.
 *  2. Snooze expiry math — given a `snoozed_until` epoch-seconds timestamp and "now", decide whether
 *     a snooze is still active and how many whole days/hours remain.
 *  3. Degrade-on-404 — the canonical "is this HTTP status benign for an optional social read?" rule
 *     so a viewer with no relationship (or a not-following target) never sees an error surface.
 */
object SocialGraphMath {

    // ---- Degrade-on-404 -----------------------------------------------------

    /**
     * True when a failed *optional* social read (followers / following / counts / mutual /
     * snoozed-list / block-status) should degrade to an empty / neutral result instead of an error.
     *
     * 404 (relationship or target absent) and 410 (gone) are benign — the social surface is
     * additive and its absence is not an error. Everything else (401/403/429/5xx) is a real failure.
     */
    fun isBenignSocialReadFailure(httpStatus: Int): Boolean = httpStatus == 404 || httpStatus == 410

    /**
     * True when a failed snooze *mutation* is benign. Un-snoozing is idempotent, so a 404
     * ("not currently snoozed" / "not following") on DELETE is a success from the user's view.
     */
    fun isBenignUnsnoozeFailure(httpStatus: Int): Boolean = httpStatus == 404 || httpStatus == 410

    // ---- Relationship-state mapping -----------------------------------------

    /**
     * Collapse the raw follow-status booleans into a single relationship the UI can switch on.
     * Blocking dominates every follow state (a blocked relationship hides the follow affordance).
     *
     * Precedence: BlockedByMe > BlockingMe > Mutual > Following > FollowsYou > None.
     */
    fun relationshipOf(
        isFollowing: Boolean,
        isFollowedBy: Boolean,
        isMutual: Boolean = isFollowing && isFollowedBy,
        isBlockedByMe: Boolean = false,
        isBlockingMe: Boolean = false,
    ): SocialRelationship = when {
        isBlockedByMe -> SocialRelationship.BLOCKED_BY_ME
        isBlockingMe -> SocialRelationship.BLOCKING_ME
        isMutual || (isFollowing && isFollowedBy) -> SocialRelationship.MUTUAL
        isFollowing -> SocialRelationship.FOLLOWING
        isFollowedBy -> SocialRelationship.FOLLOWS_YOU
        else -> SocialRelationship.NONE
    }

    /**
     * The label for the primary follow action button given the current relationship.
     * Returns null when there is no follow affordance to show (either block direction).
     */
    fun followActionLabel(relationship: SocialRelationship): FollowAction? = when (relationship) {
        SocialRelationship.MUTUAL,
        SocialRelationship.FOLLOWING -> FollowAction.UNFOLLOW
        SocialRelationship.FOLLOWS_YOU -> FollowAction.FOLLOW_BACK
        SocialRelationship.NONE -> FollowAction.FOLLOW
        SocialRelationship.BLOCKED_BY_ME,
        SocialRelationship.BLOCKING_ME -> null
    }

    // ---- Snooze math --------------------------------------------------------

    /**
     * True when a snooze with the given `snoozed_until` (epoch SECONDS; may be null) is still
     * active at [nowSeconds]. A null / non-positive timestamp means "not snoozed".
     */
    fun isSnoozeActive(snoozedUntilSeconds: Long?, nowSeconds: Long): Boolean =
        snoozedUntilSeconds != null && snoozedUntilSeconds > nowSeconds

    /**
     * Whole hours remaining until a snooze expires, clamped to 0. Returns 0 for an inactive /
     * absent snooze. Never negative.
     */
    fun snoozeRemainingHours(snoozedUntilSeconds: Long?, nowSeconds: Long): Long {
        if (snoozedUntilSeconds == null) return 0L
        val remaining = snoozedUntilSeconds - nowSeconds
        if (remaining <= 0L) return 0L
        return remaining / SECONDS_PER_HOUR
    }

    /**
     * Whole days remaining (rounded UP so a partial final day still reads as "1 day left"),
     * clamped to 0.
     */
    fun snoozeRemainingDays(snoozedUntilSeconds: Long?, nowSeconds: Long): Long {
        if (snoozedUntilSeconds == null) return 0L
        val remaining = snoozedUntilSeconds - nowSeconds
        if (remaining <= 0L) return 0L
        return (remaining + SECONDS_PER_DAY - 1) / SECONDS_PER_DAY
    }

    /**
     * A short human label for the remaining snooze, e.g. "Snoozed - 3 days left",
     * "Snoozed - 5 hours left", "Snoozed - <1 hour left". Returns null when not snoozed.
     *
     * When at least a full day remains the label is expressed in whole days (rounded UP so a partial
     * final day still reads as "N days left"); under a day it falls back to whole hours, then to a
     * "<1 hour left" catch-all. This keeps every granularity reachable and accurate.
     */
    fun snoozeLabel(snoozedUntilSeconds: Long?, nowSeconds: Long): String? {
        if (!isSnoozeActive(snoozedUntilSeconds, nowSeconds)) return null
        val remaining = snoozedUntilSeconds!! - nowSeconds
        // Only reach for the "days" wording once at least a full day is left; otherwise use hours so
        // "5 hours left" / "<1 hour left" are actually produced (the day-rounding never masks them).
        if (remaining >= SECONDS_PER_DAY) {
            val days = snoozeRemainingDays(snoozedUntilSeconds, nowSeconds)
            val unit = if (days == 1L) "day" else "days"
            return "Snoozed - $days $unit left"
        }
        val hours = remaining / SECONDS_PER_HOUR
        if (hours >= 1L) {
            val unit = if (hours == 1L) "hour" else "hours"
            return "Snoozed - $hours $unit left"
        }
        return "Snoozed - <1 hour left"
    }

    /**
     * Clamp a requested snooze duration into the backend-accepted 1..90 day range. Values below 1
     * become 1; values above 90 become 90. The server also validates (422), but clamping client-side
     * avoids a pointless round-trip.
     */
    fun clampSnoozeDays(days: Int): Int = days.coerceIn(MIN_SNOOZE_DAYS, MAX_SNOOZE_DAYS)

    /** Compute the expiry timestamp (epoch seconds) for a snooze of [days] starting at [nowSeconds]. */
    fun snoozeExpiryFor(days: Int, nowSeconds: Long): Long =
        nowSeconds + clampSnoozeDays(days).toLong() * SECONDS_PER_DAY

    const val MIN_SNOOZE_DAYS = 1
    const val MAX_SNOOZE_DAYS = 90
    private const val SECONDS_PER_HOUR = 3600L
    private const val SECONDS_PER_DAY = 86_400L
}

/** The collapsed follow/block relationship a viewer has with a target user. */
enum class SocialRelationship {
    NONE,
    FOLLOWING,
    FOLLOWS_YOU,
    MUTUAL,
    BLOCKED_BY_ME,
    BLOCKING_ME,
}

/** The primary follow action a viewer can take, derived from the relationship. */
enum class FollowAction {
    FOLLOW,
    FOLLOW_BACK,
    UNFOLLOW,
}
