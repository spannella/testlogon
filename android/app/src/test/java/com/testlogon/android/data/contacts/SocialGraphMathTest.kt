package com.testlogon.android.data.contacts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure JVM tests for [SocialGraphMath] — relationship-state mapping, snooze expiry/label math, and
 * degrade-on-404. No Android, no coroutines.
 */
class SocialGraphMathTest {

    private val now = 1_000_000L
    private val day = 86_400L
    private val hour = 3_600L

    // ---- degrade-on-404 -----------------------------------------------------

    @Test
    fun benignSocialRead_404_and_410() {
        assertTrue(SocialGraphMath.isBenignSocialReadFailure(404))
        assertTrue(SocialGraphMath.isBenignSocialReadFailure(410))
    }

    @Test
    fun benignSocialRead_rejectsRealFailures() {
        assertFalse(SocialGraphMath.isBenignSocialReadFailure(403))
        assertFalse(SocialGraphMath.isBenignSocialReadFailure(429))
        assertFalse(SocialGraphMath.isBenignSocialReadFailure(500))
    }

    @Test
    fun benignUnsnooze_isIdempotentOn404() {
        assertTrue(SocialGraphMath.isBenignUnsnoozeFailure(404))
        assertFalse(SocialGraphMath.isBenignUnsnoozeFailure(400))
    }

    // ---- relationship mapping ----------------------------------------------

    @Test
    fun relationship_none_whenNoEdges() {
        assertEquals(
            SocialRelationship.NONE,
            SocialGraphMath.relationshipOf(isFollowing = false, isFollowedBy = false),
        )
    }

    @Test
    fun relationship_following_only() {
        assertEquals(
            SocialRelationship.FOLLOWING,
            SocialGraphMath.relationshipOf(isFollowing = true, isFollowedBy = false),
        )
    }

    @Test
    fun relationship_followsYou_only() {
        assertEquals(
            SocialRelationship.FOLLOWS_YOU,
            SocialGraphMath.relationshipOf(isFollowing = false, isFollowedBy = true),
        )
    }

    @Test
    fun relationship_mutual_bothDirections() {
        assertEquals(
            SocialRelationship.MUTUAL,
            SocialGraphMath.relationshipOf(isFollowing = true, isFollowedBy = true),
        )
    }

    @Test
    fun relationship_mutual_honorsExplicitFlag() {
        assertEquals(
            SocialRelationship.MUTUAL,
            SocialGraphMath.relationshipOf(isFollowing = false, isFollowedBy = false, isMutual = true),
        )
    }

    @Test
    fun relationship_blockedByMe_dominatesFollow() {
        assertEquals(
            SocialRelationship.BLOCKED_BY_ME,
            SocialGraphMath.relationshipOf(
                isFollowing = true, isFollowedBy = true, isBlockedByMe = true,
            ),
        )
    }

    @Test
    fun relationship_blockingMe_dominatesFollow() {
        assertEquals(
            SocialRelationship.BLOCKING_ME,
            SocialGraphMath.relationshipOf(
                isFollowing = true, isFollowedBy = true, isBlockingMe = true,
            ),
        )
    }

    @Test
    fun relationship_blockedByMe_beatsBlockingMe() {
        assertEquals(
            SocialRelationship.BLOCKED_BY_ME,
            SocialGraphMath.relationshipOf(
                isFollowing = false, isFollowedBy = false,
                isBlockedByMe = true, isBlockingMe = true,
            ),
        )
    }

    // ---- follow action label -----------------------------------------------

    @Test
    fun action_none_isFollow() {
        assertEquals(FollowAction.FOLLOW, SocialGraphMath.followActionLabel(SocialRelationship.NONE))
    }

    @Test
    fun action_followsYou_isFollowBack() {
        assertEquals(
            FollowAction.FOLLOW_BACK,
            SocialGraphMath.followActionLabel(SocialRelationship.FOLLOWS_YOU),
        )
    }

    @Test
    fun action_following_and_mutual_isUnfollow() {
        assertEquals(FollowAction.UNFOLLOW, SocialGraphMath.followActionLabel(SocialRelationship.FOLLOWING))
        assertEquals(FollowAction.UNFOLLOW, SocialGraphMath.followActionLabel(SocialRelationship.MUTUAL))
    }

    @Test
    fun action_blockedEitherWay_isNull() {
        assertNull(SocialGraphMath.followActionLabel(SocialRelationship.BLOCKED_BY_ME))
        assertNull(SocialGraphMath.followActionLabel(SocialRelationship.BLOCKING_ME))
    }

    // ---- snooze active ------------------------------------------------------

    @Test
    fun snooze_null_isInactive() {
        assertFalse(SocialGraphMath.isSnoozeActive(null, now))
    }

    @Test
    fun snooze_past_isInactive() {
        assertFalse(SocialGraphMath.isSnoozeActive(now - 10, now))
    }

    @Test
    fun snooze_future_isActive() {
        assertTrue(SocialGraphMath.isSnoozeActive(now + 10, now))
    }

    // ---- snooze remaining ---------------------------------------------------

    @Test
    fun remainingHours_clampsToZero() {
        assertEquals(0L, SocialGraphMath.snoozeRemainingHours(null, now))
        assertEquals(0L, SocialGraphMath.snoozeRemainingHours(now - day, now))
    }

    @Test
    fun remainingHours_wholeHours() {
        assertEquals(5L, SocialGraphMath.snoozeRemainingHours(now + 5 * hour, now))
    }

    @Test
    fun remainingDays_roundsUp() {
        // 1 day + 1 second => 2 days remaining (partial final day still counts).
        assertEquals(2L, SocialGraphMath.snoozeRemainingDays(now + day + 1, now))
        assertEquals(3L, SocialGraphMath.snoozeRemainingDays(now + 3 * day, now))
        assertEquals(0L, SocialGraphMath.snoozeRemainingDays(now - 1, now))
    }

    // ---- snooze label -------------------------------------------------------

    @Test
    fun label_null_whenNotSnoozed() {
        assertNull(SocialGraphMath.snoozeLabel(null, now))
        assertNull(SocialGraphMath.snoozeLabel(now - 1, now))
    }

    @Test
    fun label_days_pluralization() {
        assertEquals("Snoozed - 3 days left", SocialGraphMath.snoozeLabel(now + 3 * day, now))
        // Exactly one full day => "1 day left" (singular).
        assertEquals("Snoozed - 1 day left", SocialGraphMath.snoozeLabel(now + day, now))
        // A day plus a bit still rounds up to "2 days left".
        assertEquals("Snoozed - 2 days left", SocialGraphMath.snoozeLabel(now + day + 1, now))
    }

    @Test
    fun label_hours_whenLessThanOneDay() {
        // Under a full day => expressed in whole hours.
        assertEquals("Snoozed - 5 hours left", SocialGraphMath.snoozeLabel(now + 5 * hour, now))
        assertEquals("Snoozed - 1 hour left", SocialGraphMath.snoozeLabel(now + hour, now))
    }

    @Test
    fun label_subHour_catchAll() {
        assertEquals("Snoozed - <1 hour left", SocialGraphMath.snoozeLabel(now + 60, now))
    }

    // ---- clamp + expiry -----------------------------------------------------

    @Test
    fun clampDays_bounds() {
        assertEquals(1, SocialGraphMath.clampSnoozeDays(0))
        assertEquals(1, SocialGraphMath.clampSnoozeDays(-5))
        assertEquals(90, SocialGraphMath.clampSnoozeDays(1000))
        assertEquals(7, SocialGraphMath.clampSnoozeDays(7))
    }

    @Test
    fun expiryFor_computesFromNow() {
        assertEquals(now + 7 * day, SocialGraphMath.snoozeExpiryFor(7, now))
        // clamped input.
        assertEquals(now + 90 * day, SocialGraphMath.snoozeExpiryFor(1000, now))
    }
}
