package com.testlogon.android.core.model.blocking

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-382 - [BlockRelationship] derivation from the verified is_blocked_by_me / is_blocking_me flags. */
class BlockRelationshipTest {

    @Test
    fun from_neither_isNormal() {
        assertEquals(BlockRelationship.Normal, BlockRelationship.from(false, false))
    }

    @Test
    fun from_blockedByMe() {
        assertEquals(BlockRelationship.BlockedByMe, BlockRelationship.from(isBlockedByMe = true, isBlockingMe = false))
    }

    @Test
    fun from_blockingMe() {
        assertEquals(BlockRelationship.BlockedMe, BlockRelationship.from(isBlockedByMe = false, isBlockingMe = true))
    }

    @Test
    fun from_bothDirections_blockedByMeWins() {
        // The blocker should see their own unblock affordance, not the passive banner.
        assertEquals(BlockRelationship.BlockedByMe, BlockRelationship.from(isBlockedByMe = true, isBlockingMe = true))
    }

    @Test
    fun contactBlocked_trueForEitherBlockDirection() {
        assertFalse(BlockRelationship.Normal.contactBlocked)
        assertTrue(BlockRelationship.BlockedByMe.contactBlocked)
        assertTrue(BlockRelationship.BlockedMe.contactBlocked)
    }
}
