package com.testlogon.android.core.model.delegates

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-360 - JVM unit tests for [DelegateModMath], the pure permission / role gating for the delegate
 * broadcast moderation surface. No Android / IO. Covers: control vs moderate gating per action, the
 * null-context (acting-as-oneself) deny, the allowed-action projection, ban-membership, the wire ->
 * label mapping (known + unknown + blank) and the by-type counting.
 */
class DelegateModMathTest {

    private fun ctx(vararg perms: DelegatePermission) =
        DelegationContext(creatorId = "cr_1", creatorName = "Acme", permissions = perms.toSet())

    // ---- canPerform: control gating ----

    @Test
    fun canPerform_start_requiresControl() {
        val control = ctx(DelegatePermission.BROADCAST_CONTROL)
        assertTrue(DelegateModMath.canPerform(control, BroadcastModAction.START))
        assertTrue(DelegateModMath.canPerform(control, BroadcastModAction.STOP))
        assertTrue(DelegateModMath.canPerform(control, BroadcastModAction.SCHEDULE))
    }

    @Test
    fun canPerform_control_deniedForModerateOnly() {
        val moderate = ctx(DelegatePermission.BROADCAST_MODERATE)
        assertFalse(DelegateModMath.canPerform(moderate, BroadcastModAction.START))
        assertFalse(DelegateModMath.canPerform(moderate, BroadcastModAction.STOP))
        assertFalse(DelegateModMath.canPerform(moderate, BroadcastModAction.SCHEDULE))
    }

    // ---- canPerform: moderation gating ----

    @Test
    fun canPerform_moderationActions_requireModerate() {
        val moderate = ctx(DelegatePermission.BROADCAST_MODERATE)
        val actions = listOf(
            BroadcastModAction.MUTE, BroadcastModAction.BAN, BroadcastModAction.UNBAN,
            BroadcastModAction.PIN, BroadcastModAction.UNPIN, BroadcastModAction.DELETE_CHAT,
            BroadcastModAction.ANNOUNCE, BroadcastModAction.REGISTER_MODERATOR,
            BroadcastModAction.LIST_MODERATORS, BroadcastModAction.LIST_BANS, BroadcastModAction.VIEW_LOG,
        )
        actions.forEach { assertTrue("$it should be allowed", DelegateModMath.canPerform(moderate, it)) }
    }

    @Test
    fun canPerform_moderation_deniedForControlOnly() {
        val control = ctx(DelegatePermission.BROADCAST_CONTROL)
        assertFalse(DelegateModMath.canPerform(control, BroadcastModAction.BAN))
        assertFalse(DelegateModMath.canPerform(control, BroadcastModAction.ANNOUNCE))
        assertFalse(DelegateModMath.canPerform(control, BroadcastModAction.VIEW_LOG))
    }

    @Test
    fun canPerform_nullContext_alwaysDenied() {
        assertFalse(DelegateModMath.canPerform(null, BroadcastModAction.START))
        assertFalse(DelegateModMath.canPerform(null, BroadcastModAction.BAN))
        assertFalse(DelegateModMath.canPerform(null, BroadcastModAction.VIEW_LOG))
    }

    @Test
    fun canPerform_unknownPermissionInSet_isInert() {
        val onlyUnknown = ctx(DelegatePermission.UNKNOWN)
        assertFalse(DelegateModMath.canPerform(onlyUnknown, BroadcastModAction.BAN))
        assertFalse(DelegateModMath.canPerform(onlyUnknown, BroadcastModAction.START))
    }

    // ---- allowedActions ----

    @Test
    fun allowedActions_nullContext_isEmpty() {
        assertTrue(DelegateModMath.allowedActions(null).isEmpty())
    }

    @Test
    fun allowedActions_moderateOnly_excludesControl() {
        val allowed = DelegateModMath.allowedActions(ctx(DelegatePermission.BROADCAST_MODERATE))
        assertTrue(BroadcastModAction.BAN in allowed)
        assertTrue(BroadcastModAction.VIEW_LOG in allowed)
        assertFalse(BroadcastModAction.START in allowed)
        assertFalse(BroadcastModAction.SCHEDULE in allowed)
    }

    @Test
    fun allowedActions_both_includesAll() {
        val allowed = DelegateModMath.allowedActions(
            ctx(DelegatePermission.BROADCAST_CONTROL, DelegatePermission.BROADCAST_MODERATE),
        )
        assertEquals(BroadcastModAction.entries.toSet(), allowed)
    }

    // ---- canModerate / canControl ----

    @Test
    fun canModerate_and_canControl_areIndependent() {
        val moderate = ctx(DelegatePermission.BROADCAST_MODERATE)
        val control = ctx(DelegatePermission.BROADCAST_CONTROL)
        assertTrue(DelegateModMath.canModerate(moderate))
        assertFalse(DelegateModMath.canControl(moderate))
        assertTrue(DelegateModMath.canControl(control))
        assertFalse(DelegateModMath.canModerate(control))
        assertFalse(DelegateModMath.canModerate(null))
        assertFalse(DelegateModMath.canControl(null))
    }

    // ---- isBanned ----

    @Test
    fun isBanned_matchesMembership_andRejectsBlank() {
        val banned = listOf("u_1", "u_2")
        assertTrue(DelegateModMath.isBanned("u_1", banned))
        assertFalse(DelegateModMath.isBanned("u_3", banned))
        assertFalse(DelegateModMath.isBanned("", banned))
        assertFalse(DelegateModMath.isBanned("u_1", emptyList()))
    }

    // ---- moderationLabel ----

    @Test
    fun moderationLabel_mapsKnownTypes_caseInsensitive() {
        assertEquals("Banned a viewer", DelegateModMath.moderationLabel("ban"))
        assertEquals("Muted a viewer", DelegateModMath.moderationLabel("MUTE"))
        assertEquals("Deleted a message", DelegateModMath.moderationLabel("delete_message"))
        assertEquals("Posted an announcement", DelegateModMath.moderationLabel("announcement"))
        assertEquals("Joined as moderator", DelegateModMath.moderationLabel("moderator_register"))
    }

    @Test
    fun moderationLabel_blankOrNull_isActionDefault() {
        assertEquals("Action", DelegateModMath.moderationLabel(null))
        assertEquals("Action", DelegateModMath.moderationLabel("   "))
    }

    @Test
    fun moderationLabel_unknownType_titleCasesEcho() {
        assertEquals("Shadowban", DelegateModMath.moderationLabel("shadowban"))
    }

    // ---- countByType ----

    @Test
    fun countByType_groupsByNormalizedLabel_preservingOrder() {
        val counts = DelegateModMath.countByType(listOf("ban", "MUTE", "ban", "announcement", null))
        assertEquals(1, counts["Muted a viewer"])
        assertEquals(2, counts["Banned a viewer"])
        assertEquals(1, counts["Posted an announcement"])
        assertEquals(1, counts["Action"])
        // insertion order: first-seen label wins the slot
        assertEquals(listOf("Banned a viewer", "Muted a viewer", "Posted an announcement", "Action"), counts.keys.toList())
    }

    @Test
    fun countByType_empty_isEmptyMap() {
        assertTrue(DelegateModMath.countByType(emptyList()).isEmpty())
    }
}
