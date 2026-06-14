package com.testlogon.android.core.model.groups

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-355 - unit tests for the [GroupRole] enum (from() parse + UNKNOWN fallback + canManage + the
 * assignable-role set [no admin]) and the [Group] / [GroupMember] domain helpers. Pure JVM; no Android,
 * no Moshi.
 */
class GroupRoleTest {

    @Test
    fun from_parsesKnownTokens_caseAndWhitespaceInsensitive() {
        assertEquals(GroupRole.ADMIN, GroupRole.from("admin"))
        assertEquals(GroupRole.MODERATOR, GroupRole.from("MODERATOR"))
        assertEquals(GroupRole.MEMBER, GroupRole.from(" member "))
    }

    @Test
    fun from_unknownOrNull_isUnknown_neverThrows() {
        assertEquals(GroupRole.UNKNOWN, GroupRole.from(null))
        assertEquals(GroupRole.UNKNOWN, GroupRole.from(""))
        // there is NO owner role - "owner" is unknown
        assertEquals(GroupRole.UNKNOWN, GroupRole.from("owner"))
        assertEquals(GroupRole.UNKNOWN, GroupRole.from("superadmin"))
    }

    @Test
    fun canManage_trueForAdmin_only() {
        assertTrue(GroupRole.ADMIN.canManage)
        assertFalse(GroupRole.MODERATOR.canManage)
        assertFalse(GroupRole.MEMBER.canManage)
        assertFalse(GroupRole.UNKNOWN.canManage)
    }

    @Test
    fun wire_mapsRoles_unknownHasNoToken() {
        assertEquals("admin", GroupRole.ADMIN.wire)
        assertEquals("moderator", GroupRole.MODERATOR.wire)
        assertEquals("member", GroupRole.MEMBER.wire)
        assertEquals(null, GroupRole.UNKNOWN.wire)
    }

    @Test
    fun assignable_offersModeratorMember_only_neverAdmin() {
        assertEquals(listOf(GroupRole.MODERATOR, GroupRole.MEMBER), GroupRole.ASSIGNABLE)
        assertFalse(GroupRole.ADMIN in GroupRole.ASSIGNABLE)
    }

    @Test
    fun group_canManage_mirrorsRole() {
        val admin = Group(id = "g1", name = "G", myRole = GroupRole.ADMIN)
        val member = Group(id = "g2", name = "G", myRole = GroupRole.MEMBER)
        assertTrue(admin.canManage)
        assertFalse(member.canManage)
    }

    @Test
    fun member_isPending_whenStatusInvited() {
        val pending = GroupMember(userId = "u1", role = GroupRole.MEMBER, status = "invited")
        val active = GroupMember(userId = "u2", role = GroupRole.MEMBER, status = "active")
        assertTrue(pending.isPending)
        assertFalse(active.isPending)
    }
}
