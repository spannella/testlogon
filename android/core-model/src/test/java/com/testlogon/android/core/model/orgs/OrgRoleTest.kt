package com.testlogon.android.core.model.orgs

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-353 - unit tests for the [OrgRole] enum (from() parse + UNKNOWN fallback + isManager + the
 * assignable-role set). Pure JVM; no Android, no Moshi.
 */
class OrgRoleTest {

    @Test
    fun from_parsesKnownTokens_caseAndWhitespaceInsensitive() {
        assertEquals(OrgRole.OWNER, OrgRole.from("owner"))
        assertEquals(OrgRole.ADMIN, OrgRole.from("ADMIN"))
        assertEquals(OrgRole.MEMBER, OrgRole.from(" member "))
        assertEquals(OrgRole.VIEWER, OrgRole.from("Viewer"))
    }

    @Test
    fun from_unknownOrNull_isUnknown_neverThrows() {
        assertEquals(OrgRole.UNKNOWN, OrgRole.from(null))
        assertEquals(OrgRole.UNKNOWN, OrgRole.from(""))
        assertEquals(OrgRole.UNKNOWN, OrgRole.from("superadmin"))
    }

    @Test
    fun isManager_trueForOwnerAndAdmin_only() {
        assertTrue(OrgRole.OWNER.isManager)
        assertTrue(OrgRole.ADMIN.isManager)
        assertFalse(OrgRole.MEMBER.isManager)
        assertFalse(OrgRole.VIEWER.isManager)
        assertFalse(OrgRole.UNKNOWN.isManager)
    }

    @Test
    fun wire_mapsRoles_unknownHasNoToken() {
        assertEquals("owner", OrgRole.OWNER.wire)
        assertEquals("admin", OrgRole.ADMIN.wire)
        assertEquals("member", OrgRole.MEMBER.wire)
        assertEquals("viewer", OrgRole.VIEWER.wire)
        assertEquals(null, OrgRole.UNKNOWN.wire)
    }

    @Test
    fun assignable_offersAdminMemberViewer_only_neverOwner() {
        assertEquals(listOf(OrgRole.ADMIN, OrgRole.MEMBER, OrgRole.VIEWER), OrgRole.ASSIGNABLE)
        assertFalse(OrgRole.OWNER in OrgRole.ASSIGNABLE)
    }
}
