package com.testlogon.android.core.model.delegates

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-359 - pure domain tests for the delegate model.
 *
 * The DTO -> domain mapper (ManagedCreatorOut -> ManagedCreator) lives in the data layer because
 * core-model can not see the core-network DTO; it is covered by DelegateMappersTest there. This test
 * covers the PURE core-model projection [ManagedCreator.toManagingCreator] (creatorId / label /
 * permissions carry-over).
 */
class DelegatesTest {

    @Test
    fun toManagingCreator_carriesCreatorIdLabelAndPermissions() {
        val managed = ManagedCreator(
            creatorId = "cr_1",
            permissions = listOf("read", "post"),
            preset = "editor",
            status = "active",
            label = "Acme Studio",
            acceptedAt = "2026-01-01",
        )

        val managing = managed.toManagingCreator()

        assertEquals("cr_1", managing.creatorId)
        assertEquals("Acme Studio", managing.label)
        assertEquals(listOf("read", "post"), managing.permissions)
    }

    @Test
    fun toManagingCreator_defaultsPermissionsToEmpty_andNullLabel() {
        val managing = ManagedCreator(creatorId = "cr_2").toManagingCreator()
        assertEquals("cr_2", managing.creatorId)
        assertEquals(null, managing.label)
        assertEquals(emptyList<String>(), managing.permissions)
    }
}
