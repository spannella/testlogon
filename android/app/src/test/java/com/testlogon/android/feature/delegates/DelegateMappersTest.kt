package com.testlogon.android.feature.delegates

import com.testlogon.android.core.network.delegates.ManagedCreatorOut
import com.testlogon.android.feature.delegates.data.toDomain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-359 - tests for the DTO -> domain mapper (ManagedCreatorOut -> ManagedCreator). The mapper lives in
 * the feature data layer (core-model can not see the core-network DTO); the pure toManagingCreator
 * projection is covered separately by the core-model DelegatesTest.
 */
class DelegateMappersTest {

    @Test
    fun managedCreatorOut_toDomain_carriesAllFields() {
        val dto = ManagedCreatorOut(
            creatorId = "cr_1",
            permissions = listOf("read", "post"),
            preset = "editor",
            status = "active",
            label = "Acme Studio",
            acceptedAt = "2026-01-01",
        )

        val domain = dto.toDomain()

        assertEquals("cr_1", domain.creatorId)
        assertEquals(listOf("read", "post"), domain.permissions)
        assertEquals("editor", domain.preset)
        assertEquals("active", domain.status)
        assertEquals("Acme Studio", domain.label)
        assertEquals("2026-01-01", domain.acceptedAt)
    }

    @Test
    fun managedCreatorOut_toDomain_sparseRow_defaultsEmptyPermissionsAndNullOptionals() {
        val domain = ManagedCreatorOut(creatorId = "cr_2").toDomain()
        assertEquals("cr_2", domain.creatorId)
        assertEquals(emptyList<String>(), domain.permissions)
        assertNull(domain.preset)
        assertNull(domain.status)
        assertNull(domain.label)
        assertNull(domain.acceptedAt)
    }
}
