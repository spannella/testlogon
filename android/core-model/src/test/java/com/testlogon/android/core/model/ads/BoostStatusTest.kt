package com.testlogon.android.core.model.ads

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-364 - unit tests for [BoostStatus] (the typed, forward-compat parse of the free-form wire status).
 *
 * The DTO -> domain mapper lives in the :app feature (it bridges core-network DTOs), so the mapper's
 * raw-status-retention + cents-mapping behavior is asserted there (BoostMappersTest); these core-model
 * tests pin the pure enum contract: recognized tokens map, anything unrecognized / null falls back to
 * UNKNOWN (never throws), and only ACTIVE is "active".
 */
class BoostStatusTest {

    @Test
    fun from_recognizedTokens_map() {
        assertEquals(BoostStatus.ACTIVE, BoostStatus.from("active"))
        assertEquals(BoostStatus.PENDING, BoostStatus.from("pending"))
        assertEquals(BoostStatus.UNDER_REVIEW, BoostStatus.from("under_review"))
        assertEquals(BoostStatus.REJECTED, BoostStatus.from("rejected"))
        assertEquals(BoostStatus.COMPLETED, BoostStatus.from("completed"))
        assertEquals(BoostStatus.CANCELLED, BoostStatus.from("cancelled"))
        // US spelling tolerated.
        assertEquals(BoostStatus.CANCELLED, BoostStatus.from("canceled"))
    }

    @Test
    fun from_isCaseAndWhitespaceInsensitive() {
        assertEquals(BoostStatus.ACTIVE, BoostStatus.from("  ACTIVE "))
    }

    @Test
    fun from_unknownOrNull_fallsBackToUnknown_neverThrows() {
        assertEquals(BoostStatus.UNKNOWN, BoostStatus.from("awaiting_wizard_approval"))
        assertEquals(BoostStatus.UNKNOWN, BoostStatus.from(null))
        assertEquals(BoostStatus.UNKNOWN, BoostStatus.from(""))
    }

    @Test
    fun isActive_trueOnlyForActive() {
        assertTrue(BoostStatus.ACTIVE.isActive)
        assertFalse(BoostStatus.PENDING.isActive)
        assertFalse(BoostStatus.COMPLETED.isActive)
        assertFalse(BoostStatus.UNKNOWN.isActive)
    }
}
