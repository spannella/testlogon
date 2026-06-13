package com.testlogon.android.feature.boost

import com.testlogon.android.core.model.ads.BoostStatus
import com.testlogon.android.core.network.ads.ContentBoostCancelOut
import com.testlogon.android.core.network.ads.ContentBoostOut
import com.testlogon.android.core.network.ads.ContentBoostSpendOut
import com.testlogon.android.feature.boost.data.toDomain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-364 - DTO -> domain mapper tests. Confirms the mapper keeps the RAW wire status, derives the typed
 * BoostStatus (UNKNOWN fallback for unrecognized tokens), and maps the *_cents Longs + epoch ends_at.
 */
class BoostMappersTest {

    @Test
    fun boostOut_mapsToDomain_keepsRawStatus_andEnum() {
        val domain = ContentBoostOut(
            boostId = "bst_1",
            status = "active",
            contentType = "post",
            contentId = "post_9",
            budgetCents = 500L,
            spentCents = 100L,
            remainingCents = 400L,
            durationSeconds = 3600L,
            endsAt = 1700003600L,
            createdAt = 1700000000L,
        ).toDomain()

        assertEquals("bst_1", domain.boostId)
        assertEquals("active", domain.status)
        assertEquals(BoostStatus.ACTIVE, domain.statusEnum)
        assertEquals(500L, domain.budgetCents)
        assertEquals(100L, domain.spentCents)
        assertEquals(400L, domain.remainingCents)
        assertEquals(3600L, domain.durationSeconds)
        assertEquals(1700003600L, domain.endsAt)
    }

    @Test
    fun boostOut_unknownStatus_keptRaw_enumUnknown() {
        val domain = ContentBoostOut(
            boostId = "bst_2",
            status = "awaiting_wizard_approval",
            budgetCents = 1000L,
        ).toDomain()

        assertEquals("awaiting_wizard_approval", domain.status)
        assertEquals(BoostStatus.UNKNOWN, domain.statusEnum)
        assertNull(domain.spentCents)
    }

    @Test
    fun spendOut_mapsToDomain() {
        val spend = ContentBoostSpendOut(spentCents = 250L, remainingCents = 250L).toDomain()
        assertEquals(250L, spend.spentCents)
        assertEquals(250L, spend.remainingCents)
    }

    @Test
    fun cancelOut_mapsToDomain_withRefund() {
        val cancel = ContentBoostCancelOut(
            boostId = "bst_1",
            status = "cancelled",
            refundedCents = 250L,
        ).toDomain()
        assertEquals("bst_1", cancel.boostId)
        assertEquals("cancelled", cancel.status)
        assertEquals(250L, cancel.refundedCents)
    }
}
