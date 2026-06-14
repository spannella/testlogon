package com.testlogon.android.data.billing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-248/250 — unit tests for the admin billing-config DTO -> domain mapper: known payout schedules,
 * the open-string UNKNOWN(raw) fallback, null updated_at/updated_by preservation, and missing
 * supported_currencies -> empty list. Mapping is total (no throws).
 */
class AdminBillingConfigMapperTest {

    private fun dto(
        payoutSchedule: String = "weekly",
        updatedAt: Long? = 1_717_200_000L,
        updatedBy: String? = "root|abc123",
        supportedCurrencies: List<String> = listOf("USD", "EUR"),
    ) = AdminBillingConfigDto(
        feeTipsBps = 250,
        feeUnlocksBps = 250,
        feeSubscriptionsBps = 1500,
        feeCatalogBps = 1000,
        feeAdRevenueBps = 3000,
        minPayoutCents = 5000,
        payoutFeeCents = 25,
        payoutSchedule = payoutSchedule,
        autoPayoutEnabled = true,
        minDepositCents = 500,
        maxDepositCents = 1_000_000,
        depositFeeBps = 290,
        defaultCurrency = "USD",
        supportedCurrencies = supportedCurrencies,
        taxEnabled = false,
        defaultTaxRateBps = 0,
        updatedAt = updatedAt,
        updatedBy = updatedBy,
    )

    @Test
    fun toDomain_mapsAllScalarFields() {
        val c = dto().toDomain()
        assertEquals(250, c.feeTipsBps)
        assertEquals(5000L, c.minPayoutCents)
        assertEquals(25L, c.payoutFeeCents)
        assertEquals(PayoutSchedule.Weekly, c.payoutSchedule)
        assertTrue(c.autoPayoutEnabled)
        assertEquals(290, c.depositFeeBps)
        assertEquals("USD", c.defaultCurrency)
        assertEquals(listOf("USD", "EUR"), c.supportedCurrencies)
        assertEquals(1_717_200_000L, c.updatedAtEpochSeconds)
        assertEquals("root|abc123", c.updatedBy)
    }

    @Test
    fun toDomain_knownSchedules_mapCorrectly() {
        assertEquals(PayoutSchedule.Daily, dto(payoutSchedule = "daily").toDomain().payoutSchedule)
        assertEquals(PayoutSchedule.Weekly, dto(payoutSchedule = "weekly").toDomain().payoutSchedule)
        assertEquals(PayoutSchedule.Monthly, dto(payoutSchedule = "monthly").toDomain().payoutSchedule)
    }

    @Test
    fun toDomain_unknownSchedule_keepsRaw() {
        val schedule = dto(payoutSchedule = "fortnightly").toDomain().payoutSchedule
        assertTrue(schedule is PayoutSchedule.Unknown)
        assertEquals("fortnightly", (schedule as PayoutSchedule.Unknown).raw)
    }

    @Test
    fun toDomain_nullAndMissingOptionals_preserved() {
        val c = dto(updatedAt = null, updatedBy = null, supportedCurrencies = emptyList()).toDomain()
        assertNull(c.updatedAtEpochSeconds)
        assertNull(c.updatedBy)
        assertTrue(c.supportedCurrencies.isEmpty())
    }
}
