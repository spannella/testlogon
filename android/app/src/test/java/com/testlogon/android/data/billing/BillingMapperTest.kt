package com.testlogon.android.data.billing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** AND-223 — pure mapper tests: total mapping, ISO-8601 epoch parsing, enum + brand fallbacks. */
class BillingMapperTest {

    @Test
    fun iso8601_parsesUtcZ() {
        // 2026-07-01T00:00:00Z == 1782864000
        assertEquals(1782864000L, "2026-07-01T00:00:00Z".toEpochSecondsOrNull())
        // epoch start
        assertEquals(0L, "1970-01-01T00:00:00Z".toEpochSecondsOrNull())
        // a known instant: 2021-05-01T00:00:00Z == 1619827200
        assertEquals(1619827200L, "2021-05-01T00:00:00Z".toEpochSecondsOrNull())
    }

    @Test
    fun iso8601_appliesOffset() {
        // 2026-07-01T00:00:00+02:00 == 2026-06-30T22:00:00Z == 1782856800
        assertEquals(1782856800L, "2026-07-01T00:00:00+02:00".toEpochSecondsOrNull())
        // -05:00 offset adds 5h to the UTC base
        assertEquals(1782864000L + 5 * 3600, "2026-07-01T00:00:00-05:00".toEpochSecondsOrNull())
    }

    @Test
    fun iso8601_toleratesFractionAndCompactOffset() {
        assertEquals(1782864000L, "2026-07-01T00:00:00.123Z".toEpochSecondsOrNull())
        assertEquals(1782864000L, "2026-07-01T00:00:00+0000".toEpochSecondsOrNull())
    }

    @Test
    fun iso8601_malformed_returnsNull() {
        assertNull("not a date".toEpochSecondsOrNull())
        assertNull("".toEpochSecondsOrNull())
        assertNull(null.toEpochSecondsOrNull())
        assertNull("2026-13-01T00:00:00Z".toEpochSecondsOrNull()) // month 13
    }

    @Test
    fun subscription_unknownStatus_mapsToUnknown_andBadDateNull() {
        val dto = SubscriptionDto(
            subscriptionId = "s",
            planId = "p",
            status = "frobnicated",
            billingCycle = "yearly",
            nextBillingDate = "garbage",
        )
        val domain = dto.toDomain()
        assertEquals(SubscriptionStatus.UNKNOWN, domain.status)
        assertNull(domain.nextBillingDateEpochSeconds)
        assertEquals("yearly", domain.billingCycle)
    }

    @Test
    fun paymentMethod_mapsId_brand_andDefault() {
        val dto = PaymentMethodDto(
            paymentMethodId = "pm_1",
            methodType = "card",
            label = "Personal Visa",
            brand = "Visa",
            last4 = "4242",
            expMonth = 12,
            expYear = 2027,
            priority = 0,
            provider = "stripe",
            providerMethodId = "pm_stripe",
            isDefault = true,
        )
        val domain = dto.toDomain()
        assertEquals("pm_1", domain.id)
        assertEquals(CardBrand.VISA, domain.brand)
        assertEquals("Visa", domain.rawBrand)
        assertEquals("4242", domain.last4)
        assertEquals(true, domain.isDefault)
    }

    @Test
    fun paymentMethod_bankAccount_hasNoBrandOrCardFields() {
        val dto = PaymentMethodDto(
            paymentMethodId = "pm_bank",
            methodType = "us_bank_account",
            priority = 1,
            isDefault = false,
        )
        val domain = dto.toDomain()
        assertEquals(CardBrand.UNKNOWN, domain.brand)
        assertNull(domain.last4)
        assertNull(domain.expMonth)
        assertNull(domain.rawBrand)
    }

    @Test
    fun ledgerEntry_zeroTs_mapsToNull() {
        val dto = LedgerEntryDto(sk = "L#1", type = "charge", amountCents = 100, state = "settled", ts = 0)
        val domain = dto.toDomain("USD")
        assertNull(domain.timestampEpochSeconds)
        assertEquals(100L, domain.amount.cents)
        assertEquals("USD", domain.amount.currency)
    }
}
