package com.testlogon.android.feature.adsbilling

import com.testlogon.android.core.network.ads.AdAccountDto
import com.testlogon.android.core.network.ads.AdAccountStatus
import com.testlogon.android.core.network.ads.AdBillingEntryDto
import com.testlogon.android.core.network.ads.AdDepositOut
import com.testlogon.android.core.network.ads.AdInvoiceCampaignLineDto
import com.testlogon.android.core.network.ads.AdInvoiceDto
import com.testlogon.android.feature.adsbilling.data.toBillingSummary
import com.testlogon.android.feature.adsbilling.data.toDomain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-367 - DTO -> domain mapper tests for the ads-billing surface. Confirms the summary is derived from the
 * account (balance + lifetime spend, cents Long), the ledger row maps entry_type / state / reason (with the
 * AND-363 type / description fallback), the invoice folds null totals to 0 + maps the campaign lines, and the
 * deposit out maps new_balance_cents.
 */
class AdsBillingMappersTest {

    @Test
    fun account_mapsToBillingSummary_withCents() {
        val summary = AdAccountDto(
            accountId = "acc_1",
            name = "Acme Ads",
            status = AdAccountStatus.ACTIVE,
            balanceCents = 150000L,
            lifetimeSpendCents = 9_500_000_000L,
        ).toBillingSummary()

        assertEquals("acc_1", summary.accountId)
        assertEquals("Acme Ads", summary.companyName)
        assertEquals("active", summary.status)
        assertEquals(150000L, summary.balanceCents)
        assertEquals(9_500_000_000L, summary.lifetimeSpendCents)
    }

    @Test
    fun billingEntry_mapsEntryTypeStateReason_epochLong() {
        val entry = AdBillingEntryDto(
            entryType = "charge",
            amountCents = 2500L,
            state = "settled",
            reason = "daily spend",
            createdAt = 1700000000L,
        ).toDomain()

        assertEquals("charge", entry.entryType)
        assertEquals(2500L, entry.amountCents)
        assertEquals("settled", entry.state)
        assertEquals("daily spend", entry.reason)
        assertEquals(1700000000L, entry.createdAt)
    }

    @Test
    fun billingEntry_fallsBackToLegacyTypeAndDescription() {
        val entry = AdBillingEntryDto(
            amountCents = -1000L,
            type = "credit",
            description = "promo credit",
        ).toDomain()

        assertEquals("credit", entry.entryType)
        assertEquals("promo credit", entry.reason)
        assertEquals(-1000L, entry.amountCents)
    }

    @Test
    fun invoice_mapsLines_andFoldsNullTotalsToZero() {
        val invoice = AdInvoiceDto(
            month = "2026-06",
            totalChargesCents = null,
            totalDepositsCents = 100000L,
            entryCount = 2,
            campaigns = listOf(
                AdInvoiceCampaignLineDto(
                    campaignId = "cmp_1",
                    impressions = 12000L,
                    clicks = 340L,
                    conversions = 12L,
                    totalCents = 500000L,
                ),
                AdInvoiceCampaignLineDto(campaignId = "cmp_2"),
            ),
        ).toDomain()

        assertEquals("2026-06", invoice.month)
        assertEquals(0L, invoice.totalChargesCents) // null -> 0
        assertEquals(100000L, invoice.totalDepositsCents)
        assertEquals(2, invoice.entryCount)
        assertEquals(2, invoice.campaigns.size)
        assertEquals(12000L, invoice.campaigns[0].impressions)
        assertEquals(500000L, invoice.campaigns[0].totalCents)
        // sparse line: null counts / total -> 0
        assertEquals(0L, invoice.campaigns[1].impressions)
        assertEquals(0L, invoice.campaigns[1].totalCents)
    }

    @Test
    fun depositOut_mapsNewBalance() {
        assertEquals(155000L, AdDepositOut(newBalanceCents = 155000L).toDomain().newBalanceCents)
        assertNull(AdDepositOut().toDomain().newBalanceCents)
    }
}
