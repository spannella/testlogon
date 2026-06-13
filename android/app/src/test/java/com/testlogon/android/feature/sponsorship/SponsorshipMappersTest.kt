package com.testlogon.android.feature.sponsorship

import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.network.sponsorship.SponsorshipDealDetailDto
import com.testlogon.android.core.network.sponsorship.SponsorshipDealEventDto
import com.testlogon.android.feature.sponsorship.data.toDomain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-366 - tests for the detail / event DTO -> domain mappers: the full deal keeps raw + typed status, a null
 * deliverables array maps to an empty list, payment_details collapses to a presence flag, and the OPAQUE event
 * `details` flattens from a String / Map / null into a single display string.
 */
class SponsorshipMappersTest {

    @Test
    fun detail_mapsAllFields_nullDeliverablesToEmpty_paymentToFlag() {
        val dto = SponsorshipDealDetailDto(
            dealId = "d1",
            advertiserSub = "adv_1",
            creatorSub = "cre_1",
            brief = "Promote",
            status = "negotiating",
            compensationCents = 250000L,
            deliverables = null,
            deadline = "2026-07-01",
            cpmBonusCents = 500L,
            platformCommissionBps = 1000,
            paymentDetails = null,
        )

        val deal = dto.toDomain()
        assertEquals("d1", deal.dealId)
        assertEquals("negotiating", deal.status)
        assertEquals(SponsorshipDealStatus.NEGOTIATING, deal.statusEnum)
        assertTrue(deal.deliverables.isEmpty())
        assertFalse(deal.hasPaymentDetails)
    }

    @Test
    fun detail_paymentDetailsPresent_setsFlag() {
        val dto = SponsorshipDealDetailDto(dealId = "d1", paymentDetails = mapOf("method" to "wallet"))
        assertTrue(dto.toDomain().hasPaymentDetails)
    }

    @Test
    fun event_flattensStringDetails() {
        val dto = SponsorshipDealEventDto(eventId = "e1", eventType = "note", details = "reconsider please")
        val event = dto.toDomain()
        assertEquals("e1", event.eventId)
        assertEquals("reconsider please", event.detailsText)
    }

    @Test
    fun event_flattensMapDetails() {
        val dto = SponsorshipDealEventDto(
            eventId = "e1",
            details = linkedMapOf("compensation_cents" to 300000, "note" to "more"),
        )
        assertEquals("compensation_cents: 300000, note: more", dto.toDomain().detailsText)
    }

    @Test
    fun event_nullOrBlankDetails_isNull() {
        assertNull(SponsorshipDealEventDto(eventId = "e1", details = null).toDomain().detailsText)
        assertNull(SponsorshipDealEventDto(eventId = "e2", details = "   ").toDomain().detailsText)
    }
}
