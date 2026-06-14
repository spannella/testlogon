package com.testlogon.android.feature.donation

import com.testlogon.android.core.network.donation.DonationDto
import com.testlogon.android.core.network.donation.DonationReceiptDto
import com.testlogon.android.core.network.donation.PublicFundraiserDto
import com.testlogon.android.feature.donation.model.DonationStatus
import com.testlogon.android.feature.donation.model.FundraiserStatus
import com.testlogon.android.feature.donation.model.toDomain
import com.testlogon.android.feature.donation.model.toReceiptFallback
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-393 - pure mapper tests: status enums tolerate UNKNOWN wire values (never throw); progress is null
 * without a positive goal; the soft-fallback receipt is built from a donation 201.
 */
class DonationMappingTest {

    @Test
    fun fundraiserStatus_unknownValue_tolerated() {
        val dto = PublicFundraiserDto(
            fundraiserId = "f", groupId = "g", groupName = "n", title = "t", status = "weird_status",
        )
        assertEquals(FundraiserStatus.UNKNOWN, dto.toDomain().status)
        assertEquals(false, dto.toDomain().status.isOpen)
    }

    @Test
    fun fundraiserStatus_active_isOpen() {
        val dto = PublicFundraiserDto(
            fundraiserId = "f", groupId = "g", groupName = "n", title = "t", status = "active",
        )
        assertEquals(FundraiserStatus.ACTIVE, dto.toDomain().status)
        assertEquals(true, dto.toDomain().status.isOpen)
    }

    @Test
    fun progress_nullWithoutPositiveGoal_andClampedWithGoal() {
        val noGoal = PublicFundraiserDto(
            fundraiserId = "f", groupId = "g", groupName = "n", title = "t", status = "active",
            goalCents = null, raisedCents = 100L,
        )
        assertNull(noGoal.toDomain().progress)

        val withGoal = PublicFundraiserDto(
            fundraiserId = "f", groupId = "g", groupName = "n", title = "t", status = "active",
            goalCents = 1000L, raisedCents = 250L,
        )
        assertEquals(0.25f, withGoal.toDomain().progress!!, 0.0001f)

        val over = PublicFundraiserDto(
            fundraiserId = "f", groupId = "g", groupName = "n", title = "t", status = "active",
            goalCents = 1000L, raisedCents = 5000L,
        )
        assertEquals(1.0f, over.toDomain().progress!!, 0.0001f)
    }

    @Test
    fun donationStatus_unknownValue_tolerated() {
        val dto = DonationReceiptDto(
            donationId = "d", amountCents = 100L, groupName = "n", fundraiserTitle = "t",
            createdAt = 1L, status = "queued",
        )
        assertEquals(DonationStatus.UNKNOWN, dto.toDomain().status)
    }

    @Test
    fun softFallback_buildsReceiptFromDonation() {
        val donation = DonationDto(
            donationId = "don_1", amountCents = 2500L, status = "pending", createdAt = 99L,
            donorName = "A", isExternal = true, checkoutUrl = null,
        )
        val receipt = donation.toReceiptFallback(
            currency = "usd", groupName = "Grp", fundraiserTitle = "Title",
        )
        assertEquals("don_1", receipt.donationId)
        assertEquals(2500L, receipt.amountCents)
        assertEquals(DonationStatus.PENDING, receipt.status)
        assertEquals("usd", receipt.currency)
        assertEquals("Title", receipt.fundraiserTitle)
    }
}
