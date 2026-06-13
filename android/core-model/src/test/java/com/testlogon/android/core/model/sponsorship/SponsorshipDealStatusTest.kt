package com.testlogon.android.core.model.sponsorship

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-365 - tests for [SponsorshipDealStatus]: the verified wire tokens parse to the right member, an
 * unrecognized / null token falls back to UNKNOWN (never throws), and [SponsorshipDealStatus.group] buckets
 * each status into the four client-side filter groups the web client uses (UNKNOWN -> PENDING so a
 * forward-compat status still surfaces in the default-visible bucket).
 */
class SponsorshipDealStatusTest {

    @Test
    fun from_parsesEveryVerifiedWireToken() {
        assertEquals(SponsorshipDealStatus.PROPOSED, SponsorshipDealStatus.from("proposed"))
        assertEquals(SponsorshipDealStatus.NEGOTIATING, SponsorshipDealStatus.from("negotiating"))
        assertEquals(SponsorshipDealStatus.ACCEPTED, SponsorshipDealStatus.from("accepted"))
        assertEquals(
            SponsorshipDealStatus.CONTENT_SUBMITTED,
            SponsorshipDealStatus.from("content_submitted"),
        )
        assertEquals(SponsorshipDealStatus.COMPLETED, SponsorshipDealStatus.from("completed"))
        assertEquals(SponsorshipDealStatus.REJECTED, SponsorshipDealStatus.from("rejected"))
        assertEquals(SponsorshipDealStatus.CANCELLED, SponsorshipDealStatus.from("cancelled"))
    }

    @Test
    fun from_isCaseAndWhitespaceInsensitive_andAcceptsCanceledSpelling() {
        assertEquals(SponsorshipDealStatus.PROPOSED, SponsorshipDealStatus.from(" Proposed "))
        assertEquals(SponsorshipDealStatus.CANCELLED, SponsorshipDealStatus.from("canceled"))
    }

    @Test
    fun from_unknownOrNull_fallsBackToUnknown() {
        assertEquals(SponsorshipDealStatus.UNKNOWN, SponsorshipDealStatus.from("teleported"))
        assertEquals(SponsorshipDealStatus.UNKNOWN, SponsorshipDealStatus.from(null))
        assertEquals(SponsorshipDealStatus.UNKNOWN, SponsorshipDealStatus.from(""))
    }

    @Test
    fun group_bucketsStatusesIntoTheFourWebGroups() {
        assertEquals(SponsorshipDealGroup.PENDING, SponsorshipDealStatus.PROPOSED.group)
        assertEquals(SponsorshipDealGroup.PENDING, SponsorshipDealStatus.NEGOTIATING.group)
        assertEquals(SponsorshipDealGroup.ACTIVE, SponsorshipDealStatus.ACCEPTED.group)
        assertEquals(SponsorshipDealGroup.ACTIVE, SponsorshipDealStatus.CONTENT_SUBMITTED.group)
        assertEquals(SponsorshipDealGroup.COMPLETED, SponsorshipDealStatus.COMPLETED.group)
        assertEquals(SponsorshipDealGroup.CANCELLED, SponsorshipDealStatus.REJECTED.group)
        assertEquals(SponsorshipDealGroup.CANCELLED, SponsorshipDealStatus.CANCELLED.group)
    }

    @Test
    fun group_unknownFallsIntoPending_soItIsNeverHidden() {
        assertEquals(SponsorshipDealGroup.PENDING, SponsorshipDealStatus.UNKNOWN.group)
    }
}
