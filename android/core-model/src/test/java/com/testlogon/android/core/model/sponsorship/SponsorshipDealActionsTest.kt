package com.testlogon.android.core.model.sponsorship

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-366 - tests for the CLIENT-SIDE management gating: [availableActions] is non-empty ONLY in the
 * actionable statuses (proposed / negotiating) for a party (advertiser / creator), every terminal status (and
 * UNKNOWN) yields the empty set, an OBSERVER never gets actions, and [ViewerRole.derive] maps the current sub
 * to the right party. Also covers [SponsorshipDealStatus.isTerminal].
 */
class SponsorshipDealActionsTest {

    private val fullSet = setOf(DealAction.ACCEPT, DealAction.REJECT, DealAction.NEGOTIATE)

    @Test
    fun availableActions_proposedAndNegotiating_offerAllThree_forBothParties() {
        for (role in listOf(ViewerRole.ADVERTISER, ViewerRole.CREATOR)) {
            assertEquals(fullSet, availableActions(SponsorshipDealStatus.PROPOSED, role))
            assertEquals(fullSet, availableActions(SponsorshipDealStatus.NEGOTIATING, role))
        }
    }

    @Test
    fun availableActions_terminalStatuses_offerNone() {
        val terminal = listOf(
            SponsorshipDealStatus.ACCEPTED,
            SponsorshipDealStatus.CONTENT_SUBMITTED,
            SponsorshipDealStatus.COMPLETED,
            SponsorshipDealStatus.REJECTED,
            SponsorshipDealStatus.CANCELLED,
            SponsorshipDealStatus.UNKNOWN,
        )
        for (status in terminal) {
            assertTrue(availableActions(status, ViewerRole.ADVERTISER).isEmpty())
            assertTrue(availableActions(status, ViewerRole.CREATOR).isEmpty())
        }
    }

    @Test
    fun availableActions_observer_neverGetsActions() {
        assertTrue(availableActions(SponsorshipDealStatus.PROPOSED, ViewerRole.OBSERVER).isEmpty())
        assertTrue(availableActions(SponsorshipDealStatus.NEGOTIATING, ViewerRole.OBSERVER).isEmpty())
    }

    @Test
    fun viewerRole_derivesFromCurrentSub() {
        assertEquals(
            ViewerRole.ADVERTISER,
            ViewerRole.derive(currentSub = "adv_1", advertiserSub = "adv_1", creatorSub = "cre_1"),
        )
        assertEquals(
            ViewerRole.CREATOR,
            ViewerRole.derive(currentSub = "cre_1", advertiserSub = "adv_1", creatorSub = "cre_1"),
        )
        assertEquals(
            ViewerRole.OBSERVER,
            ViewerRole.derive(currentSub = "someone_else", advertiserSub = "adv_1", creatorSub = "cre_1"),
        )
    }

    @Test
    fun viewerRole_blankOrNullCurrentSub_isObserver() {
        assertEquals(ViewerRole.OBSERVER, ViewerRole.derive(null, "adv_1", "cre_1"))
        assertEquals(ViewerRole.OBSERVER, ViewerRole.derive("   ", "adv_1", "cre_1"))
    }

    @Test
    fun isTerminal_trueForEverythingButProposedAndNegotiating() {
        assertFalse(SponsorshipDealStatus.PROPOSED.isTerminal)
        assertFalse(SponsorshipDealStatus.NEGOTIATING.isTerminal)
        assertTrue(SponsorshipDealStatus.ACCEPTED.isTerminal)
        assertTrue(SponsorshipDealStatus.COMPLETED.isTerminal)
        assertTrue(SponsorshipDealStatus.REJECTED.isTerminal)
        assertTrue(SponsorshipDealStatus.CANCELLED.isTerminal)
        assertTrue(SponsorshipDealStatus.UNKNOWN.isTerminal)
    }
}
