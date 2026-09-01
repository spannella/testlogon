package com.testlogon.android.core.model.syndicates

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure JVM unit tests for [SyndicateMath] (the syndicate MANAGEMENT logic: plan validation, price parsing,
 * subscribe/invite/admin eligibility, status + audit labelling). No Android / network dependency.
 */
class SyndicateMathTest {

    // ---- validatePlanDraft ----

    @Test
    fun `valid plan draft has no errors`() {
        val errors = SyndicateMath.validatePlanDraft(name = "Gold Tier", priceCents = 999, interval = "month")
        assertTrue(errors.isEmpty())
        assertTrue(SyndicateMath.isPlanDraftValid("Gold Tier", 999, "month"))
    }

    @Test
    fun `plan name too short flags NAME`() {
        val errors = SyndicateMath.validatePlanDraft(name = "A", priceCents = 999, interval = "month")
        assertEquals(1, errors.size)
        assertEquals(PlanField.NAME, errors.first().field)
    }

    @Test
    fun `plan name is trimmed before length check`() {
        // "  A  " trims to a single char -> too short.
        assertFalse(SyndicateMath.isPlanDraftValid("  A  ", 999, "month"))
        // A 2-char name padded with spaces is still valid.
        assertTrue(SyndicateMath.isPlanDraftValid("  Ab  ", 999, "month"))
    }

    @Test
    fun `plan price below floor flags PRICE`() {
        val errors = SyndicateMath.validatePlanDraft("Tier", priceCents = 99, interval = "month")
        assertEquals(PlanField.PRICE, errors.single().field)
    }

    @Test
    fun `plan price above ceiling flags PRICE`() {
        val errors = SyndicateMath.validatePlanDraft("Tier", priceCents = 100_001, interval = "month")
        assertEquals(PlanField.PRICE, errors.single().field)
    }

    @Test
    fun `plan boundary prices are accepted`() {
        assertTrue(SyndicateMath.isPlanDraftValid("Tier", 100, "month"))
        assertTrue(SyndicateMath.isPlanDraftValid("Tier", 100_000, "year"))
    }

    @Test
    fun `invalid interval flags INTERVAL`() {
        val errors = SyndicateMath.validatePlanDraft("Tier", 999, interval = "week")
        assertEquals(PlanField.INTERVAL, errors.single().field)
    }

    @Test
    fun `overlong description flags DESCRIPTION`() {
        val longDesc = "x".repeat(SyndicateMath.PLAN_DESC_MAX + 1)
        val errors = SyndicateMath.validatePlanDraft("Tier", 999, "month", description = longDesc)
        assertEquals(PlanField.DESCRIPTION, errors.single().field)
    }

    @Test
    fun `multiple violations are all reported in order`() {
        val errors = SyndicateMath.validatePlanDraft(name = "A", priceCents = 5, interval = "week")
        assertEquals(listOf(PlanField.NAME, PlanField.PRICE, PlanField.INTERVAL), errors.map { it.field })
    }

    // ---- parsePriceToCents ----

    @Test
    fun `parsePriceToCents handles dollar signs commas and decimals`() {
        assertEquals(1250, SyndicateMath.parsePriceToCents("$12.50"))
        assertEquals(1250, SyndicateMath.parsePriceToCents("12.5"))
        assertEquals(900, SyndicateMath.parsePriceToCents("  9 "))
        assertEquals(123456, SyndicateMath.parsePriceToCents("$1,234.56"))
    }

    @Test
    fun `parsePriceToCents rounds half cents and rejects junk`() {
        assertEquals(1000, SyndicateMath.parsePriceToCents("9.999")) // rounds up to $10.00
        assertNull(SyndicateMath.parsePriceToCents(""))
        assertNull(SyndicateMath.parsePriceToCents("abc"))
        assertNull(SyndicateMath.parsePriceToCents("-5"))
    }

    // ---- formatCents / priceLabel ----

    @Test
    fun `formatCents pads and signs`() {
        assertEquals("$9.99", SyndicateMath.formatCents(999))
        assertEquals("$0.05", SyndicateMath.formatCents(5))
        assertEquals("$10.00", SyndicateMath.formatCents(1000))
        assertEquals("-$1.50", SyndicateMath.formatCents(-150))
    }

    @Test
    fun `priceLabel abbreviates interval`() {
        assertEquals("$9.99 / mo", SyndicateMath.priceLabel(999, "month"))
        assertEquals("$99.00 / yr", SyndicateMath.priceLabel(9900, "year"))
        assertEquals("$5.00 / week", SyndicateMath.priceLabel(500, "week"))
    }

    // ---- canSubscribe ----

    @Test
    fun `canSubscribe blocks duplicate active subscription`() {
        assertTrue(SyndicateMath.canSubscribe("plan_1", activePlanIds = setOf("plan_2")))
        assertFalse(SyndicateMath.canSubscribe("plan_1", activePlanIds = setOf("plan_1")))
        assertFalse(SyndicateMath.canSubscribe("", activePlanIds = emptySet()))
    }

    // ---- canInvite ----

    @Test
    fun `canInvite excludes members and pending invitees`() {
        assertTrue(SyndicateMath.canInvite("u3", memberIds = setOf("u1"), pendingInviteeIds = setOf("u2")))
        assertFalse(SyndicateMath.canInvite("u1", memberIds = setOf("u1"), pendingInviteeIds = emptySet()))
        assertFalse(SyndicateMath.canInvite("u2", memberIds = emptySet(), pendingInviteeIds = setOf("u2")))
        assertFalse(SyndicateMath.canInvite("", memberIds = emptySet(), pendingInviteeIds = emptySet()))
    }

    // ---- isAdmin / canTransferAdmin ----

    @Test
    fun `isAdmin is fail-closed on blank`() {
        assertTrue(SyndicateMath.isAdmin("u1", "u1"))
        assertFalse(SyndicateMath.isAdmin("u1", "u2"))
        assertFalse(SyndicateMath.isAdmin(null, "u1"))
        assertFalse(SyndicateMath.isAdmin("", "u1"))
        assertFalse(SyndicateMath.isAdmin("u1", null))
    }

    @Test
    fun `canTransferAdmin requires a different existing member`() {
        val members = setOf("u1", "u2")
        assertTrue(SyndicateMath.canTransferAdmin("u2", currentAdminUserId = "u1", memberIds = members))
        assertFalse(SyndicateMath.canTransferAdmin("u1", currentAdminUserId = "u1", memberIds = members))
        assertFalse(SyndicateMath.canTransferAdmin("u9", currentAdminUserId = "u1", memberIds = members))
        assertFalse(SyndicateMath.canTransferAdmin("", currentAdminUserId = "u1", memberIds = members))
    }

    // ---- membershipStatus ----

    @Test
    fun `membershipStatus maps synonyms and falls back to UNKNOWN`() {
        assertEquals(MembershipStatus.PENDING, SyndicateMath.membershipStatus("pending"))
        assertEquals(MembershipStatus.ACCEPTED, SyndicateMath.membershipStatus("approved"))
        assertEquals(MembershipStatus.ACCEPTED, SyndicateMath.membershipStatus("ACTIVE"))
        assertEquals(MembershipStatus.REJECTED, SyndicateMath.membershipStatus("declined"))
        assertEquals(MembershipStatus.UNKNOWN, SyndicateMath.membershipStatus(null))
        assertEquals(MembershipStatus.UNKNOWN, SyndicateMath.membershipStatus("weird"))
    }

    // ---- auditActionLabel ----

    @Test
    fun `auditActionLabel title-cases snake_case tokens`() {
        assertEquals("Invite Member", SyndicateMath.auditActionLabel("invite_member"))
        assertEquals("Transfer Admin", SyndicateMath.auditActionLabel("transfer_admin"))
        assertEquals("Activity", SyndicateMath.auditActionLabel(""))
        assertEquals("Activity", SyndicateMath.auditActionLabel(null))
    }
}
