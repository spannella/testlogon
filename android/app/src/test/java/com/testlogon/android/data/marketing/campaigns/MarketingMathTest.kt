package com.testlogon.android.data.marketing.campaigns

import com.testlogon.android.data.marketing.campaigns.MarketingMath.CampaignObjective
import com.testlogon.android.data.marketing.campaigns.MarketingMath.CampaignStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [MarketingMath] — the campaign state machine + display formatters. These pin the
 * transition table to the backend `_CAMPAIGN_TRANSITIONS` and lock the money/size formatting.
 */
class MarketingMathTest {

    // ---- status parsing ----

    @Test
    fun status_from_parsesKnownAndUnknown() {
        assertEquals(CampaignStatus.DRAFT, CampaignStatus.from("draft"))
        assertEquals(CampaignStatus.ACTIVE, CampaignStatus.from("ACTIVE"))
        assertEquals(CampaignStatus.ARCHIVED, CampaignStatus.from("archived"))
        assertEquals(CampaignStatus.UNKNOWN, CampaignStatus.from("weird"))
        assertEquals(CampaignStatus.UNKNOWN, CampaignStatus.from(null))
    }

    // ---- transitions mirror the backend state machine ----

    @Test
    fun transitions_draft() {
        assertEquals(
            listOf(CampaignStatus.SCHEDULED, CampaignStatus.ACTIVE, CampaignStatus.ARCHIVED),
            MarketingMath.allowedTransitions(CampaignStatus.DRAFT),
        )
    }

    @Test
    fun transitions_scheduled() {
        assertEquals(
            listOf(CampaignStatus.ACTIVE, CampaignStatus.ARCHIVED),
            MarketingMath.allowedTransitions(CampaignStatus.SCHEDULED),
        )
    }

    @Test
    fun transitions_active() {
        assertEquals(
            listOf(CampaignStatus.PAUSED, CampaignStatus.COMPLETED, CampaignStatus.ARCHIVED),
            MarketingMath.allowedTransitions(CampaignStatus.ACTIVE),
        )
    }

    @Test
    fun transitions_paused_and_completed() {
        assertEquals(
            listOf(CampaignStatus.ACTIVE, CampaignStatus.ARCHIVED),
            MarketingMath.allowedTransitions(CampaignStatus.PAUSED),
        )
        assertEquals(
            listOf(CampaignStatus.ARCHIVED),
            MarketingMath.allowedTransitions(CampaignStatus.COMPLETED),
        )
    }

    @Test
    fun transitions_archivedIsTerminal() {
        assertTrue(MarketingMath.allowedTransitions(CampaignStatus.ARCHIVED).isEmpty())
        assertTrue(MarketingMath.isTerminal(CampaignStatus.ARCHIVED))
        assertFalse(MarketingMath.isTerminal(CampaignStatus.DRAFT))
    }

    @Test
    fun canTransition_rejectsIllegalHops() {
        assertTrue(MarketingMath.canTransition(CampaignStatus.DRAFT, CampaignStatus.ACTIVE))
        // completed -> active is NOT allowed
        assertFalse(MarketingMath.canTransition(CampaignStatus.COMPLETED, CampaignStatus.ACTIVE))
        // draft -> paused is NOT allowed
        assertFalse(MarketingMath.canTransition(CampaignStatus.DRAFT, CampaignStatus.PAUSED))
        // unknown -> anything is not allowed
        assertFalse(MarketingMath.canTransition(CampaignStatus.UNKNOWN, CampaignStatus.ACTIVE))
    }

    @Test
    fun canSend_onlyActive() {
        assertTrue(MarketingMath.canSend(CampaignStatus.ACTIVE))
        assertFalse(MarketingMath.canSend(CampaignStatus.DRAFT))
        assertFalse(MarketingMath.canSend(CampaignStatus.PAUSED))
    }

    // ---- objective ----

    @Test
    fun objective_parsesAndListsAll() {
        assertEquals(CampaignObjective.CONVERSIONS, CampaignObjective.from("conversions"))
        assertNull(CampaignObjective.from("nope"))
        assertEquals(4, CampaignObjective.ALL.size)
    }

    // ---- budget formatting ----

    @Test
    fun formatBudget_variousMagnitudes() {
        assertEquals("$0.00", MarketingMath.formatBudget(0))
        assertEquals("$1.00", MarketingMath.formatBudget(100))
        assertEquals("$1.05", MarketingMath.formatBudget(105))
        assertEquals("$1,500.00", MarketingMath.formatBudget(150_000))
        assertEquals("$1,234,567.89", MarketingMath.formatBudget(123_456_789))
        assertEquals("-$1.00", MarketingMath.formatBudget(-100))
    }

    @Test
    fun parseBudgetToCents_validAndInvalid() {
        assertEquals(150_000L, MarketingMath.parseBudgetToCents("1500"))
        assertEquals(150_050L, MarketingMath.parseBudgetToCents("1,500.50"))
        assertEquals(2_500L, MarketingMath.parseBudgetToCents("$25"))
        assertEquals(0L, MarketingMath.parseBudgetToCents("0"))
        assertNull(MarketingMath.parseBudgetToCents(""))
        assertNull(MarketingMath.parseBudgetToCents("abc"))
        assertNull(MarketingMath.parseBudgetToCents("-5"))
    }

    // ---- segment / list size ----

    @Test
    fun formatSegmentSize_pluralizationAndCompaction() {
        assertEquals("No members", MarketingMath.formatSegmentSize(0))
        assertEquals("No members", MarketingMath.formatSegmentSize(-3))
        assertEquals("1 member", MarketingMath.formatSegmentSize(1))
        assertEquals("42 members", MarketingMath.formatSegmentSize(42))
        assertEquals("1.5K members", MarketingMath.formatSegmentSize(1_500))
        assertEquals("2M members", MarketingMath.formatSegmentSize(2_000_000))
    }

    @Test
    fun compact_boundaries() {
        assertEquals("999", MarketingMath.compact(999))
        assertEquals("1K", MarketingMath.compact(1_000))
        assertEquals("12.3K", MarketingMath.compact(12_345))
        assertEquals("1M", MarketingMath.compact(1_000_000))
    }

    // ---- predicate ----

    @Test
    fun formatPredicate_mapsOperators() {
        assertEquals("total_spend_cents ≥ 1000", MarketingMath.formatPredicate("total_spend_cents", "gte", "1000"))
        assertEquals("profile_country = US", MarketingMath.formatPredicate("profile_country", "eq", "US"))
        assertEquals("tier in a,b", MarketingMath.formatPredicate("tier", "in", "a,b"))
        assertEquals("x not in y", MarketingMath.formatPredicate("x", "not_in", "y"))
    }
}
