package com.testlogon.android.data.adminmod

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for the PURE [ModerationMath] logic (no Android / Moshi types). Covers the
 * case-state normalization (incl. unknown-safe + legacy-token synonyms), terminality, the
 * action state-machine gating (claim/dismiss/confirm/final-call), age computation, and the
 * hold/awaiting-final SLA deadline + breach + bucket math.
 */
class ModerationMathTest {

    // ---- state normalization ----

    @Test
    fun caseState_mapsKnownTokens() {
        assertEquals(ModerationMath.CaseState.OPEN, ModerationMath.caseState("open"))
        assertEquals(ModerationMath.CaseState.UNDER_REVIEW, ModerationMath.caseState("under_review"))
        assertEquals(ModerationMath.CaseState.HOLD, ModerationMath.caseState("hold"))
        assertEquals(ModerationMath.CaseState.AWAITING_FINAL, ModerationMath.caseState("awaiting_final"))
        assertEquals(ModerationMath.CaseState.DELETED, ModerationMath.caseState("deleted"))
        assertEquals(ModerationMath.CaseState.REINSTATED, ModerationMath.caseState("reinstated"))
        assertEquals(ModerationMath.CaseState.DISMISSED, ModerationMath.caseState("dismissed"))
    }

    @Test
    fun caseState_acceptsLegacySynonyms() {
        assertEquals(ModerationMath.CaseState.OPEN, ModerationMath.caseState("new"))
        assertEquals(ModerationMath.CaseState.UNDER_REVIEW, ModerationMath.caseState("claimed"))
        assertEquals(ModerationMath.CaseState.HOLD, ModerationMath.caseState("on_hold"))
        assertEquals(ModerationMath.CaseState.CLOSED, ModerationMath.caseState("resolved"))
        assertEquals(ModerationMath.CaseState.DELETED, ModerationMath.caseState("removed"))
    }

    @Test
    fun caseState_blankAndUnknownAreUnknownSafe() {
        assertEquals(ModerationMath.CaseState.UNKNOWN, ModerationMath.caseState(null))
        assertEquals(ModerationMath.CaseState.UNKNOWN, ModerationMath.caseState(""))
        assertEquals(ModerationMath.CaseState.UNKNOWN, ModerationMath.caseState("   "))
        assertEquals(ModerationMath.CaseState.UNKNOWN, ModerationMath.caseState("brand_new_server_state"))
    }

    @Test
    fun caseState_isCaseInsensitiveAndTrims() {
        assertEquals(ModerationMath.CaseState.HOLD, ModerationMath.caseState("  HOLD  "))
    }

    // ---- terminality ----

    @Test
    fun isTerminal_forEndStates() {
        assertTrue(ModerationMath.isTerminal(ModerationMath.CaseState.DISMISSED))
        assertTrue(ModerationMath.isTerminal(ModerationMath.CaseState.REINSTATED))
        assertTrue(ModerationMath.isTerminal(ModerationMath.CaseState.DELETED))
        assertTrue(ModerationMath.isTerminal(ModerationMath.CaseState.CLOSED))
        assertTrue(ModerationMath.isTerminal("deleted"))
    }

    @Test
    fun isTerminal_falseForLiveStates() {
        assertFalse(ModerationMath.isTerminal(ModerationMath.CaseState.OPEN))
        assertFalse(ModerationMath.isTerminal(ModerationMath.CaseState.UNDER_REVIEW))
        assertFalse(ModerationMath.isTerminal(ModerationMath.CaseState.HOLD))
        assertFalse(ModerationMath.isTerminal(ModerationMath.CaseState.AWAITING_FINAL))
    }

    // ---- action state machine ----

    @Test
    fun canApply_claimOnlyWhenUnowned() {
        assertTrue(ModerationMath.canApply(ModerationMath.CaseState.OPEN, ModerationMath.CaseAction.CLAIM, owned = false))
        assertFalse(ModerationMath.canApply(ModerationMath.CaseState.OPEN, ModerationMath.CaseAction.CLAIM, owned = true))
    }

    @Test
    fun canApply_dismissConfirmOnlyWhileReviewable() {
        assertTrue(ModerationMath.canApply(ModerationMath.CaseState.UNDER_REVIEW, ModerationMath.CaseAction.DISMISS))
        assertTrue(ModerationMath.canApply(ModerationMath.CaseState.UNDER_REVIEW, ModerationMath.CaseAction.CONFIRM))
        assertTrue(ModerationMath.canApply(ModerationMath.CaseState.OPEN, ModerationMath.CaseAction.CONFIRM))
        // not once escalated to hold
        assertFalse(ModerationMath.canApply(ModerationMath.CaseState.HOLD, ModerationMath.CaseAction.CONFIRM))
        assertFalse(ModerationMath.canApply(ModerationMath.CaseState.HOLD, ModerationMath.CaseAction.DISMISS))
    }

    @Test
    fun canApply_finalCallOnlyAfterEscalation() {
        assertTrue(ModerationMath.canApply(ModerationMath.CaseState.HOLD, ModerationMath.CaseAction.FINAL_CALL))
        assertTrue(ModerationMath.canApply(ModerationMath.CaseState.AWAITING_FINAL, ModerationMath.CaseAction.FINAL_CALL))
        assertFalse(ModerationMath.canApply(ModerationMath.CaseState.OPEN, ModerationMath.CaseAction.FINAL_CALL))
        assertFalse(ModerationMath.canApply(ModerationMath.CaseState.UNDER_REVIEW, ModerationMath.CaseAction.FINAL_CALL))
    }

    @Test
    fun canApply_nothingOnTerminal() {
        for (a in ModerationMath.CaseAction.entries) {
            assertFalse(ModerationMath.canApply(ModerationMath.CaseState.DELETED, a))
            assertFalse(ModerationMath.canApply(ModerationMath.CaseState.DISMISSED, a))
        }
    }

    @Test
    fun availableActions_forHoldIsFinalCallOnly() {
        assertEquals(
            listOf(ModerationMath.CaseAction.FINAL_CALL),
            ModerationMath.availableActions(ModerationMath.CaseState.HOLD),
        )
    }

    @Test
    fun availableActions_terminalIsEmpty() {
        assertTrue(ModerationMath.availableActions(ModerationMath.CaseState.CLOSED).isEmpty())
    }

    // ---- age ----

    @Test
    fun age_isNeverNegative() {
        assertEquals(0L, ModerationMath.ageSeconds(createdAt = 100L, now = 50L))
        assertEquals(60L, ModerationMath.ageSeconds(createdAt = 100L, now = 160L))
        assertEquals(1L, ModerationMath.ageMinutes(createdAt = 0L, now = 90L))
    }

    // ---- SLA deadline / breach / bucket ----

    @Test
    fun deadline_holdUsesHoldUntilThenFallback() {
        assertEquals(
            java.lang.Long.valueOf(5_000L),
            ModerationMath.deadline(ModerationMath.CaseState.HOLD, createdAt = 100L, holdUntil = 5_000L),
        )
        // fallback createdAt + 30d when holdUntil missing
        assertEquals(
            java.lang.Long.valueOf(100L + ModerationMath.HOLD_WINDOW_SECONDS),
            ModerationMath.deadline(ModerationMath.CaseState.HOLD, createdAt = 100L, holdUntil = null),
        )
    }

    @Test
    fun deadline_awaitingFinalFallsBackTo14d() {
        assertEquals(
            java.lang.Long.valueOf(200L + ModerationMath.AWAITING_FINAL_SLA_SECONDS),
            ModerationMath.deadline(ModerationMath.CaseState.AWAITING_FINAL, createdAt = 200L, holdUntil = 0L),
        )
    }

    @Test
    fun deadline_noneForReviewableAndTerminal() {
        assertNull(ModerationMath.deadline(ModerationMath.CaseState.OPEN, 100L, null))
        assertNull(ModerationMath.deadline(ModerationMath.CaseState.UNDER_REVIEW, 100L, 999L))
        assertNull(ModerationMath.deadline(ModerationMath.CaseState.DELETED, 100L, 999L))
    }

    @Test
    fun slaBreach_whenPastDeadline() {
        val created = 0L
        val hold = ModerationMath.HOLD_WINDOW_SECONDS
        // exactly at deadline: not yet breached (remaining == 0)
        assertFalse(ModerationMath.isSlaBreached(ModerationMath.CaseState.HOLD, created, hold, now = hold))
        // one second past
        assertTrue(ModerationMath.isSlaBreached(ModerationMath.CaseState.HOLD, created, hold, now = hold + 1))
        // reviewable never breaches
        assertFalse(ModerationMath.isSlaBreached(ModerationMath.CaseState.OPEN, created, null, now = hold + 1))
    }

    @Test
    fun slaBucket_partitionsRemainingTime() {
        val created = 0L
        val deadline = ModerationMath.HOLD_WINDOW_SECONDS
        // no deadline state
        assertEquals(
            ModerationMath.SlaBucket.NONE,
            ModerationMath.slaBucket(ModerationMath.CaseState.OPEN, created, null, now = 0L),
        )
        // plenty of time -> OK
        assertEquals(
            ModerationMath.SlaBucket.OK,
            ModerationMath.slaBucket(ModerationMath.CaseState.HOLD, created, deadline, now = 0L),
        )
        // within 24h -> DUE_SOON
        assertEquals(
            ModerationMath.SlaBucket.DUE_SOON,
            ModerationMath.slaBucket(ModerationMath.CaseState.HOLD, created, deadline, now = deadline - 3600L),
        )
        // past -> BREACHED
        assertEquals(
            ModerationMath.SlaBucket.BREACHED,
            ModerationMath.slaBucket(ModerationMath.CaseState.HOLD, created, deadline, now = deadline + 10L),
        )
    }
}
