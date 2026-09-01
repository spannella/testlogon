package com.testlogon.android.core.model.collaborations

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FIN-011 (Android) - pure JVM tests for [CollaborationMath], [SplitValidation] and [DisputeState]. No Android,
 * no Moshi: mirrors the server-side split + dispute invariants (app/services/collaboration_revenue.py).
 */
class CollaborationMathTest {

    // ---- validateSplit ----

    @Test
    fun validateSplit_exactly100_twoParties_isValid() {
        assertEquals(
            SplitValidation.Valid,
            CollaborationMath.validateSplit(mapOf("a" to 60, "b" to 40)),
        )
        assertTrue(CollaborationMath.isSplitValid(mapOf("a" to 50, "b" to 50)))
    }

    @Test
    fun validateSplit_threeParties_summing100_isValid() {
        assertTrue(CollaborationMath.isSplitValid(mapOf("a" to 34, "b" to 33, "c" to 33)))
    }

    @Test
    fun validateSplit_under100_isWrongTotal() {
        val r = CollaborationMath.validateSplit(mapOf("a" to 60, "b" to 39))
        assertTrue(r is SplitValidation.WrongTotal)
        assertEquals(99, (r as SplitValidation.WrongTotal).total)
        assertFalse(r.isValid)
    }

    @Test
    fun validateSplit_over100_isWrongTotal() {
        val r = CollaborationMath.validateSplit(mapOf("a" to 60, "b" to 45))
        assertTrue(r is SplitValidation.WrongTotal)
        assertEquals(105, (r as SplitValidation.WrongTotal).total)
    }

    @Test
    fun validateSplit_singleParty_isTooFewParties() {
        val r = CollaborationMath.validateSplit(mapOf("a" to 100))
        assertTrue(r is SplitValidation.TooFewParties)
        assertEquals(1, (r as SplitValidation.TooFewParties).count)
    }

    @Test
    fun validateSplit_emptyMap_isTooFewParties() {
        assertTrue(CollaborationMath.validateSplit(emptyMap()) is SplitValidation.TooFewParties)
    }

    @Test
    fun validateSplit_zeroPercentParty_isOutOfRange() {
        val r = CollaborationMath.validateSplit(mapOf("a" to 99, "b" to 0))
        assertTrue(r is SplitValidation.PartyOutOfRange)
        assertEquals("b", (r as SplitValidation.PartyOutOfRange).userId)
        assertEquals(0, r.percent)
    }

    @Test
    fun validateSplit_partyAtOrOver100_isOutOfRange() {
        // 100 for a single-visible party is >MAX_PARTY_PCT (99), caught before total.
        val r = CollaborationMath.validateSplit(mapOf("a" to 100, "b" to 5))
        assertTrue(r is SplitValidation.PartyOutOfRange)
        assertEquals("a", (r as SplitValidation.PartyOutOfRange).userId)
    }

    @Test
    fun validateSplit_negativeParty_isOutOfRange() {
        assertTrue(
            CollaborationMath.validateSplit(mapOf("a" to 110, "b" to -10))
                is SplitValidation.PartyOutOfRange,
        )
    }

    @Test
    fun splitTotal_and_remainderToFull_areComputed() {
        assertEquals(99, CollaborationMath.splitTotal(mapOf("a" to 60, "b" to 39)))
        assertEquals(-1, CollaborationMath.remainderToFull(mapOf("a" to 60, "b" to 39)))
        assertEquals(5, CollaborationMath.remainderToFull(mapOf("a" to 60, "b" to 45)))
        assertEquals(0, CollaborationMath.remainderToFull(mapOf("a" to 50, "b" to 50)))
    }

    // ---- DisputeState.from ----

    @Test
    fun disputeState_parsesTokens_withUnknownAndNoneFallbacks() {
        assertEquals(DisputeState.NONE, DisputeState.from(null))
        assertEquals(DisputeState.NONE, DisputeState.from(""))
        assertEquals(DisputeState.NONE, DisputeState.from(" NONE "))
        assertEquals(DisputeState.OPEN, DisputeState.from("open"))
        assertEquals(DisputeState.OPEN, DisputeState.from("Disputed"))
        assertEquals(DisputeState.OPEN, DisputeState.from("pending"))
        assertEquals(DisputeState.RESOLVED, DisputeState.from("resolved"))
        assertEquals(DisputeState.RESOLVED, DisputeState.from("REJECTED"))
        assertEquals(DisputeState.UNKNOWN, DisputeState.from("wat"))
        assertTrue(DisputeState.from("open").isOpen)
        assertFalse(DisputeState.from("resolved").isOpen)
    }

    // ---- canFileDispute ----

    @Test
    fun canFileDispute_onlyWhenParticipant_andNotAlreadyDisputed() {
        assertTrue(CollaborationMath.canFileDispute(null, isParticipant = true))
        assertTrue(CollaborationMath.canFileDispute("none", isParticipant = true))
        assertFalse(CollaborationMath.canFileDispute(null, isParticipant = false))
        assertFalse(CollaborationMath.canFileDispute("open", isParticipant = true))
        assertFalse(CollaborationMath.canFileDispute("resolved", isParticipant = true))
    }

    // ---- canResolveDispute ----

    @Test
    fun canResolveDispute_openOnly_counterpartyOrAdmin_notFiler() {
        // counter-party (participant, did not file) may resolve an open dispute
        assertTrue(
            CollaborationMath.canResolveDispute(
                disputeStatus = "open", filedBy = "a", viewerId = "b",
                isAdmin = false, isParticipant = true,
            ),
        )
        // the filer may NOT self-resolve
        assertFalse(
            CollaborationMath.canResolveDispute(
                disputeStatus = "open", filedBy = "a", viewerId = "a",
                isAdmin = false, isParticipant = true,
            ),
        )
        // an admin may always arbitrate an open dispute (even as the filer)
        assertTrue(
            CollaborationMath.canResolveDispute(
                disputeStatus = "open", filedBy = "a", viewerId = "a",
                isAdmin = true, isParticipant = true,
            ),
        )
        // a resolved dispute is never re-resolvable
        assertFalse(
            CollaborationMath.canResolveDispute(
                disputeStatus = "resolved", filedBy = "a", viewerId = "b",
                isAdmin = true, isParticipant = true,
            ),
        )
        // a non-participant non-admin may not resolve
        assertFalse(
            CollaborationMath.canResolveDispute(
                disputeStatus = "open", filedBy = "a", viewerId = "c",
                isAdmin = false, isParticipant = false,
            ),
        )
    }

    @Test
    fun canResolveDispute_blankViewer_isFalse() {
        assertFalse(
            CollaborationMath.canResolveDispute(
                disputeStatus = "open", filedBy = "a", viewerId = "",
                isAdmin = false, isParticipant = true,
            ),
        )
    }
}
