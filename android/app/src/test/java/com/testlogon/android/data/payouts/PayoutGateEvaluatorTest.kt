package com.testlogon.android.data.payouts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-259 — pure gate evaluator: null -> Unknown (fail-closed); eligible=true -> Allowed;
 * eligible=null & rank >= required -> Allowed (fallback); eligible=false -> Blocked carrying tiers + unmet.
 */
class PayoutGateEvaluatorTest {

    private fun status(
        current: Int,
        required: Int = PAYOUT_REQUIRED_TIER,
        eligible: Boolean? = null,
        unmet: List<String> = emptyList(),
    ) = TierStatus(
        currentTier = KycTier(current),
        tierName = "t",
        requiredTierForPayouts = KycTier(required),
        eligibleForPayoutTier = eligible,
        unmetRequirements = unmet,
    )

    @Test
    fun nullStatus_failsClosedToUnknown() {
        assertEquals(PayoutGate.Unknown, PayoutGateEvaluator.evaluate(null))
    }

    @Test
    fun eligibleTrue_isAllowed_evenWhenRankLow() {
        assertEquals(PayoutGate.Allowed, PayoutGateEvaluator.evaluate(status(current = 0, required = 2, eligible = true)))
    }

    @Test
    fun eligibleNull_rankAtOrAboveRequired_isAllowed() {
        assertEquals(PayoutGate.Allowed, PayoutGateEvaluator.evaluate(status(current = 1, required = 1, eligible = null)))
        assertEquals(PayoutGate.Allowed, PayoutGateEvaluator.evaluate(status(current = 3, required = 1, eligible = null)))
    }

    @Test
    fun eligibleFalse_isBlocked_carryingTiersAndUnmet() {
        val gate = PayoutGateEvaluator.evaluate(
            status(current = 0, required = 1, eligible = false, unmet = listOf("gov_id")),
        )
        assertTrue(gate is PayoutGate.Blocked)
        gate as PayoutGate.Blocked
        assertEquals(0, gate.currentTier.rank)
        assertEquals(1, gate.requiredTier.rank)
        assertEquals(listOf("gov_id"), gate.missing)
    }

    @Test
    fun eligibleNull_rankBelowRequired_isBlocked() {
        val gate = PayoutGateEvaluator.evaluate(status(current = 0, required = 2, eligible = null))
        assertTrue(gate is PayoutGate.Blocked)
    }
}
