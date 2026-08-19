package com.testlogon.android.feature.home

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the pure getting-started checklist derivation. Covers the three real signals
 * (custody funded / trading funded / first trade), the neutral UNKNOWN mapping for unavailable data
 * (never a false "incomplete"), and the [HomeOnboarding] "all set" / "show checklist" gating.
 */
class HomeOnboardingDeriverTest {

    private fun step(steps: List<OnboardingStep>, id: OnboardingStepId) =
        steps.first { it.id == id }

    @Test
    fun `all signals true means every step DONE`() {
        val steps = HomeOnboardingDeriver.derive(
            OnboardingInputs(custodyFunded = true, tradingFunded = true, hasFirstTrade = true),
        )
        assertEquals(3, steps.size)
        assertTrue(steps.all { it.state == StepState.DONE })
        assertTrue(steps.all { it.isDone })
        assertTrue(steps.none { it.isActionable })
    }

    @Test
    fun `false signal means INCOMPLETE and actionable`() {
        val steps = HomeOnboardingDeriver.derive(
            OnboardingInputs(custodyFunded = false, tradingFunded = false, hasFirstTrade = false),
        )
        assertTrue(steps.all { it.state == StepState.INCOMPLETE })
        assertTrue(steps.all { it.isActionable })
        assertTrue(steps.none { it.isDone })
    }

    @Test
    fun `null signal maps to UNKNOWN and is never a false incomplete`() {
        val steps = HomeOnboardingDeriver.derive(
            OnboardingInputs(custodyFunded = null, tradingFunded = null, hasFirstTrade = null),
        )
        assertTrue(steps.all { it.state == StepState.UNKNOWN })
        // UNKNOWN is neutral: not done, but also not actionable (no false "incomplete").
        assertTrue(steps.none { it.isDone })
        assertTrue(steps.none { it.isActionable })
    }

    @Test
    fun `mixed signals derive per-step state and correct targets`() {
        val steps = HomeOnboardingDeriver.derive(
            OnboardingInputs(custodyFunded = true, tradingFunded = false, hasFirstTrade = null),
        )
        assertEquals(StepState.DONE, step(steps, OnboardingStepId.FUND_CUSTODY).state)
        assertEquals(StepState.INCOMPLETE, step(steps, OnboardingStepId.FUND_TRADING).state)
        assertEquals(StepState.UNKNOWN, step(steps, OnboardingStepId.FIRST_TRADE).state)

        assertEquals(HomeTarget.DEPOSIT, step(steps, OnboardingStepId.FUND_CUSTODY).target)
        assertEquals(HomeTarget.DEPOSIT, step(steps, OnboardingStepId.FUND_TRADING).target)
        assertEquals(HomeTarget.TRADE, step(steps, OnboardingStepId.FIRST_TRADE).target)
    }

    @Test
    fun `onboarding shows checklist while any step is confirmed incomplete`() {
        val steps = HomeOnboardingDeriver.derive(
            OnboardingInputs(custodyFunded = true, tradingFunded = false, hasFirstTrade = true),
        )
        val onboarding = HomeOnboarding(loading = false, steps = steps)
        assertTrue(onboarding.showChecklist)
        assertFalse(onboarding.allSet)
        assertFalse(onboarding.showAllSet)
        assertEquals(1, onboarding.actionableSteps.size)
    }

    @Test
    fun `all-known-done is all set and shows dismissible banner until dismissed`() {
        val steps = HomeOnboardingDeriver.derive(
            OnboardingInputs(custodyFunded = true, tradingFunded = true, hasFirstTrade = true),
        )
        val onboarding = HomeOnboarding(loading = false, steps = steps)
        assertTrue(onboarding.allSet)
        assertTrue(onboarding.showAllSet)
        assertFalse(onboarding.showChecklist)

        val dismissed = onboarding.copy(dismissed = true)
        assertTrue(dismissed.allSet)
        assertFalse(dismissed.showAllSet)
    }

    @Test
    fun `unknown-only is all set (nothing confirmed incomplete) but no step is marked done`() {
        val steps = HomeOnboardingDeriver.derive(
            OnboardingInputs(custodyFunded = null, tradingFunded = null, hasFirstTrade = null),
        )
        val onboarding = HomeOnboarding(loading = false, steps = steps)
        // No confirmed-incomplete step -> not prompting; all-set banner is allowed.
        assertFalse(onboarding.showChecklist)
        assertTrue(onboarding.allSet)
    }

    @Test
    fun `loading onboarding neither shows checklist nor all-set`() {
        val onboarding = HomeOnboarding(loading = true, steps = emptyList())
        assertFalse(onboarding.showChecklist)
        assertFalse(onboarding.showAllSet)
        assertFalse(onboarding.allSet)
    }
}
