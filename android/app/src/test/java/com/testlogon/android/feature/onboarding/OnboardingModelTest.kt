package com.testlogon.android.feature.onboarding

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Thorough unit tests for the PURE [OnboardingModel] registry + seen-set helpers. */
class OnboardingModelTest {

    @Test
    fun shouldShow_true_whenIdNotSeen() {
        assertTrue(OnboardingModel.shouldShow("x", emptySet()))
        assertTrue(OnboardingModel.shouldShow("x", setOf("y", "z")))
    }

    @Test
    fun shouldShow_false_whenIdSeen() {
        assertFalse(OnboardingModel.shouldShow("x", setOf("x")))
        assertFalse(OnboardingModel.shouldShow("x", setOf("x", "y")))
    }

    @Test
    fun markSeen_addsId() {
        assertEquals(setOf("x"), OnboardingModel.markSeen("x", emptySet()))
        assertEquals(setOf("a", "x"), OnboardingModel.markSeen("x", setOf("a")))
    }

    @Test
    fun markSeen_isIdempotent_returnsSameInstanceWhenAlreadyPresent() {
        val seen = setOf("x", "y")
        val after = OnboardingModel.markSeen("x", seen)
        assertEquals(seen, after)
        assertTrue("no-op should return the same set instance", seen === after)
    }

    @Test
    fun markSeen_isMonotonic_neverRemoves() {
        var seen = emptySet<String>()
        seen = OnboardingModel.markSeen("a", seen)
        seen = OnboardingModel.markSeen("b", seen)
        seen = OnboardingModel.markSeen("a", seen)
        assertEquals(setOf("a", "b"), seen)
    }

    @Test
    fun tourSteps_notEmpty_firstStepHasNoRoute() {
        val steps = OnboardingModel.tourSteps()
        assertTrue(steps.size >= 8)
        assertNull("intro/welcome step should not navigate", steps.first().route)
    }

    @Test
    fun tourSteps_haveUniqueIds() {
        val ids = OnboardingModel.tourSteps().map { it.id }
        assertEquals(ids.size, ids.toSet().size)
    }

    @Test
    fun tourSteps_allTitlesAndBodiesNonBlank() {
        OnboardingModel.tourSteps().forEach {
            assertTrue("blank title for ${it.id}", it.title.isNotBlank())
            assertTrue("blank body for ${it.id}", it.body.isNotBlank())
        }
    }

    @Test
    fun tourSteps_routedStepsCarryRoutes_atLeastSix() {
        val routed = OnboardingModel.tourSteps().count { it.route != null }
        assertTrue("expected several routed steps, got $routed", routed >= 6)
    }

    @Test
    fun surfaceIntros_containAllSevenExpectedIds() {
        val intros = OnboardingModel.surfaceIntros()
        val expected = setOf(
            OnboardingModel.INTRO_INVEST,
            OnboardingModel.INTRO_STRATEGIES,
            OnboardingModel.INTRO_TOKENS,
            OnboardingModel.INTRO_BAILOUTS,
            OnboardingModel.INTRO_PORTFOLIO_ANALYTICS,
            OnboardingModel.INTRO_ACTIVITY_CENTER,
            OnboardingModel.INTRO_ACTIVE_ALGOS,
        )
        assertEquals(expected, intros.keys)
    }

    @Test
    fun surfaceIntro_lookup_matchesKeyAndHasContent() {
        val invest = OnboardingModel.surfaceIntro(OnboardingModel.INTRO_INVEST)
        assertNotNull(invest)
        assertEquals(OnboardingModel.INTRO_INVEST, invest!!.id)
        assertTrue(invest.title.isNotBlank())
        assertTrue(invest.body.isNotBlank())
    }

    @Test
    fun surfaceIntro_unknownId_returnsNull() {
        assertNull(OnboardingModel.surfaceIntro("nope"))
    }

    @Test
    fun surfaceIntros_haveNoRoute() {
        OnboardingModel.surfaceIntros().values.forEach {
            assertNull("surface intro ${it.id} should not carry a route", it.route)
        }
    }

    @Test
    fun allIds_includeWelcomeTourAndEverySurfaceIntro() {
        val all = OnboardingModel.allIds()
        assertTrue(all.contains(OnboardingModel.WELCOME_TOUR_ID))
        assertTrue(all.containsAll(OnboardingModel.surfaceIntros().keys))
        // welcome tour + 7 surface intros
        assertEquals(1 + OnboardingModel.surfaceIntros().size, all.size)
    }

    @Test
    fun welcomeTour_gatedByStableId_showsThenHidesAfterSeen() {
        var seen = emptySet<String>()
        assertTrue(OnboardingModel.shouldShow(OnboardingModel.WELCOME_TOUR_ID, seen))
        seen = OnboardingModel.markSeen(OnboardingModel.WELCOME_TOUR_ID, seen)
        assertFalse(OnboardingModel.shouldShow(OnboardingModel.WELCOME_TOUR_ID, seen))
    }
}
