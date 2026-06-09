package com.testlogon.android.feature.auth.recovery

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakePasswordRecoveryRepository
import com.testlogon.android.data.auth.RecoveryFactor
import com.testlogon.android.data.auth.RecoveryStartOutcome
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class RecoveryStartViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private lateinit var repo: FakePasswordRecoveryRepository

    @Before
    fun setUp() {
        repo = FakePasswordRecoveryRepository()
    }

    private fun vm() = RecoveryStartViewModel(repo)

    @Test
    fun continue_disabledUntilUsernameNonBlank() {
        val v = vm()
        assertFalse(v.uiState.value.canContinue)
        v.onUsernameChange("alice")
        assertTrue(v.uiState.value.canContinue)
    }

    @Test
    fun blankUsername_makesZeroNetworkCalls() = runTest(mainRule.dispatcher) {
        val v = vm()
        v.onContinue() // blank
        advanceUntilIdle()
        assertEquals(0, repo.startCalls)
    }

    @Test
    fun challenge_emitsProceed_withTrimmedUsername() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(
            RecoveryStartOutcome.Challenge(
                challengeId = "pwr_1",
                requiredFactors = listOf(RecoveryFactor.Sms),
                deliveryMedium = "sms",
                deliveryDestination = "+1 ••• ••• 4821",
            ),
        )
        val v = vm()
        val effects = mutableListOf<RecoveryStartEffect>()
        val job = launch { v.effects.collect { effects += it } }
        runCurrent()

        v.onUsernameChange("  alice@example.com  ")
        v.onContinue()
        advanceUntilIdle()
        job.cancel()

        assertEquals(
            listOf(
                RecoveryStartEffect.ProceedToChallenge(
                    username = "alice@example.com",
                    challengeId = "pwr_1",
                    requiredFactors = listOf("sms"),
                    delivery = DeliverySummary("sms", "+1 ••• ••• 4821"),
                ),
            ),
            effects,
        )
        assertFalse(v.uiState.value.isSubmitting)
        assertNull(v.uiState.value.error)
    }

    @Test
    fun noChallenge_setsSentConfirmation_noEffect() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(
            RecoveryStartOutcome.Sent(deliveryMedium = "email", deliveryDestination = "a•••@example.com"),
        )
        val v = vm()
        val effects = mutableListOf<RecoveryStartEffect>()
        val job = launch { v.effects.collect { effects += it } }
        runCurrent()
        v.onUsernameChange("alice")
        v.onContinue()
        advanceUntilIdle()
        job.cancel()

        assertTrue(effects.isEmpty())
        assertEquals(DeliverySummary("email", "a•••@example.com"), v.uiState.value.sentConfirmation)
    }

    @Test
    fun httpError_showsMessage_staysOnScreen() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Failure(ApiError(429, "Too many attempts."))
        val v = vm()
        v.onUsernameChange("alice")
        v.onContinue()
        advanceUntilIdle()
        assertEquals("Too many attempts.", v.uiState.value.error)
        assertFalse(v.uiState.value.isSubmitting)
    }

    @Test
    fun networkError_showsRetryableMessage() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.NetworkError(java.io.IOException())
        val v = vm()
        v.onUsernameChange("alice")
        v.onContinue()
        advanceUntilIdle()
        assertTrue(v.uiState.value.error!!.contains("Couldn't reach the server"))
    }

    @Test
    fun doubleContinue_whileInFlight_callsRepoOnce() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(RecoveryStartOutcome.Sent("email", null))
        val v = vm()
        v.onUsernameChange("alice")
        v.onContinue()
        v.onContinue()
        advanceUntilIdle()
        assertEquals(1, repo.startCalls)
    }

    @Test
    fun toString_doesNotLeakUsername() {
        val v = vm()
        v.onUsernameChange("secretuser@example.com")
        assertFalse(v.uiState.value.toString().contains("secretuser"))
    }
}
