package com.testlogon.android.feature.auth.recovery

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakePasswordRecoveryRepository
import com.testlogon.android.data.auth.RecoveryBeginOutcome
import com.testlogon.android.data.auth.RecoveryFactor
import com.testlogon.android.data.auth.RecoveryVerifyOutcome
import com.testlogon.android.navigation.AuthDest
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class RecoveryChallengeViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private lateinit var repo: FakePasswordRecoveryRepository

    @Before
    fun setUp() {
        repo = FakePasswordRecoveryRepository()
    }

    private fun vm(
        username: String = "alice",
        challengeId: String = "pwr_1",
        factors: String = "sms",
        medium: String = "sms",
        destination: String = "+1 ••• ••• 4821",
    ): RecoveryChallengeViewModel {
        val handle = SavedStateHandle(
            mapOf(
                AuthDest.RecoveryChallenge.ARG_USERNAME to username,
                AuthDest.RecoveryChallenge.ARG_CHALLENGE_ID to challengeId,
                AuthDest.RecoveryChallenge.ARG_FACTORS to factors,
                AuthDest.RecoveryChallenge.ARG_MEDIUM to medium,
                AuthDest.RecoveryChallenge.ARG_DESTINATION to destination,
            ),
        )
        return RecoveryChallengeViewModel(repo, handle)
    }

    @Test
    fun seedsState_andBeginsSmsFactor() = runTest(mainRule.dispatcher) {
        repo.beginResult = ApiResult.Success(RecoveryBeginOutcome(listOf("+1 ••• ••• 4821")))
        val v = vm()
        advanceUntilIdle()
        val s = v.uiState.value
        assertEquals("pwr_1", s.challengeId)
        assertEquals(RecoveryFactor.Sms, s.activeFactor)
        assertEquals(listOf(RecoveryFactor.Sms), v.uiState.value.factors)
        assertEquals(1, repo.beginCalls)
        assertEquals(listOf(RecoveryFactor.Sms), repo.beginFactors)
    }

    @Test
    fun totpFactor_doesNotBegin() = runTest(mainRule.dispatcher) {
        val v = vm(factors = "totp", medium = "totp", destination = "")
        advanceUntilIdle()
        assertEquals(RecoveryFactor.Totp, v.uiState.value.activeFactor)
        assertEquals(0, repo.beginCalls)
    }

    @Test
    fun verifySuccess_emitsVerified_withEnteredCode() = runTest(mainRule.dispatcher) {
        repo.beginResult = ApiResult.Success(RecoveryBeginOutcome())
        repo.verifyResult = ApiResult.Success(RecoveryVerifyOutcome("pwr_1", null))
        val v = vm()
        val effects = mutableListOf<RecoveryChallengeEffect>()
        val job = launch { v.effects.collect { effects += it } }
        advanceUntilIdle()

        v.onCodeChange("482913")
        v.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(
            listOf(RecoveryChallengeEffect.Verified("alice", "pwr_1", "482913")),
            effects,
        )
        assertEquals(RecoveryFactor.Sms, repo.lastVerifyFactor)
        assertEquals("482913", repo.lastVerifyCode)
    }

    @Test
    fun wrongCode_clearsField_staysOnScreen() = runTest(mainRule.dispatcher) {
        repo.beginResult = ApiResult.Success(RecoveryBeginOutcome())
        repo.verifyResult = ApiResult.Failure(ApiError(422, "That code didn't match."))
        val v = vm()
        advanceUntilIdle()
        v.onCodeChange("000000")
        v.onSubmit()
        advanceUntilIdle()
        assertEquals("", v.uiState.value.code)
        assertEquals("That code didn't match.", v.uiState.value.error)
        assertFalse(v.uiState.value.isVerifying)
    }

    @Test
    fun expiredChallenge_emitsRestart() = runTest(mainRule.dispatcher) {
        repo.beginResult = ApiResult.Success(RecoveryBeginOutcome())
        repo.verifyResult = ApiResult.Failure(ApiError(410, "expired"))
        val v = vm()
        val effects = mutableListOf<RecoveryChallengeEffect>()
        val job = launch { v.effects.collect { effects += it } }
        advanceUntilIdle()
        v.onCodeChange("123456")
        v.onSubmit()
        advanceUntilIdle()
        job.cancel()
        assertTrue(effects.contains(RecoveryChallengeEffect.RestartRequired))
    }

    @Test
    fun blankChallengeId_emitsRestart_immediately() = runTest(mainRule.dispatcher) {
        val v = vm(challengeId = "")
        val effects = mutableListOf<RecoveryChallengeEffect>()
        val job = launch { v.effects.collect { effects += it } }
        advanceUntilIdle()
        job.cancel()
        assertTrue(effects.contains(RecoveryChallengeEffect.RestartRequired))
        assertEquals(0, repo.verifyCalls)
    }

    @Test
    fun doubleSubmit_whileInFlight_callsVerifyOnce() = runTest(mainRule.dispatcher) {
        repo.beginResult = ApiResult.Success(RecoveryBeginOutcome())
        repo.verifyResult = ApiResult.Success(RecoveryVerifyOutcome("pwr_1", null))
        val v = vm()
        advanceUntilIdle()
        v.onCodeChange("482913")
        v.onSubmit()
        v.onSubmit()
        advanceUntilIdle()
        assertEquals(1, repo.verifyCalls)
    }

    @Test
    fun submit_disabledUntilOtpFull_forNumericFactor() = runTest(mainRule.dispatcher) {
        repo.beginResult = ApiResult.Success(RecoveryBeginOutcome())
        val v = vm()
        advanceUntilIdle()
        v.onCodeChange("12345")
        assertFalse(v.uiState.value.canSubmit)
        v.onCodeChange("123456")
        assertTrue(v.uiState.value.canSubmit)
    }

    @Test
    fun recoveryFactor_acceptsLongerCode() = runTest(mainRule.dispatcher) {
        val v = vm(factors = "recovery", medium = "", destination = "")
        advanceUntilIdle()
        assertFalse(v.uiState.value.isNumericFactor)
        v.onCodeChange("ABCD-1234")
        assertTrue(v.uiState.value.canSubmit)
    }

    @Test
    fun toString_doesNotLeakCode() = runTest(mainRule.dispatcher) {
        repo.beginResult = ApiResult.Success(RecoveryBeginOutcome())
        val v = vm()
        advanceUntilIdle()
        v.onCodeChange("482913")
        assertFalse(v.uiState.value.toString().contains("482913"))
    }
}
