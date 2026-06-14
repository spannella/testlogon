package com.testlogon.android.feature.auth.mfa

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthRepository
import com.testlogon.android.data.auth.MfaFactor
import com.testlogon.android.data.auth.MfaVerifyOutcome
import com.testlogon.android.data.auth.User
import com.testlogon.android.navigation.AuthDest
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class MfaViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(
        repo: FakeAuthRepository,
        challengeId: String = "chl_1",
        factors: String = "totp",
    ): MfaViewModel {
        val handle = SavedStateHandle(
            mapOf(
                AuthDest.Mfa.ARG_CHALLENGE_ID to challengeId,
                AuthDest.Mfa.ARG_FACTORS to factors,
            ),
        )
        return MfaViewModel(repo, handle)
    }

    @Test
    fun seed_selectsFirstFactor_totpNeedsNoBegin() = runTest(mainRule.dispatcher) {
        val repo = FakeAuthRepository()
        val vm = vm(repo, factors = "totp,sms")
        advanceUntilIdle()
        assertEquals(MfaFactor.Totp, vm.uiState.value.activeFactor)
        assertEquals(0, repo.beginSmsCalls)
    }

    @Test
    fun smsFactor_runsBeginAndSurfacesSentTo() = runTest(mainRule.dispatcher) {
        val repo = FakeAuthRepository().apply { beginResult = ApiResult.Success(listOf("+1•••1234")) }
        val vm = vm(repo, factors = "sms")
        advanceUntilIdle()
        assertEquals(1, repo.beginSmsCalls)
        assertEquals(listOf("+1•••1234"), vm.uiState.value.sentTo)
    }

    @Test
    fun submitTotp_authenticated_emitsNavigateHome() = runTest(mainRule.dispatcher) {
        val repo = FakeAuthRepository().apply {
            verifyResult = ApiResult.Success(MfaVerifyOutcome.Authenticated(User("u", "s", "ip")))
        }
        val vm = vm(repo)
        advanceUntilIdle()

        val effects = mutableListOf<MfaEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        runCurrent()

        vm.onCodeChange("123456")
        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(MfaEffect.NavigateHome), effects)
        assertEquals(1, repo.verifyTotpCalls)
    }

    @Test
    fun submitTotp_factorsRemaining_advancesToNextFactor() = runTest(mainRule.dispatcher) {
        val repo = FakeAuthRepository().apply {
            verifyResult = ApiResult.Success(MfaVerifyOutcome.FactorsRemaining(listOf(MfaFactor.Sms)))
            beginResult = ApiResult.Success(listOf("+1•••1234"))
        }
        val vm = vm(repo, factors = "totp,sms")
        advanceUntilIdle()

        vm.onCodeChange("123456")
        vm.onSubmit()
        advanceUntilIdle()

        assertEquals(MfaFactor.Sms, vm.uiState.value.activeFactor)
        assertEquals("", vm.uiState.value.code)
        assertEquals(1, repo.beginSmsCalls) // begin fired for the advanced-to SMS factor
    }

    @Test
    fun wrongCode_keepsUserOnFactor_clearsCode_setsError() = runTest(mainRule.dispatcher) {
        val repo = FakeAuthRepository().apply {
            verifyResult = ApiResult.Failure(ApiError(400, "Invalid code"))
        }
        val vm = vm(repo)
        advanceUntilIdle()

        vm.onCodeChange("000000")
        vm.onSubmit()
        advanceUntilIdle()

        val s = vm.uiState.value
        assertEquals(MfaFactor.Totp, s.activeFactor)
        assertEquals("", s.code)
        assertEquals("Invalid code", s.error)
    }

    @Test
    fun sessionLost401_emitsNavigateToLogin() = runTest(mainRule.dispatcher) {
        val repo = FakeAuthRepository().apply {
            verifyResult = ApiResult.Failure(ApiError(401, "expired"))
        }
        val vm = vm(repo)
        advanceUntilIdle()

        val effects = mutableListOf<MfaEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        runCurrent()

        vm.onCodeChange("123456")
        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(MfaEffect.NavigateToLogin), effects)
    }

    @Test
    fun submit_gatedUntilCodeComplete() = runTest(mainRule.dispatcher) {
        val repo = FakeAuthRepository()
        val vm = vm(repo)
        advanceUntilIdle()

        vm.onCodeChange("123")
        vm.onSubmit()
        advanceUntilIdle()
        assertEquals(0, repo.verifyTotpCalls) // not full length → no verify call

        vm.onCodeChange("123456")
        assertTrue(vm.uiState.value.canSubmit)
    }

    @Test
    fun missingChallenge_doesNotBeginOrSeedFactors() = runTest(mainRule.dispatcher) {
        val repo = FakeAuthRepository()
        val vm = vm(repo, challengeId = "")
        advanceUntilIdle()
        // Blank challenge → init routes to login (one-shot effect) and runs no begin call.
        assertEquals("", vm.uiState.value.challengeId)
        assertEquals(0, repo.beginSmsCalls)
    }

    @Test
    fun uiStateToString_doesNotLeakCode() {
        val repo = FakeAuthRepository()
        val vm = vm(repo)
        vm.onCodeChange("999999")
        assertFalse(vm.uiState.value.toString().contains("999999"))
    }
}
