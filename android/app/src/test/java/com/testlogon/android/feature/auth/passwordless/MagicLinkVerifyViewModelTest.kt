package com.testlogon.android.feature.auth.passwordless

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakePasswordlessRepository
import com.testlogon.android.data.auth.PasswordlessVerified
import com.testlogon.android.navigation.AuthDest
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class MagicLinkVerifyViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private lateinit var repo: FakePasswordlessRepository

    @Before
    fun setUp() {
        repo = FakePasswordlessRepository()
    }

    private fun vm(token: String?) =
        MagicLinkVerifyViewModel(
            savedStateHandle = SavedStateHandle(mapOf(AuthDest.MagicLinkVerify.ARG_TOKEN to token)),
            repository = repo,
        )

    @Test
    fun fullSession_emitsAuthenticatedEffect_andCallsVerifyOnce() = runTest(mainRule.dispatcher) {
        repo.verifyResult = ApiResult.Success(PasswordlessVerified.Authenticated)
        val v = vm("valid")
        val effects = mutableListOf<MagicLinkVerifyEffect>()
        val job = launch { v.effects.collect { effects += it } }
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(MagicLinkVerifyEffect.Authenticated), effects)
        assertEquals(1, repo.verifyCalls)
        assertEquals("valid", repo.lastVerifyToken)
    }

    @Test
    fun mfaRequired_emitsMfaEffect_withArgs() = runTest(mainRule.dispatcher) {
        repo.verifyResult = ApiResult.Success(
            PasswordlessVerified.MfaRequired(challengeId = "chg_8f2", requiredFactors = listOf("totp")),
        )
        val v = vm("valid")
        val effects = mutableListOf<MagicLinkVerifyEffect>()
        val job = launch { v.effects.collect { effects += it } }
        advanceUntilIdle()
        job.cancel()

        assertEquals(
            listOf(MagicLinkVerifyEffect.MfaRequired("chg_8f2", listOf("totp"))),
            effects,
        )
    }

    @Test
    fun missingToken_emitsMissingTokenError_noNetworkCall() = runTest(mainRule.dispatcher) {
        val v = vm(null)
        advanceUntilIdle()
        assertEquals(MagicLinkVerifyUiState.Error(MagicLinkError.MISSING_TOKEN), v.uiState.value)
        assertEquals(0, repo.verifyCalls)
    }

    @Test
    fun blankToken_emitsMissingTokenError_noNetworkCall() = runTest(mainRule.dispatcher) {
        val v = vm("   ")
        advanceUntilIdle()
        assertEquals(MagicLinkVerifyUiState.Error(MagicLinkError.MISSING_TOKEN), v.uiState.value)
        assertEquals(0, repo.verifyCalls)
    }

    @Test
    fun invalidOutcome_mapsToInvalidError() = runTest(mainRule.dispatcher) {
        repo.verifyResult = ApiResult.Success(PasswordlessVerified.Invalid)
        val v = vm("tok")
        advanceUntilIdle()
        assertEquals(MagicLinkVerifyUiState.Error(MagicLinkError.INVALID), v.uiState.value)
    }

    @Test
    fun http422_mapsToInvalid() = runTest(mainRule.dispatcher) {
        repo.verifyResult = ApiResult.Failure(ApiError(422, "bad"))
        val v = vm("tok")
        advanceUntilIdle()
        assertEquals(MagicLinkVerifyUiState.Error(MagicLinkError.INVALID), v.uiState.value)
    }

    @Test
    fun expiredCode_mapsToExpired_usedCode_mapsToUsed() = runTest(mainRule.dispatcher) {
        repo.verifyResult = ApiResult.Failure(ApiError(400, "x", code = "token_expired"))
        assertEquals(MagicLinkVerifyUiState.Error(MagicLinkError.EXPIRED), vm("tok").also { advanceUntilIdle() }.uiState.value)

        repo.verifyResult = ApiResult.Failure(ApiError(400, "x", code = "token_used"))
        assertEquals(MagicLinkVerifyUiState.Error(MagicLinkError.USED), vm("tok").also { advanceUntilIdle() }.uiState.value)
    }

    @Test
    fun networkError_mapsToNetwork_5xx_mapsToServer() = runTest(mainRule.dispatcher) {
        repo.verifyResult = ApiResult.NetworkError(java.io.IOException())
        assertEquals(MagicLinkVerifyUiState.Error(MagicLinkError.NETWORK), vm("tok").also { advanceUntilIdle() }.uiState.value)

        repo.verifyResult = ApiResult.Failure(ApiError(503, "down"))
        assertEquals(MagicLinkVerifyUiState.Error(MagicLinkError.SERVER), vm("tok").also { advanceUntilIdle() }.uiState.value)
    }

    @Test
    fun retry_afterNetworkError_reissuesWithSameToken() = runTest(mainRule.dispatcher) {
        repo.verifyResult = ApiResult.NetworkError(java.io.IOException())
        val v = vm("tok")
        advanceUntilIdle()
        assertEquals(1, repo.verifyCalls)

        repo.verifyResult = ApiResult.Success(PasswordlessVerified.Authenticated)
        val effects = mutableListOf<MagicLinkVerifyEffect>()
        val job = launch { v.effects.collect { effects += it } }
        runCurrent()
        v.verify()
        advanceUntilIdle()
        job.cancel()

        assertEquals(2, repo.verifyCalls)
        assertEquals("tok", repo.lastVerifyToken)
        assertTrue(effects.contains(MagicLinkVerifyEffect.Authenticated))
    }
}
