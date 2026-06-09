package com.testlogon.android.feature.auth.recovery

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakePasswordRecoveryRepository
import com.testlogon.android.navigation.AuthDest
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class RecoveryConfirmViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private lateinit var repo: FakePasswordRecoveryRepository
    private val strongPassword = "Str0ng!Passw0rd"

    @Before
    fun setUp() {
        repo = FakePasswordRecoveryRepository()
    }

    private fun vm(
        username: String = "alice",
        challengeId: String = "pwr_1",
        code: String? = "482913",
    ): RecoveryConfirmViewModel {
        val map = mutableMapOf<String, Any?>(
            AuthDest.RecoveryConfirm.ARG_USERNAME to username,
            AuthDest.RecoveryConfirm.ARG_CHALLENGE_ID to challengeId,
        )
        if (code != null) map[AuthDest.RecoveryConfirm.KEY_CODE] = code
        return RecoveryConfirmViewModel(repo, SavedStateHandle(map))
    }

    @Test
    fun missingCode_isFatalMissingContext_noNetworkCall() = runTest(mainRule.dispatcher) {
        val v = vm(code = null)
        assertEquals(ConfirmFatal.MISSING_CONTEXT, v.uiState.value.fatal)
        v.onNewPasswordChange(strongPassword)
        v.onConfirmPasswordChange(strongPassword)
        v.onSubmit()
        advanceUntilIdle()
        assertEquals(0, repo.confirmCalls)
    }

    @Test
    fun submitGate_requiresRulesAndMatch() {
        val v = vm()
        assertFalse(v.uiState.value.isSubmitEnabled)
        v.onNewPasswordChange(strongPassword)
        assertFalse(v.uiState.value.isSubmitEnabled) // confirm empty
        v.onConfirmPasswordChange("different")
        assertFalse(v.uiState.value.isSubmitEnabled) // mismatch
        v.onConfirmPasswordChange(strongPassword)
        assertTrue(v.uiState.value.isSubmitEnabled)
        v.onNewPasswordChange("weak")
        assertFalse(v.uiState.value.isSubmitEnabled) // rules fail
    }

    @Test
    fun success_emitsSuccess_clearsPasswords_sendsConfirmationCode() = runTest(mainRule.dispatcher) {
        repo.confirmResult = ApiResult.Success(Unit)
        val v = vm()
        val effects = mutableListOf<RecoveryConfirmEffect>()
        val job = launch { v.effects.collect { effects += it } }
        runCurrent()

        v.onNewPasswordChange(strongPassword)
        v.onConfirmPasswordChange(strongPassword)
        v.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(RecoveryConfirmEffect.Success("alice")), effects)
        assertEquals("", v.uiState.value.newPassword)
        assertEquals("", v.uiState.value.confirmPassword)
        assertEquals("482913", repo.lastConfirmCode)
        assertEquals(strongPassword, repo.lastConfirmNewPassword)
        assertEquals("pwr_1", repo.lastConfirmChallengeId)
    }

    @Test
    fun policyRejection_showsInlineError_staysOnScreen() = runTest(mainRule.dispatcher) {
        repo.confirmResult = ApiResult.Failure(ApiError(422, "Password does not meet policy."))
        val v = vm()
        v.onNewPasswordChange(strongPassword)
        v.onConfirmPasswordChange(strongPassword)
        v.onSubmit()
        advanceUntilIdle()
        assertEquals("Password does not meet policy.", v.uiState.value.error)
        assertEquals(null, v.uiState.value.fatal)
    }

    @Test
    fun expiredChallenge_setsFatal() = runTest(mainRule.dispatcher) {
        repo.confirmResult = ApiResult.Failure(ApiError(410, "expired", code = "challenge_expired"))
        val v = vm()
        v.onNewPasswordChange(strongPassword)
        v.onConfirmPasswordChange(strongPassword)
        v.onSubmit()
        advanceUntilIdle()
        assertEquals(ConfirmFatal.CHALLENGE_EXPIRED, v.uiState.value.fatal)
    }

    @Test
    fun networkError_showsRetryableMessage() = runTest(mainRule.dispatcher) {
        repo.confirmResult = ApiResult.NetworkError(java.io.IOException())
        val v = vm()
        v.onNewPasswordChange(strongPassword)
        v.onConfirmPasswordChange(strongPassword)
        v.onSubmit()
        advanceUntilIdle()
        assertTrue(v.uiState.value.error!!.contains("Couldn't reach the server"))
    }

    @Test
    fun doubleSubmit_whileInFlight_callsConfirmOnce() = runTest(mainRule.dispatcher) {
        repo.confirmResult = ApiResult.Success(Unit)
        val v = vm()
        v.onNewPasswordChange(strongPassword)
        v.onConfirmPasswordChange(strongPassword)
        v.onSubmit()
        v.onSubmit()
        advanceUntilIdle()
        assertEquals(1, repo.confirmCalls)
    }

    @Test
    fun toString_doesNotLeakPassword() {
        val v = vm()
        v.onNewPasswordChange(strongPassword)
        assertFalse(v.uiState.value.toString().contains(strongPassword))
    }
}
