package com.testlogon.android.feature.auth.register

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeRegisterRepository
import com.testlogon.android.data.auth.MfaSetupFactor
import com.testlogon.android.data.auth.MfaSetupHandoff
import com.testlogon.android.data.auth.RegisterConfirmOutcome
import com.testlogon.android.data.auth.RegisterResendResp
import com.testlogon.android.data.auth.User
import com.testlogon.android.navigation.AuthDest
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class RegisterConfirmViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private lateinit var repo: FakeRegisterRepository

    @Before
    fun setUp() {
        repo = FakeRegisterRepository()
    }

    private fun vm(
        email: String = "jane@example.com",
        medium: String = "email",
        smsMfa: Boolean = false,
        phone: String = "",
    ): RegisterConfirmViewModel {
        val handle = SavedStateHandle(
            mapOf(
                AuthDest.RegisterConfirm.ARG_EMAIL to email,
                AuthDest.RegisterConfirm.ARG_MEDIUM to medium,
                AuthDest.RegisterConfirm.ARG_DESTINATION to "j**@example.com",
                AuthDest.RegisterConfirm.ARG_SMS_MFA to smsMfa.toString(),
                AuthDest.RegisterConfirm.ARG_TOTP_MFA to "false",
                AuthDest.RegisterConfirm.ARG_PHONE to phone,
            ),
        )
        return RegisterConfirmViewModel(repo, handle)
    }

    @Test
    fun seedsStateFromArgs() {
        val s = vm().uiState.value
        assertEquals("jane@example.com", s.email)
        assertEquals("email", s.deliveryMedium)
        assertEquals("j**@example.com", s.deliveryDestination)
    }

    @Test
    fun confirm_disabledUntilFullLength() {
        val v = vm()
        assertFalse(v.uiState.value.canConfirm)
        v.onCodeChange("12345")
        assertFalse(v.uiState.value.canConfirm)
        v.onCodeChange("123456")
        assertTrue(v.uiState.value.canConfirm)
    }

    @Test
    fun confirm_noSession_emitsGoToLogin_sendsEmailAndCode() = runTest(mainRule.dispatcher) {
        repo.confirmResult = ApiResult.Success(RegisterConfirmOutcome.VerifiedSignIn("jane@example.com"))
        val v = vm()
        val effects = mutableListOf<RegisterConfirmEffect>()
        val job = launch { v.effects.collect { effects += it } }
        runCurrent()

        v.onCodeChange("123456")
        v.onConfirm()
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(RegisterConfirmEffect.GoToLogin("jane@example.com")), effects)
        assertEquals("jane@example.com", repo.lastConfirmReq?.email)
        assertEquals("123456", repo.lastConfirmReq?.confirmationCode)
    }

    @Test
    fun confirm_session_noMfa_emitsGoToApp() = runTest(mainRule.dispatcher) {
        repo.confirmResult = ApiResult.Success(
            RegisterConfirmOutcome.Authenticated(User("u", "s", "ip"), MfaSetupHandoff()),
        )
        val v = vm()
        val effects = mutableListOf<RegisterConfirmEffect>()
        val job = launch { v.effects.collect { effects += it } }
        runCurrent()
        v.onCodeChange("123456")
        v.onConfirm()
        advanceUntilIdle()
        job.cancel()
        assertEquals(listOf(RegisterConfirmEffect.GoToApp), effects)
    }

    @Test
    fun confirm_session_withMfa_emitsGoToMfaSetup() = runTest(mainRule.dispatcher) {
        val handoff = MfaSetupHandoff(factors = listOf(MfaSetupFactor.Totp))
        repo.confirmResult = ApiResult.Success(
            RegisterConfirmOutcome.Authenticated(User("u", "s", "ip"), handoff),
        )
        val v = vm()
        val effects = mutableListOf<RegisterConfirmEffect>()
        val job = launch { v.effects.collect { effects += it } }
        runCurrent()
        v.onCodeChange("123456")
        v.onConfirm()
        advanceUntilIdle()
        job.cancel()
        assertEquals(listOf(RegisterConfirmEffect.GoToMfaSetup(handoff)), effects)
    }

    @Test
    fun wrongCode_failure_clearsCode_staysOnScreen() = runTest(mainRule.dispatcher) {
        repo.confirmResult = ApiResult.Failure(ApiError(400, "That code isn't correct."))
        val v = vm()
        v.onCodeChange("000000")
        v.onConfirm()
        advanceUntilIdle()
        assertEquals("", v.uiState.value.code)
        assertEquals("That code isn't correct.", v.uiState.value.error)
        assertFalse(v.uiState.value.isSubmitting)
    }

    @Test
    fun networkError_keepsEnteredCode() = runTest(mainRule.dispatcher) {
        repo.confirmResult = ApiResult.NetworkError(java.io.IOException())
        val v = vm()
        v.onCodeChange("123456")
        v.onConfirm()
        advanceUntilIdle()
        assertEquals("123456", v.uiState.value.code)
        assertTrue(v.uiState.value.error!!.contains("Couldn't reach the server"))
    }

    @Test
    fun resend_success_showsTransient_startsCooldown_thenReEnables() = runTest(mainRule.dispatcher) {
        repo.resendResult = ApiResult.Success(
            RegisterResendResp("sent", deliveryMedium = "email", deliveryDestination = "j**@example.com"),
        )
        val v = vm()
        v.onResend()
        runCurrent()
        assertEquals(1, repo.resendCalls)
        assertEquals("New code sent", v.uiState.value.transientMessage)
        assertEquals(RegisterConfirmViewModel.RESEND_COOLDOWN_SECONDS, v.uiState.value.resendCountdownSeconds)
        assertFalse(v.uiState.value.canResend)

        advanceTimeBy(RegisterConfirmViewModel.RESEND_COOLDOWN_SECONDS * 1000L + 100)
        advanceUntilIdle()
        assertEquals(0, v.uiState.value.resendCountdownSeconds)
        assertTrue(v.uiState.value.canResend)
    }

    @Test
    fun resend_duringCooldown_isNoOp() = runTest(mainRule.dispatcher) {
        repo.resendResult = ApiResult.Success(RegisterResendResp("sent"))
        val v = vm()
        v.onResend()
        runCurrent()
        assertEquals(1, repo.resendCalls)
        v.onResend() // still cooling down
        advanceUntilIdle()
        assertEquals(1, repo.resendCalls)
    }

    @Test
    fun resend_sendsMfaFlagsFromArgs() = runTest(mainRule.dispatcher) {
        repo.resendResult = ApiResult.Success(RegisterResendResp("sent"))
        val v = vm(smsMfa = true, phone = "+15551234567")
        v.onResend()
        advanceUntilIdle()
        assertEquals(true, repo.lastResendReq?.enableSmsMfa)
        assertEquals("+15551234567", repo.lastResendReq?.phone)
    }

    @Test
    fun doubleConfirm_whileInFlight_callsRepoOnce() = runTest(mainRule.dispatcher) {
        repo.confirmResult = ApiResult.Success(RegisterConfirmOutcome.VerifiedSignIn("jane@example.com"))
        val v = vm()
        v.onCodeChange("123456")
        v.onConfirm()
        v.onConfirm()
        advanceUntilIdle()
        assertEquals(1, repo.confirmCalls)
    }

    @Test
    fun toString_doesNotLeakCodeOrDestination() {
        val v = vm()
        v.onCodeChange("123456")
        val s = v.uiState.value.toString()
        assertFalse(s.contains("123456"))
        assertFalse(s.contains("j**@example.com"))
    }
}
