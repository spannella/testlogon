package com.testlogon.android.feature.auth.login

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthRepository
import com.testlogon.android.data.auth.LoginOutcome
import com.testlogon.android.data.auth.MfaFactor
import com.testlogon.android.data.auth.User
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

class LoginViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private lateinit var repo: FakeAuthRepository
    private lateinit var vm: LoginViewModel

    private class FakeServerUrlConfig : ServerUrlConfig {
        var url = "http://host:8000/"
        override fun current() = url
        override fun update(value: String) { url = value }
    }

    private lateinit var serverConfig: FakeServerUrlConfig

    @Before
    fun setUp() {
        repo = FakeAuthRepository()
        serverConfig = FakeServerUrlConfig()
        vm = LoginViewModel(repo, serverConfig)
    }

    @Test
    fun initialState_isEmptyAndDisabled() {
        val s = vm.uiState.value
        assertEquals("", s.email)
        assertFalse(s.submitEnabled)
        assertFalse(s.isSubmitting)
    }

    @Test
    fun submitEnabled_whenValidEmailAndPassword() {
        vm.onEmailChange("alice@example.com")
        vm.onPasswordChange("pw")
        assertTrue(vm.uiState.value.submitEnabled)
    }

    @Test
    fun submitDisabled_forMalformedEmail() {
        vm.onEmailChange("a@b") // has '@' but malformed
        vm.onPasswordChange("pw")
        assertFalse(vm.uiState.value.submitEnabled)
    }

    @Test
    fun submitDisabled_forBlankPassword() {
        vm.onEmailChange("alice@example.com")
        vm.onPasswordChange("")
        assertFalse(vm.uiState.value.submitEnabled)
    }

    @Test
    fun submit_authenticated_emitsNavigateHome() = runTest(mainRule.dispatcher) {
        repo.loginResult = ApiResult.Success(LoginOutcome.Authenticated(User("u", "s", "ip")))
        vm.onEmailChange("alice@example.com")
        vm.onPasswordChange("pw")

        val effects = mutableListOf<LoginEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        runCurrent()

        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(LoginEffect.NavigateHome), effects)
        assertNull(vm.uiState.value.error)
        assertEquals("alice@example.com", repo.lastUsername)
    }

    @Test
    fun submit_mfaRequired_emitsNavigateToMfa_andReturnsToIdle() = runTest(mainRule.dispatcher) {
        repo.loginResult = ApiResult.Success(LoginOutcome.MfaRequired("chl_1", listOf(MfaFactor.Totp)))
        vm.onEmailChange("alice@example.com")
        vm.onPasswordChange("pw")

        val effects = mutableListOf<LoginEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        runCurrent()

        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(LoginEffect.NavigateToMfa("chl_1", listOf(MfaFactor.Totp))), effects)
        assertEquals(LoginStatus.Idle, vm.uiState.value.status)
    }

    @Test
    fun submit_unauthorized_showsCredentialError_andReEnables() = runTest(mainRule.dispatcher) {
        repo.loginResult = ApiResult.Failure(ApiError(401, "nope"))
        vm.onEmailChange("alice@example.com")
        vm.onPasswordChange("pw")

        vm.onSubmit()
        advanceUntilIdle()

        val s = vm.uiState.value
        assertEquals("Invalid email or password.", s.error)
        assertEquals(LoginStatus.Idle, s.status)
        assertTrue(s.submitEnabled)
    }

    @Test
    fun submit_networkError_showsNetworkMessage() = runTest(mainRule.dispatcher) {
        repo.loginResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
        vm.onEmailChange("alice@example.com")
        vm.onPasswordChange("pw")

        vm.onSubmit()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.error!!.contains("Couldn't reach the server"))
    }

    @Test
    fun doubleSubmit_whileInFlight_callsRepoOnce() = runTest(mainRule.dispatcher) {
        repo.loginResult = ApiResult.Success(LoginOutcome.MfaRequired("chl_1", emptyList()))
        vm.onEmailChange("alice@example.com")
        vm.onPasswordChange("pw")

        vm.onSubmit()
        vm.onSubmit() // second call before the first completes is a no-op (still Submitting)
        advanceUntilIdle()
        assertEquals(1, repo.loginCalls)
    }

    @Test
    fun errorClears_onInputChange() = runTest(mainRule.dispatcher) {
        repo.loginResult = ApiResult.Failure(ApiError(401, "nope"))
        vm.onEmailChange("alice@example.com")
        vm.onPasswordChange("pw")
        vm.onSubmit()
        advanceUntilIdle()
        assertEquals("Invalid email or password.", vm.uiState.value.error)

        vm.onEmailChange("alice2@example.com")
        assertNull(vm.uiState.value.error)
    }

    @Test
    fun uiStateToString_doesNotLeakPassword() {
        vm.onPasswordChange("hunter2")
        assertFalse(vm.uiState.value.toString().contains("hunter2"))
    }
}
