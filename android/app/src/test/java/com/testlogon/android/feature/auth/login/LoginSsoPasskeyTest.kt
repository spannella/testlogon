package com.testlogon.android.feature.auth.login

import android.app.Activity
import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthRepository
import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.data.auth.FakePasskeyRepository
import com.testlogon.android.data.auth.FakeSsoRepository
import com.testlogon.android.data.auth.FakeSsoStateStore
import com.testlogon.android.data.auth.FakeSsoTabLauncher
import com.testlogon.android.data.auth.PasskeyAuthResult
import com.testlogon.android.data.auth.SsoInfo
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito.mock

/** AND-062/063 — LoginViewModel SSO discovery + browser handoff + passkey sign-in. */
class LoginSsoPasskeyTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeServerUrlConfig : ServerUrlConfig {
        override fun current() = "http://host:8000/"
        override fun update(value: String) {}
        override fun default() = "http://18.222.237.167:8000/"
        override fun reset() {}
    }

    private val activity: Activity = mock(Activity::class.java)

    private fun vm(
        sso: FakeSsoRepository = FakeSsoRepository(),
        store: FakeSsoStateStore = FakeSsoStateStore(),
        launcher: FakeSsoTabLauncher = FakeSsoTabLauncher(),
        passkey: FakePasskeyRepository = FakePasskeyRepository(),
    ) = LoginViewModel(
        authRepository = FakeAuthRepository(),
        serverUrlConfig = FakeServerUrlConfig(),
        authStateStore = FakeAuthStateStore(),
        savedStateHandle = SavedStateHandle(),
        ssoRepository = sso,
        ssoStateStore = store,
        ssoTabLauncher = launcher,
        passkeyRepository = passkey,
    )

    @Test
    fun probeSso_ssoOnly_hidesPasswordForm() = runTest(mainRule.dispatcher) {
        val sso = FakeSsoRepository().apply {
            infoResult = ApiResult.Success(SsoInfo(true, true, "http://h/saml/login", "Acme SSO", "saml"))
        }
        val v = vm(sso = sso)
        advanceUntilIdle()
        assertTrue(v.uiState.value.ssoOnly)
        assertFalse(v.uiState.value.submitEnabled) // password sign-in disabled when sso_only
        assertEquals("Acme SSO", v.uiState.value.ssoProviderName)
    }

    @Test
    fun probeSso_failure_fallsBackToPasswordForm() = runTest(mainRule.dispatcher) {
        val sso = FakeSsoRepository().apply { infoResult = ApiResult.Failure(ApiError(500, "x")) }
        val v = vm(sso = sso)
        advanceUntilIdle()
        assertFalse(v.uiState.value.ssoOnly)
        assertFalse(v.uiState.value.ssoAvailable)
    }

    @Test
    fun startSso_launchesTab_andPersistsState() = runTest(mainRule.dispatcher) {
        val launcher = FakeSsoTabLauncher(available = true)
        val store = FakeSsoStateStore()
        val v = vm(launcher = launcher, store = store)
        advanceUntilIdle()
        v.startSso(activity)
        advanceUntilIdle()
        assertEquals(1, launcher.launchCalls)
        assertTrue(store.peek() != null)
        assertTrue(v.uiState.value.ssoBusy)
    }

    @Test
    fun startSso_noBrowser_showsError_clearsState() = runTest(mainRule.dispatcher) {
        val launcher = FakeSsoTabLauncher(available = false)
        val store = FakeSsoStateStore()
        val v = vm(launcher = launcher, store = store)
        advanceUntilIdle()
        v.startSso(activity)
        advanceUntilIdle()
        assertFalse(v.uiState.value.ssoBusy)
        assertEquals("No browser available to complete sign-in.", v.uiState.value.error)
    }

    @Test
    fun onSsoRedirect_error_mapsToMessage() = runTest(mainRule.dispatcher) {
        val v = vm()
        advanceUntilIdle()
        val uri = mock(Uri::class.java)
        org.mockito.Mockito.`when`(uri.getQueryParameter("error")).thenReturn("sso_replay_detected")
        v.onSsoRedirect(uri)
        advanceUntilIdle()
        assertEquals("This sign-in link was already used. Please try again.", v.uiState.value.error)
    }

    @Test
    fun onSsoRedirect_success_emitsNavigateHome() = runTest(mainRule.dispatcher) {
        val sso = FakeSsoRepository()
        val v = vm(sso = sso)
        advanceUntilIdle()
        val uri = mock(Uri::class.java)
        org.mockito.Mockito.`when`(uri.getQueryParameter("error")).thenReturn(null)

        val effects = mutableListOf<LoginEffect>()
        val job = launch { v.effects.collect { effects.add(it) } }
        runCurrent()
        v.onSsoRedirect(uri)
        advanceUntilIdle()
        assertEquals(1, sso.finalizeCalls)
        assertTrue(effects.any { it is LoginEffect.NavigateHome })
        job.cancel()
    }

    @Test
    fun signInWithPasskey_requiresUsername() = runTest(mainRule.dispatcher) {
        val passkey = FakePasskeyRepository()
        val v = vm(passkey = passkey)
        advanceUntilIdle()
        v.signInWithPasskey(activity) // email is blank
        advanceUntilIdle()
        assertEquals(0, passkey.authCalls)
    }

    @Test
    fun signInWithPasskey_success_navigatesHome() = runTest(mainRule.dispatcher) {
        val passkey = FakePasskeyRepository().apply {
            authResult = ApiResult.Success(PasskeyAuthResult.Authenticated(com.testlogon.android.data.auth.User("u", "s", "i")))
        }
        val v = vm(passkey = passkey)
        advanceUntilIdle()
        v.onEmailChange("spannella@gmail.com")

        val effects = mutableListOf<LoginEffect>()
        val job = launch { v.effects.collect { effects.add(it) } }
        runCurrent()
        v.signInWithPasskey(activity)
        advanceUntilIdle()
        assertEquals("spannella@gmail.com", passkey.lastAuthUsername)
        assertTrue(effects.any { it is LoginEffect.NavigateHome })
        job.cancel()
    }

    @Test
    fun signInWithPasskey_cancelled_silentNoError() = runTest(mainRule.dispatcher) {
        val passkey = FakePasskeyRepository().apply {
            authResult = ApiResult.Success(PasskeyAuthResult.Cancelled)
        }
        val v = vm(passkey = passkey)
        advanceUntilIdle()
        v.onEmailChange("user")
        v.signInWithPasskey(activity)
        advanceUntilIdle()
        assertFalse(v.uiState.value.passkeyBusy)
        assertEquals(null, v.uiState.value.error)
    }
}
