package com.testlogon.android.feature.auth.passkey

import android.content.Context
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakePasskeyRepository
import com.testlogon.android.data.auth.RegisteredPasskey
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito.mock

class PasskeyRegisterViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val context: Context = mock(Context::class.java)

    @Test
    fun init_reflectsSupport() = runTest(mainRule.dispatcher) {
        val repo = FakePasskeyRepository().apply { supported = true }
        val v = PasskeyRegisterViewModel(repo)
        advanceUntilIdle()
        val s = v.uiState.value as PasskeyRegisterUiState.Idle
        assertTrue(s.supported)
    }

    @Test
    fun register_success_emitsSuccess() = runTest(mainRule.dispatcher) {
        val repo = FakePasskeyRepository().apply {
            registerResult = ApiResult.Success(RegisteredPasskey("cred_1", "Pixel"))
        }
        val v = PasskeyRegisterViewModel(repo)
        advanceUntilIdle()
        v.register(context, "Pixel")
        advanceUntilIdle()
        val s = v.uiState.value as PasskeyRegisterUiState.Success
        assertEquals("cred_1", s.passkey.credentialId)
    }

    @Test
    fun register_failure_emitsError() = runTest(mainRule.dispatcher) {
        val repo = FakePasskeyRepository().apply {
            registerResult = ApiResult.Failure(ApiError(0, "Passkeys aren't set up for this app yet."))
        }
        val v = PasskeyRegisterViewModel(repo)
        advanceUntilIdle()
        v.register(context, null)
        advanceUntilIdle()
        assertTrue(v.uiState.value is PasskeyRegisterUiState.Error)
        assertEquals(1, repo.registerCalls)
    }
}
