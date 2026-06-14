package com.testlogon.android.data.auth

import android.content.Context
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.mock

/** AND-062 — PasskeyRepository orchestration: begin → Credential Manager → finish, and mappings. */
class PasskeyRepositoryTest {

    private val moshi = Moshi.Builder().build()
    private val api = FakeAuthApi()
    private val manager = FakePasskeyManager()
    private val authRepo = FakeAuthRepository()
    private val context: Context = mock(Context::class.java)

    private fun repo() = PasskeyRepositoryImpl(api, manager, authRepo, ApiErrorParser(moshi), moshi)

    @Test
    fun register_happyPath_forwardsOptions_andSendsCredentialAndLabel() = runTest {
        api.webauthnRegisterBeginResult = {
            WebAuthnRegisterBeginResp(options = mapOf("challenge" to "abc", "rp" to mapOf("id" to "x")))
        }
        api.webauthnRegisterFinishResult = { WebAuthnRegisterFinishResp(credentialId = "cred_1") }
        manager.createOutcome = PasskeyOutcome.Success("""{"id":"cred_raw"}""")

        val r = repo().registerPasskey(context, label = "Pixel 8")
        assertTrue(r is ApiResult.Success)
        assertEquals("cred_1", (r as ApiResult.Success).data.credentialId)
        assertEquals("Pixel 8", r.data.label)

        // Options forwarded to Credential Manager without field loss.
        assertTrue(manager.lastCreateRequestJson!!.contains("\"challenge\":\"abc\""))
        // finish carried the credential object + label.
        assertEquals("Pixel 8", api.lastWebauthnRegisterFinishBody?.label)
        assertEquals("cred_raw", api.lastWebauthnRegisterFinishBody?.credential?.get("id"))
        assertEquals(1, api.webauthnRegisterFinishCalls)
    }

    @Test
    fun register_cancellation_neverCallsFinish() = runTest {
        api.webauthnRegisterBeginResult = { WebAuthnRegisterBeginResp(options = mapOf("a" to 1)) }
        manager.createOutcome = PasskeyOutcome.Cancelled

        val r = repo().registerPasskey(context, label = null)
        assertTrue(r is ApiResult.Failure)
        assertEquals(0, api.webauthnRegisterFinishCalls)
    }

    @Test
    fun authenticate_happyPath_sendsUsernameAndCredential_thenAuthenticated() = runTest {
        api.webauthnAuthBeginResult = { WebAuthnAuthBeginResp(options = mapOf("challenge" to "z")) }
        api.webauthnAuthFinishResult = { WebAuthnAuthFinishResp(status = "ok", sessionId = "sess_1") }
        manager.getOutcome = PasskeyOutcome.Success("""{"id":"assert_1"}""")

        val r = repo().authenticateWithPasskey(context, "spannella@gmail.com")
        assertTrue(r is ApiResult.Success)
        assertTrue((r as ApiResult.Success).data is PasskeyAuthResult.Authenticated)
        assertEquals("spannella@gmail.com", api.lastWebauthnAuthBeginBody?.username)
        assertEquals("spannella@gmail.com", api.lastWebauthnAuthFinishBody?.username)
        assertEquals("assert_1", api.lastWebauthnAuthFinishBody?.credential?.get("id"))
    }

    @Test
    fun authenticate_nonOkStatus_isFailure_notSuccess() = runTest {
        api.webauthnAuthBeginResult = { WebAuthnAuthBeginResp(options = mapOf("c" to "1")) }
        api.webauthnAuthFinishResult = { WebAuthnAuthFinishResp(status = "failed", sessionId = null) }
        manager.getOutcome = PasskeyOutcome.Success("""{"id":"a"}""")

        val r = repo().authenticateWithPasskey(context, "user")
        assertTrue(r is ApiResult.Failure)
    }

    @Test
    fun authenticate_cancellation_returnsCancelled_neverCallsFinish() = runTest {
        api.webauthnAuthBeginResult = { WebAuthnAuthBeginResp(options = mapOf("c" to "1")) }
        manager.getOutcome = PasskeyOutcome.Cancelled

        val r = repo().authenticateWithPasskey(context, "user")
        assertTrue(r is ApiResult.Success)
        assertTrue((r as ApiResult.Success).data is PasskeyAuthResult.Cancelled)
        assertEquals(0, api.webauthnAuthFinishCalls)
    }

    @Test
    fun authenticate_noCredential_mapsToFailure_noFinish() = runTest {
        api.webauthnAuthBeginResult = { WebAuthnAuthBeginResp(options = mapOf("c" to "1")) }
        manager.getOutcome = PasskeyOutcome.NoCredential

        val r = repo().authenticateWithPasskey(context, "user")
        assertTrue(r is ApiResult.Failure)
        assertEquals("no_credential", (r as ApiResult.Failure).error.code)
        assertEquals(0, api.webauthnAuthFinishCalls)
    }

    @Test
    fun authenticate_blankUsername_shortCircuits_noNetwork() = runTest {
        val r = repo().authenticateWithPasskey(context, "   ")
        assertTrue(r is ApiResult.Failure)
        assertEquals(0, api.webauthnAuthBeginCalls)
    }
}
