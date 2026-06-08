package com.testlogon.android.data.auth

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AuthRepositoryTest {

    private lateinit var api: FakeAuthApi
    private lateinit var store: FakeAuthStateStore
    private var cleared = 0
    private lateinit var repo: AuthRepositoryImpl

    @Before
    fun setUp() {
        api = FakeAuthApi()
        store = FakeAuthStateStore()
        cleared = 0
        repo = AuthRepositoryImpl(
            api = api,
            authStateStore = store,
            cookieCleaner = SessionCookieCleaner { cleared++ },
            errorParser = ApiErrorParser(Moshi.Builder().build()),
        )
    }

    @Test
    fun login_authenticated_oneStep_callsGetMe_andSetsAuthState() = runTest {
        api.sessionStartResult = {
            SessionStartResp(authRequired = false, sessionId = "sess_1", requiredFactors = emptyList())
        }
        api.meResult = { MeResp(userSub = "usr_1", sessionId = "sess_1", ip = "1.2.3.4") }

        val result = repo.login("alice@example.com", "pw")

        assertTrue(result is ApiResult.Success)
        val outcome = (result as ApiResult.Success).data
        assertTrue(outcome is LoginOutcome.Authenticated)
        assertEquals("usr_1", (outcome as LoginOutcome.Authenticated).user.userSub)
        assertEquals(1, store.setAuthenticatedCalls)
        // Request body carries the credentials in challenge_context.
        assertEquals(mapOf("username" to "alice@example.com", "password" to "pw"), api.lastStartBody?.challengeContext)
    }

    @Test
    fun login_mfaRequired_returnsChallengeAndFactors() = runTest {
        api.sessionStartResult = {
            SessionStartResp(
                authRequired = true,
                challengeId = "chl_1",
                requiredFactors = listOf("totp", "sms"),
                sessionId = null,
            )
        }

        val result = repo.login("alice@example.com", "pw")

        val outcome = (result as ApiResult.Success).data as LoginOutcome.MfaRequired
        assertEquals("chl_1", outcome.challengeId)
        assertEquals(listOf(MfaFactor.Totp, MfaFactor.Sms), outcome.factors)
        assertEquals(0, store.setAuthenticatedCalls)
    }

    @Test
    fun login_authRequiredFalse_butNoSessionId_isNotAuthenticated() = runTest {
        api.sessionStartResult = {
            SessionStartResp(
                authRequired = false,
                sessionId = null,
                challengeId = "chl_1",
                requiredFactors = listOf("totp"),
            )
        }

        val outcome = (repo.login("a@b.com", "pw") as ApiResult.Success).data
        assertTrue(outcome is LoginOutcome.MfaRequired)
        assertEquals(0, api.meCalls)
    }

    @Test
    fun login_unknownFactor_isRetained() = runTest {
        api.sessionStartResult = {
            SessionStartResp(authRequired = true, challengeId = "chl_1", requiredFactors = listOf("totp", "webauthn"))
        }

        val outcome = (repo.login("a@b.com", "pw") as ApiResult.Success).data as LoginOutcome.MfaRequired
        assertEquals(listOf(MfaFactor.Totp, MfaFactor.Unknown("webauthn")), outcome.factors)
    }

    @Test
    fun login_malformed_mfa_noChallengeId_failsClosed() = runTest {
        api.sessionStartResult = {
            SessionStartResp(authRequired = true, challengeId = null, requiredFactors = listOf("totp"))
        }

        val result = repo.login("a@b.com", "pw")
        assertTrue(result is ApiResult.Failure)
        assertEquals("malformed_mfa", (result as ApiResult.Failure).error.code)
    }

    @Test
    fun login_httpError_passesThroughAsFailure() = runTest {
        api.sessionStartResult = { throw FakeAuthApi.httpError(401, """{"detail":"bad creds"}""") }

        val result = repo.login("a@b.com", "pw")
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun login_ioError_isNetworkError() = runTest {
        api.sessionStartResult = { throw java.io.IOException("offline") }
        assertTrue(repo.login("a@b.com", "pw") is ApiResult.NetworkError)
    }

    @Test
    fun login_timeout_isNetworkError_withTimeoutFlag() = runTest {
        api.sessionStartResult = { throw java.net.SocketTimeoutException("slow") }
        val result = repo.login("a@b.com", "pw")
        assertTrue(result is ApiResult.NetworkError)
        assertTrue((result as ApiResult.NetworkError).isTimeout)
    }

    @Test
    fun verifyTotp_lastFactor_finalizesAndAuthenticates() = runTest {
        api.totpResult = { MfaVerifyResp(status = "ok", remainingFactors = emptyList()) }
        api.finalizeResult = { SessionFinalizeResp(status = "ok", sessionId = "sess_1") }
        api.meResult = { MeResp(userSub = "usr_1", sessionId = "sess_1", ip = "1.2.3.4") }

        val result = repo.verifyTotp("chl_1", "123456")

        val outcome = (result as ApiResult.Success).data
        assertTrue(outcome is MfaVerifyOutcome.Authenticated)
        assertEquals(1, api.finalizeCalls)
        assertEquals("123456", api.lastTotpBody?.totpCode)
    }

    @Test
    fun verifyTotp_factorsRemaining_doesNotFinalize() = runTest {
        api.totpResult = { MfaVerifyResp(status = "pending", remainingFactors = listOf("sms")) }

        val outcome = (repo.verifyTotp("chl_1", "123456") as ApiResult.Success).data
        assertEquals(MfaVerifyOutcome.FactorsRemaining(listOf(MfaFactor.Sms)), outcome)
        assertEquals(0, api.finalizeCalls)
    }

    @Test
    fun verifyTotp_blankCode_shortCircuits_noNetworkCall() = runTest {
        val result = repo.verifyTotp("chl_1", "   ")
        assertTrue(result is ApiResult.Failure)
        assertEquals(0, api.verifyTotpCalls)
    }

    @Test
    fun verifyTotp_finalizePending_resyncsRemaining() = runTest {
        api.totpResult = { MfaVerifyResp(status = "ok", remainingFactors = emptyList()) }
        api.finalizeResult = {
            SessionFinalizeResp(status = "pending", sessionId = null, requiredFactors = listOf("sms"))
        }

        val outcome = (repo.verifyTotp("chl_1", "123456") as ApiResult.Success).data
        assertEquals(MfaVerifyOutcome.FactorsRemaining(listOf(MfaFactor.Sms)), outcome)
        assertEquals(0, api.meCalls)
    }

    @Test
    fun beginSms_returnsMaskedDestinations() = runTest {
        api.smsBeginResult = { ChallengeResp(challengeId = "chl_1", sentTo = listOf("+1•••1234")) }
        val result = repo.beginSms("chl_1")
        assertEquals(listOf("+1•••1234"), (result as ApiResult.Success).data)
    }

    @Test
    fun getMe_definitive401_clearsAuthState() = runTest {
        store.setAuthenticated("old")
        api.meResult = { throw FakeAuthApi.httpError(401) }

        val result = repo.getMe()
        assertTrue(result is ApiResult.Failure)
        assertEquals(1, store.clearCalls)
        assertNull(repo.cachedUser.value)
    }

    @Test
    fun getMe_serverError_doesNotClearAuthState() = runTest {
        store.setAuthenticated("usr_1")
        api.meResult = { throw FakeAuthApi.httpError(500) }

        repo.getMe()
        assertEquals(0, store.clearCalls)
    }

    @Test
    fun logout_alwaysClearsLocally_evenWhenServerFails() = runTest {
        api.logoutResult = { throw FakeAuthApi.httpError(500) }
        store.setAuthenticated("usr_1")

        val result = repo.logout()
        assertTrue(result is ApiResult.Success)
        assertEquals(1, cleared)
        assertEquals(1, store.clearCalls)
    }
}
