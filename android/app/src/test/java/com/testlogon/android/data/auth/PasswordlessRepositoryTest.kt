package com.testlogon.android.data.auth

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * AND-060/061 — PasswordlessRepository unit tests over [FakeAuthApi] + a real [AuthRepositoryImpl]
 * (so the full-session branch exercises the actual getMe / AuthStateStore wiring).
 */
class PasswordlessRepositoryTest {

    private lateinit var api: FakeAuthApi
    private lateinit var store: FakeAuthStateStore
    private lateinit var repo: PasswordlessRepositoryImpl

    @Before
    fun setUp() {
        api = FakeAuthApi()
        store = FakeAuthStateStore()
        val authRepo = AuthRepositoryImpl(
            api = api,
            authStateStore = store,
            cookieCleaner = SessionCookieCleaner { },
            errorParser = ApiErrorParser(Moshi.Builder().build()),
            authAreaCache = AuthAreaCache(),
        )
        repo = PasswordlessRepositoryImpl(
            api = api,
            authRepository = authRepo,
            errorParser = ApiErrorParser(Moshi.Builder().build()),
        )
    }

    // ── start ──

    @Test
    fun start_success_mapsStatusAndSentTo_andTrimsUsername() = runTest {
        api.passwordlessStartResult = { PasswordlessStartResp(status = "sent", sentTo = listOf("u***@example.com")) }
        val result = repo.start("  alice@example.com  ")
        assertTrue(result is ApiResult.Success)
        val data = (result as ApiResult.Success).data
        assertEquals("sent", data.status)
        assertEquals(listOf("u***@example.com"), data.sentTo)
        assertEquals("alice@example.com", api.lastPasswordlessStartBody?.username)
    }

    @Test
    fun start_nullSentTo_mapsToEmptyList() = runTest {
        api.passwordlessStartResult = { PasswordlessStartResp(status = "sent", sentTo = null) }
        val data = (repo.start("alice") as ApiResult.Success).data
        assertTrue(data.sentTo.isEmpty())
    }

    @Test
    fun start_422_mapsToFailure() = runTest {
        api.passwordlessStartResult = { throw FakeAuthApi.httpError(422) }
        val result = repo.start("x")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun start_io_mapsToNetworkError() = runTest {
        api.passwordlessStartResult = { throw java.io.IOException("boom") }
        assertTrue(repo.start("alice") is ApiResult.NetworkError)
    }

    // ── verify ──

    @Test
    fun verify_fullSession_runsGetMe_setsAuthState_andReturnsAuthenticated() = runTest {
        api.passwordlessVerifyResult = {
            PasswordlessVerifyResp(status = "ok", sessionId = "sess_1", authRequired = false)
        }
        api.meResult = { MeResp(userSub = "usr_1", sessionId = "sess_1", ip = "1.2.3.4") }

        val result = repo.verify("tok_123")

        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data is PasswordlessVerified.Authenticated)
        assertEquals(1, api.meCalls)
        assertEquals(1, store.setAuthenticatedCalls)
        assertEquals("tok_123", api.lastPasswordlessVerifyBody?.token)
    }

    @Test
    fun verify_mfaRequired_returnsChallengeAndFactors_noGetMe() = runTest {
        api.passwordlessVerifyResult = {
            PasswordlessVerifyResp(
                status = "mfa_required",
                sessionId = null,
                authRequired = true,
                challengeId = "chg_8f2",
                requiredFactors = listOf("totp"),
            )
        }
        val outcome = (repo.verify("tok") as ApiResult.Success).data
        assertTrue(outcome is PasswordlessVerified.MfaRequired)
        outcome as PasswordlessVerified.MfaRequired
        assertEquals("chg_8f2", outcome.challengeId)
        assertEquals(listOf("totp"), outcome.requiredFactors)
        assertEquals(0, api.meCalls)
    }

    @Test
    fun verify_nonOkNonMfaBody_mapsToInvalid() = runTest {
        api.passwordlessVerifyResult = {
            PasswordlessVerifyResp(status = "failed", sessionId = null, authRequired = false)
        }
        val outcome = (repo.verify("tok") as ApiResult.Success).data
        assertTrue(outcome is PasswordlessVerified.Invalid)
    }

    @Test
    fun verify_blankToken_shortCircuits_withoutNetworkCall() = runTest {
        val result = repo.verify("   ")
        assertTrue(result is ApiResult.Failure)
        assertEquals("missing_token", (result as ApiResult.Failure).error.code)
        assertEquals(0, api.passwordlessVerifyCalls)
    }

    @Test
    fun verify_422_mapsToFailure() = runTest {
        api.passwordlessVerifyResult = { throw FakeAuthApi.httpError(422) }
        val result = repo.verify("tok")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun verify_io_mapsToNetworkError_noAutoRetry() = runTest {
        api.passwordlessVerifyResult = { throw java.net.SocketTimeoutException() }
        assertTrue(repo.verify("tok") is ApiResult.NetworkError)
        assertEquals(1, api.passwordlessVerifyCalls)
    }
}
