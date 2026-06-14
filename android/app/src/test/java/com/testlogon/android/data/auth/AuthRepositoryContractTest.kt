package com.testlogon.android.data.auth

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.FixtureName
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.InMemoryCookieJar
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-047 — AuthRepository contract tests against a real MockWebServer + the production
 * Retrofit/Moshi/OkHttp stack and fixtures (AND-046). Asserts both the typed outcomes and the exact
 * bytes on the wire.
 */
class AuthRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private val cookieJar = InMemoryCookieJar()
    private val store = FakeAuthStateStore()

    private fun repo(): AuthRepositoryImpl {
        val api = backend.retrofit(moshi, client = defaultTestClient(cookieJar)).create(AuthApi::class.java)
        return AuthRepositoryImpl(
            api = api,
            authStateStore = store,
            cookieCleaner = SessionCookieCleaner { cookieJar.clear() },
            errorParser = ApiErrorParser(moshi),
            authAreaCache = AuthAreaCache(),
        )
    }

    // ── login branches ──

    @Test
    fun login_noMfa_authenticates_andCallsMe() = runTest {
        backend.enqueue(Fixtures.ok(FixtureName.SESSION_START_NO_MFA))
        backend.enqueue(Fixtures.ok(FixtureName.ME))

        val result = repo().login("alice@example.com", "pw")

        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data is LoginOutcome.Authenticated)
        val start = backend.takeRequest()
        assertEquals("/ui/session/start", start.requestUrl?.encodedPath)
        @Suppress("UNCHECKED_CAST")
        val ctx = start.bodyJson()["challenge_context"] as Map<String, Any?>
        assertEquals("alice@example.com", ctx["username"])
        assertEquals("/ui/me", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun login_mfaRequired_returnsChallengeAndFactors() = runTest {
        backend.enqueue(Fixtures.ok(FixtureName.SESSION_START_MFA))
        val outcome = (repo().login("a@b.com", "pw") as ApiResult.Success).data
        assertTrue(outcome is LoginOutcome.MfaRequired)
        outcome as LoginOutcome.MfaRequired
        assertEquals("chal_01HZX", outcome.challengeId)
        assertEquals(listOf(MfaFactor.Totp), outcome.factors)
    }

    @Test
    fun login_401_mapsToFailure_credentialError() = runTest {
        backend.enqueue(Fixtures.error("\"Invalid credentials\"", 401))
        val result = repo().login("a@b.com", "wrong")
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
    }

    // ── factor verify + finalize ──

    @Test
    fun verifyTotp_lastFactor_finalizes_andAuthenticates() = runTest {
        backend.enqueue(Fixtures.ok(FixtureName.MFA_TOTP_VERIFY_OK))
        backend.enqueue(Fixtures.ok(FixtureName.SESSION_FINALIZE_OK))
        backend.enqueue(Fixtures.ok(FixtureName.ME))

        val result = repo().verifyTotp("chal_01HZX", "123456")

        assertTrue((result as ApiResult.Success).data is MfaVerifyOutcome.Authenticated)
        val verify = backend.takeRequest()
        assertEquals("/ui/mfa/totp/verify", verify.requestUrl?.encodedPath)
        assertEquals("123456", verify.bodyJson()["totp_code"])
        assertEquals("/ui/session/finalize", backend.takeRequest().requestUrl?.encodedPath)
        assertEquals("/ui/me", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun verifyTotp_factorsRemaining_doesNotFinalize() = runTest {
        backend.enqueue(Fixtures.ok(FixtureName.MFA_TOTP_VERIFY_REMAINING_SMS))
        val outcome = (repo().verifyTotp("chal_01HZX", "123456") as ApiResult.Success).data
        assertEquals(MfaVerifyOutcome.FactorsRemaining(listOf(MfaFactor.Sms)), outcome)
        assertEquals("/ui/mfa/totp/verify", backend.takeRequest().requestUrl?.encodedPath)
        // No further request enqueued/consumed -> finalize was not called.
        assertEquals(1, backend.requestCount)
    }

    @Test
    fun beginSms_then_verifySms_sendsCodeField() = runTest {
        backend.enqueue(Fixtures.ok(FixtureName.MFA_SMS_BEGIN_OK))
        val repo = repo()
        val begin = repo.beginSms("chal_01HZX")
        assertTrue(begin is ApiResult.Success)
        val beginReq = backend.takeRequest()
        assertEquals("/ui/mfa/sms/begin", beginReq.requestUrl?.encodedPath)
        assertEquals("chal_01HZX", beginReq.bodyJson()["challenge_id"])

        backend.enqueue(Fixtures.ok(FixtureName.MFA_SMS_VERIFY_OK))
        backend.enqueue(Fixtures.ok(FixtureName.SESSION_FINALIZE_OK))
        backend.enqueue(Fixtures.ok(FixtureName.ME))
        val verify = repo.verifySms("chal_01HZX", "654321")
        assertTrue((verify as ApiResult.Success).data is MfaVerifyOutcome.Authenticated)
        val verifyReq = backend.takeRequest()
        assertEquals("/ui/mfa/sms/verify", verifyReq.requestUrl?.encodedPath)
        assertEquals("654321", verifyReq.bodyJson()["code"])
    }

    // ── refresh, logout, errors ──

    @Test
    fun logout_postsLogout_andClearsLocalState() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ok"}"""))
        store.setAuthenticated("usr_42")
        val result = repo().logout()
        assertTrue(result is ApiResult.Success)
        assertEquals("/ui/session/logout", backend.takeRequest().requestUrl?.encodedPath)
        assertTrue(store.clearCalls >= 1)
    }

    @Test
    fun getMe_definitive401_clearsAuthState() = runTest {
        store.setAuthenticated("usr_42")
        backend.enqueue(Fixtures.error("\"Not authenticated\"", 401))
        val result = repo().getMe()
        assertTrue(result is ApiResult.Failure)
        assertEquals(1, store.clearCalls)
    }

    @Test
    fun errorMapping_detailVariants_neverThrow() = runTest {
        // string
        backend.enqueue(Fixtures.ok(FixtureName.SESSION_START_NO_MFA))
        backend.enqueue(Fixtures.error("[{\"loc\":[\"body\"],\"msg\":\"bad\",\"type\":\"missing\"}]", 422))
        // session/start success then getMe 422 array -> Failure (422)
        val result = repo().login("a@b.com", "pw")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun networkTimeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().login("a@b.com", "pw")
        assertTrue(result is ApiResult.NetworkError)
    }

    @Test
    fun malformedBody_mapsToFailure_orNetwork_notCrash() = runTest {
        backend.enqueue(Fixtures.malformed())
        val result = repo().login("a@b.com", "pw")
        // Moshi parse failure on a 200 surfaces as a thrown error folded into the result; assert no crash.
        assertTrue(result is ApiResult.Failure || result is ApiResult.NetworkError)
    }
}
