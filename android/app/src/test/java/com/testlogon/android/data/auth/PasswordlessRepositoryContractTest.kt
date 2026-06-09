package com.testlogon.android.data.auth

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.InMemoryCookieJar
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-060/061 — PasswordlessRepository contract tests against a real MockWebServer + the production
 * Retrofit/Moshi stack. Asserts the exact JSON on the wire (request keys), paths, and that a verify
 * Set-Cookie populates the shared cookie jar.
 */
class PasswordlessRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private val cookieJar = InMemoryCookieJar()

    private fun repo(): PasswordlessRepositoryImpl {
        val api = backend.retrofit(moshi, client = defaultTestClient(cookieJar)).create(AuthApi::class.java)
        val authRepo = AuthRepositoryImpl(
            api = api,
            authStateStore = FakeAuthStateStore(),
            cookieCleaner = SessionCookieCleaner { },
            errorParser = ApiErrorParser(moshi),
            authAreaCache = AuthAreaCache(),
        )
        return PasswordlessRepositoryImpl(api = api, authRepository = authRepo, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun start_sendsUsernameKey_notEmail() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"sent","sent_to":["u***@example.com"]}"""))
        val result = repo().start("alice@example.com")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/passwordless/start", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("alice@example.com", body["username"])
        assertNull(body["email"]) // wire key is username, never email
    }

    @Test
    fun verify_sendsTokenBody_andPopulatesCookieJar() = runTest {
        // verify response: full session + Set-Cookie; then getMe returns a principal.
        backend.enqueue(
            Fixtures.okBody(
                """{"status":"ok","session_id":"sess_1","auth_required":false,""" +
                    """"challenge_id":null,"required_factors":[]}""",
            ).addHeader("Set-Cookie", "tl_session=sess-1; Path=/; HttpOnly")
                .addHeader("Set-Cookie", "ui_csrf=${Fixtures.DEFAULT_CSRF}; Path=/"),
        )
        backend.enqueue(Fixtures.okBody("""{"user_sub":"usr_1","session_id":"sess_1","ip":"1.2.3.4"}"""))

        val result = repo().verify("tok_123")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data is PasswordlessVerified.Authenticated)

        val verifyReq = backend.takeRequest()
        assertEquals("/ui/passwordless/verify", verifyReq.requestUrl?.encodedPath)
        assertEquals("tok_123", verifyReq.bodyJson()["token"])
        // The shared cookie jar captured the session + ui_csrf from the verify response.
        assertEquals(Fixtures.DEFAULT_CSRF, cookieJar.cookieValue("ui_csrf"))
    }

    @Test
    fun verify_422_mapsToFailure() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["body","token"],"msg":"field required","type":"value_error.missing"}]""", 422),
        )
        val result = repo().verify("tok")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
