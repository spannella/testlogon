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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-053/054/055 — RegisterRepository contract tests against a real MockWebServer + the production
 * Retrofit/Moshi stack. Asserts both the exact JSON on the wire and the typed outcome mapping.
 */
class RegisterRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private val cookieJar = InMemoryCookieJar()
    private val store = FakeAuthStateStore()

    private fun api() =
        backend.retrofit(moshi, client = defaultTestClient(cookieJar)).create(AuthApi::class.java)

    private fun repo(): RegisterRepositoryImpl {
        val api = api()
        val authRepo = AuthRepositoryImpl(
            api = api,
            authStateStore = store,
            cookieCleaner = SessionCookieCleaner { cookieJar.clear() },
            errorParser = ApiErrorParser(moshi),
            authAreaCache = AuthAreaCache(),
        )
        return RegisterRepositoryImpl(
            api = api,
            authRepository = authRepo,
            errorParser = ApiErrorParser(moshi),
        )
    }

    // ── start ──

    @Test
    fun start_verificationRequired_mapsOutcome_andOmitsDeliveryAndPhone() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"status":"verification_sent","verification_required":true,""" +
                    """"delivery_medium":"email","delivery_destination":"a***@example.com","session_id":null}""",
            ),
        )
        val result = repo().registerStart(
            RegisterStartReq(
                fullName = "Ada Lovelace",
                email = "ada@example.com",
                password = "Ada!Lovelace2026",
                confirmPassword = "Ada!Lovelace2026",
                enableTotpMfa = true,
            ),
        )
        assertTrue(result is ApiResult.Success)
        val outcome = (result as ApiResult.Success).data
        assertTrue(outcome is RegisterStartOutcome.VerificationRequired)
        outcome as RegisterStartOutcome.VerificationRequired
        assertEquals("ada@example.com", outcome.email)
        assertEquals("email", outcome.deliveryMedium)

        val req = backend.takeRequest()
        assertEquals("/ui/register/start", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("Ada Lovelace", body["full_name"])
        assertEquals("ada@example.com", body["email"])
        assertEquals("Ada!Lovelace2026", body["password"])
        assertEquals("Ada!Lovelace2026", body["confirm_password"])
        assertEquals(false, body["enable_sms_mfa"])
        assertEquals(true, body["enable_totp_mfa"])
        assertFalse(body.containsKey("delivery_method"))
        // phone omitted (null) when SMS-MFA off
        assertNull(body["phone"])
    }

    @Test
    fun start_smsMfa_includesPhone() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"status":"verification_sent","verification_required":true}"""),
        )
        repo().registerStart(
            RegisterStartReq(
                fullName = "Ada",
                email = "ada@example.com",
                password = "Ada!Lovelace2026",
                confirmPassword = "Ada!Lovelace2026",
                phone = "+15551234567",
                enableSmsMfa = true,
            ),
        )
        val body = backend.takeRequest().bodyJson()
        assertEquals(true, body["enable_sms_mfa"])
        assertEquals("+15551234567", body["phone"])
    }

    @Test
    fun start_noVerification_noSession_isVerifiedSignIn() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"created","verification_required":false}"""))
        val result = repo().registerStart(
            RegisterStartReq("Ada", "ada@example.com", "Ada!Lovelace2026", "Ada!Lovelace2026"),
        )
        assertEquals(
            RegisterStartOutcome.VerifiedSignIn,
            (result as ApiResult.Success).data,
        )
    }

    @Test
    fun start_noVerification_withSession_authenticatesViaGetMe() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"status":"created","verification_required":false,"session_id":"sess_1"}"""),
        )
        backend.enqueue(Fixtures.okBody("""{"user_sub":"u1","session_id":"sess_1","ip":"1.2.3.4"}"""))
        val result = repo().registerStart(
            RegisterStartReq("Ada", "ada@example.com", "Ada!Lovelace2026", "Ada!Lovelace2026"),
        )
        assertTrue((result as ApiResult.Success).data is RegisterStartOutcome.Authenticated)
        assertEquals("/ui/register/start", backend.takeRequest().requestUrl?.encodedPath)
        assertEquals("/ui/me", backend.takeRequest().requestUrl?.encodedPath)
        assertTrue(store.setAuthenticatedCalls >= 1)
    }

    @Test
    fun start_422_mapsToFailure_withDetailString() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["body","email"],"msg":"field required","type":"value_error.missing"}]""", 422),
        )
        val result = repo().registerStart(
            RegisterStartReq("Ada", "ada@example.com", "Ada!Lovelace2026", "Ada!Lovelace2026"),
        )
        assertTrue(result is ApiResult.Failure)
        result as ApiResult.Failure
        assertEquals(422, result.error.status)
        assertEquals("field required", result.error.message)
    }

    @Test
    fun start_429_carriesServerDetailString() = runTest {
        backend.enqueue(Fixtures.error("\"Too many registration attempts. Please wait and try again.\"", 429))
        val result = repo().registerStart(
            RegisterStartReq("Ada", "ada@example.com", "Ada!Lovelace2026", "Ada!Lovelace2026"),
        )
        assertTrue(result is ApiResult.Failure)
        assertEquals(429, (result as ApiResult.Failure).error.status)
        assertEquals("Too many registration attempts. Please wait and try again.", result.error.message)
    }

    @Test
    fun start_timeout_mapsToNetworkError_singleRequest() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().registerStart(
            RegisterStartReq("Ada", "ada@example.com", "Ada!Lovelace2026", "Ada!Lovelace2026"),
        )
        assertTrue(result is ApiResult.NetworkError)
        assertEquals(1, backend.requestCount)
    }

    // ── confirm ──

    @Test
    fun confirm_noSession_isVerifiedSignIn_sendsEmailAndCode() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"confirmed","session_id":null}"""))
        val result = repo().confirm(RegisterConfirmReq("jane@example.com", "123456"))
        assertEquals(
            RegisterConfirmOutcome.VerifiedSignIn("jane@example.com"),
            (result as ApiResult.Success).data,
        )
        val body = backend.takeRequest().bodyJson()
        assertEquals("jane@example.com", body["email"])
        assertEquals("123456", body["confirmation_code"])
    }

    @Test
    fun confirm_session_noMfa_authenticated_emptyHandoff() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ok","session_id":"sess_1","mfa_setup":[]}"""))
        backend.enqueue(Fixtures.okBody("""{"user_sub":"u1","session_id":"sess_1","ip":"1.2.3.4"}"""))
        val outcome = (repo().confirm(RegisterConfirmReq("jane@example.com", "123456")) as ApiResult.Success).data
        assertTrue(outcome is RegisterConfirmOutcome.Authenticated)
        assertFalse((outcome as RegisterConfirmOutcome.Authenticated).handoff.isRequired)
    }

    @Test
    fun confirm_session_withMfa_authenticatedWithHandoff() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"status":"ok","session_id":"sess_1","mfa_setup":["totp"],"sms_phone":null}""",
            ),
        )
        backend.enqueue(Fixtures.okBody("""{"user_sub":"u1","session_id":"sess_1","ip":"1.2.3.4"}"""))
        val outcome = (repo().confirm(RegisterConfirmReq("jane@example.com", "123456")) as ApiResult.Success).data
        outcome as RegisterConfirmOutcome.Authenticated
        assertEquals(listOf(MfaSetupFactor.Totp), outcome.handoff.factors)
    }

    @Test
    fun confirm_wrongCode_4xx_mapsToFailureWithDetail() = runTest {
        backend.enqueue(Fixtures.error("\"That code isn't correct.\"", 400))
        val result = repo().confirm(RegisterConfirmReq("jane@example.com", "000000"))
        assertTrue(result is ApiResult.Failure)
        assertEquals("That code isn't correct.", (result as ApiResult.Failure).error.message)
    }

    // ── resend + check ──

    @Test
    fun resend_sendsExpectedBody() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"status":"sent","delivery_medium":"email","delivery_destination":"j**@example.com"}"""),
        )
        val result = repo().resend(RegisterResendReq(email = "jane@example.com"))
        assertTrue(result is ApiResult.Success)
        val body = backend.takeRequest().bodyJson()
        assertEquals("jane@example.com", body["email"])
        assertEquals("email", body["delivery_method"])
        assertEquals(false, body["enable_sms_mfa"])
    }

    @Test
    fun checkEmail_available_andTaken() = runTest {
        backend.enqueue(Fixtures.okBody("""{"available":true,"status":"ok"}"""))
        assertEquals(true, (repo().checkEmail("free@example.com") as ApiResult.Success).data)
        val req = backend.takeRequest()
        assertEquals("/ui/register/check", req.requestUrl?.encodedPath)
        assertEquals("free@example.com", req.bodyJson()["email"])

        backend.enqueue(Fixtures.okBody("""{"available":false,"status":"taken"}"""))
        assertEquals(false, (repo().checkEmail("taken@example.com") as ApiResult.Success).data)
    }

    @Test
    fun checkEmail_error_stitchesToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"rate limited\"", 429))
        val result = repo().checkEmail("x@example.com")
        assertTrue(result is ApiResult.Failure)
    }
}
