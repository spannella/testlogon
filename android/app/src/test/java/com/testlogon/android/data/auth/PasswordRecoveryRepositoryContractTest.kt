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
 * AND-057/058/059 — PasswordRecoveryRepository contract tests against a real MockWebServer + the
 * production Retrofit/Moshi stack. Asserts both the exact JSON on the wire and the typed mapping.
 */
class PasswordRecoveryRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private val cookieJar = InMemoryCookieJar()

    private fun repo(): PasswordRecoveryRepositoryImpl {
        val api = backend.retrofit(moshi, client = defaultTestClient(cookieJar)).create(AuthApi::class.java)
        return PasswordRecoveryRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    // ── start ──

    @Test
    fun start_challenge_mapsOutcome_andSendsTrimmedUsername() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"status":"challenge_sent","challenge_id":"pwr_1","required_factors":["sms"],""" +
                    """"delivery_medium":"sms","delivery_destination":"+1 ••• ••• 4821"}""",
            ),
        )
        val result = repo().start("  alice@example.com  ")
        assertTrue(result is ApiResult.Success)
        val outcome = (result as ApiResult.Success).data
        assertTrue(outcome is RecoveryStartOutcome.Challenge)
        outcome as RecoveryStartOutcome.Challenge
        assertEquals("pwr_1", outcome.challengeId)
        assertEquals(listOf(RecoveryFactor.Sms), outcome.requiredFactors)
        assertEquals("sms", outcome.deliveryMedium)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/password-recovery/start", req.requestUrl?.encodedPath)
        assertEquals("alice@example.com", req.bodyJson()["username"])
    }

    @Test
    fun start_noChallenge_isSent() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"status":"ok","required_factors":[],"delivery_medium":"email"}"""),
        )
        val outcome = (repo().start("alice") as ApiResult.Success).data
        assertTrue(outcome is RecoveryStartOutcome.Sent)
        assertEquals("email", (outcome as RecoveryStartOutcome.Sent).deliveryMedium)
    }

    @Test
    fun start_422_mapsToFailure() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["body","username"],"msg":"field required","type":"value_error.missing"}]""", 422),
        )
        val result = repo().start("x")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun start_timeout_mapsToNetworkError_singleRequest() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().start("alice")
        assertTrue(result is ApiResult.NetworkError)
        assertEquals(1, backend.requestCount)
    }

    // ── begin (path + short-circuit) ──

    @Test
    fun begin_email_hitsCorrectPath_withUsernameAndChallengeId() = runTest {
        backend.enqueue(Fixtures.okBody("""{"challenge_id":"pwr_1","sent_to":["a•••@example.com"]}"""))
        val result = repo().beginChallenge(RecoveryFactor.Email, "alice", "pwr_1")
        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("a•••@example.com"), (result as ApiResult.Success).data.maskedDestinations)
        val req = backend.takeRequest()
        assertEquals("/ui/password-recovery/challenge/email/begin", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("alice", body["username"])
        assertEquals("pwr_1", body["challenge_id"])
    }

    @Test
    fun begin_totp_makesNoNetworkCall() = runTest {
        val result = repo().beginChallenge(RecoveryFactor.Totp, "alice", "pwr_1")
        assertTrue(result is ApiResult.Success)
        assertEquals(0, backend.requestCount)
    }

    // ── verify (per-factor path + body field) ──

    @Test
    fun verify_sms_usesCodeField_andSmsPath() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ok","remaining_factors":[]}"""))
        val result = repo().verifyChallenge(RecoveryFactor.Sms, "alice", "pwr_1", " 482913 ")
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("/ui/password-recovery/challenge/sms/verify", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("alice", body["username"])
        assertEquals("pwr_1", body["challenge_id"])
        assertEquals("482913", body["code"]) // trimmed
        assertNull(body["totp_code"])
    }

    @Test
    fun verify_totp_usesTotpCodeField_andTotpPath() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ok","remaining_factors":[]}"""))
        repo().verifyChallenge(RecoveryFactor.Totp, "alice", "pwr_1", "123456")
        val req = backend.takeRequest()
        assertEquals("/ui/password-recovery/challenge/totp/verify", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("123456", body["totp_code"])
        assertNull(body["code"])
    }

    @Test
    fun verify_recovery_usesFlatPath_andRecoveryCodeField() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ok","remaining_factors":[]}"""))
        repo().verifyChallenge(RecoveryFactor.Recovery, "alice", "pwr_1", "ABCD-1234-EFGH")
        val req = backend.takeRequest()
        assertEquals("/ui/password-recovery/challenge/recovery", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("recovery", body["factor"])
        assertEquals("ABCD-1234-EFGH", body["recovery_code"])
    }

    @Test
    fun verify_blankCode_shortCircuits_withoutNetworkCall() = runTest {
        val result = repo().verifyChallenge(RecoveryFactor.Sms, "alice", "pwr_1", "   ")
        assertTrue(result is ApiResult.Failure)
        assertEquals("invalid_code", (result as ApiResult.Failure).error.code)
        assertEquals(0, backend.requestCount)
    }

    @Test
    fun verify_wrongCode_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"That code isn't correct.\"", 422))
        val result = repo().verifyChallenge(RecoveryFactor.Email, "alice", "pwr_1", "000000")
        assertTrue(result is ApiResult.Failure)
        assertEquals("That code isn't correct.", (result as ApiResult.Failure).error.message)
    }

    // ── confirm ──

    @Test
    fun confirm_sendsExpectedBody_andMapsOk() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().confirmNewPassword(
            username = "alice",
            confirmationCode = "482913",
            newPassword = "Str0ng!Passw0rd",
            challengeId = "pwr_1",
        )
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("/ui/password-recovery/confirm", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("alice", body["username"])
        assertEquals("482913", body["confirmation_code"])
        assertEquals("Str0ng!Passw0rd", body["new_password"])
        assertEquals("pwr_1", body["challenge_id"])
        assertNull(body["code"]) // wire key is confirmation_code, never `code`
    }

    @Test
    fun confirm_omitsChallengeId_whenNull() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        repo().confirmNewPassword("alice", "482913", "Str0ng!Passw0rd", challengeId = null)
        val body = backend.takeRequest().bodyJson()
        assertNull(body["challenge_id"])
    }
}
