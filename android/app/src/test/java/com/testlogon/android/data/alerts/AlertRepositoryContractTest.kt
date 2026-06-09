package com.testlogon.android.data.alerts

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-086 / AND-087 — contract tests for the email + SMS alert-target repositories against
 * MockWebServer. Verifies the begin/confirm/remove request shapes and AlertPreferences mapping.
 */
class AlertRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun email(): EmailAlertRepositoryImpl {
        val api = backend.retrofit(moshi).create(EmailAlertApi::class.java)
        return EmailAlertRepositoryImpl(api, ApiErrorParser(moshi))
    }

    private fun sms(): SmsAlertRepositoryImpl {
        val api = backend.retrofit(moshi).create(SmsAlertApi::class.java)
        return SmsAlertRepositoryImpl(api, ApiErrorParser(moshi))
    }

    // ── Email ──

    @Test
    fun emailPrefs_mapsEmailsList() = runTest {
        backend.enqueue(Fixtures.okBody("""{"emails":["a@x.com","b@y.com"],"email_event_types":["login"]}"""))
        val result = email().listEmails()
        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("a@x.com", "b@y.com"), (result as ApiResult.Success).data)
        assertEquals("/ui/alerts/email_prefs", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun emailBegin_postsEmail_returnsChallenge() = runTest {
        backend.enqueue(Fixtures.okBody("""{"challenge_id":"chal_1","sent_to":"new@x.com"}"""))
        val result = email().begin("new@x.com")
        assertTrue(result is ApiResult.Success)
        val data = (result as ApiResult.Success).data
        assertEquals("chal_1", data.challengeId)
        assertEquals("new@x.com", data.sentTo)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/alerts/emails/begin", req.requestUrl?.encodedPath)
        assertEquals("new@x.com", req.bodyJson()["email"])
    }

    @Test
    fun emailConfirm_postsChallengeAndCode_returnsUpdatedEmails() = runTest {
        backend.enqueue(Fixtures.okBody("""{"emails":["a@x.com","new@x.com"]}"""))
        val result = email().confirm("chal_1", "483920")
        assertTrue(result is ApiResult.Success)
        assertTrue("new@x.com" in (result as ApiResult.Success).data)

        val req = backend.takeRequest()
        assertEquals("/ui/alerts/emails/confirm", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("chal_1", body["challenge_id"])
        assertEquals("483920", body["code"])
    }

    @Test
    fun emailRemove_postsEmail() = runTest {
        backend.enqueue(Fixtures.okBody("""{"emails":["a@x.com"]}"""))
        val result = email().remove("new@x.com")
        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("a@x.com"), (result as ApiResult.Success).data)

        val req = backend.takeRequest()
        assertEquals("/ui/alerts/emails/remove", req.requestUrl?.encodedPath)
        assertEquals("new@x.com", req.bodyJson()["email"])
    }

    @Test
    fun emailBegin_422_mapsToFailure() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","email"],"msg":"value is not a valid email","type":"value_error"}]""",
                422,
            ),
        )
        val result = email().begin("bad")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    // ── SMS ──

    @Test
    fun smsPrefs_mapsNumbersList() = runTest {
        backend.enqueue(Fixtures.okBody("""{"sms_numbers":["+15551231234"],"sms_event_types":[]}"""))
        val result = sms().listNumbers()
        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("+15551231234"), (result as ApiResult.Success).data)
        assertEquals("/ui/alerts/sms_prefs", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun smsBegin_normalizesPhone_postsPhoneKey() = runTest {
        backend.enqueue(Fixtures.okBody("""{"challenge_id":"chl_1","sent_to":"+1•••1234"}"""))
        val result = sms().begin("+1 (555) 123-1234")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("/ui/alerts/sms/begin", req.requestUrl?.encodedPath)
        assertEquals("+15551231234", req.bodyJson()["phone"]) // normalized
    }

    @Test
    fun smsConfirm_postsChallengeAndCode() = runTest {
        backend.enqueue(Fixtures.okBody("""{"sms_numbers":["+15551231234"]}"""))
        val result = sms().confirm("chl_1", "482915")
        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("+15551231234"), (result as ApiResult.Success).data)

        val req = backend.takeRequest()
        assertEquals("/ui/alerts/sms/confirm", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("chl_1", body["challenge_id"])
        assertEquals("482915", body["code"])
    }

    @Test
    fun smsResend_delegatesToBegin() = runTest {
        backend.enqueue(Fixtures.okBody("""{"challenge_id":"chl_2","sent_to":"+1•••1234"}"""))
        val result = sms().resend("+15551231234")
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("/ui/alerts/sms/begin", req.requestUrl?.encodedPath) // no /resend endpoint
        assertEquals("+15551231234", req.bodyJson()["phone"])
    }

    @Test
    fun smsRemove_postsPhone() = runTest {
        backend.enqueue(Fixtures.okBody("""{"sms_numbers":[]}"""))
        val result = sms().remove("+15551231234")
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("/ui/alerts/sms/remove", req.requestUrl?.encodedPath)
        assertEquals("+15551231234", req.bodyJson()["phone"])
    }
}
