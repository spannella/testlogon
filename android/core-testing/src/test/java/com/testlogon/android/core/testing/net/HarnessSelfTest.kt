package com.testlogon.android.core.testing.net

import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-046 self-tests: prove the harness starts/stops, loads fixtures, and routes the auth flow. */
class HarnessSelfTest {

    @get:Rule
    val backend = MockBackendRule()

    @Test
    fun baseUrl_isLoopback_andEnqueueRoundTrips() {
        backend.enqueue(Fixtures.ok(FixtureName.ME))
        val client = defaultTestClient()
        val resp = client.newCall(Request.Builder().url(backend.baseUrl.resolve("ui/me")!!).build()).execute()
        assertTrue(resp.isSuccessful)
        assertTrue(resp.body!!.string().contains("user_sub"))
        val recorded = backend.takeRequest()
        assertEquals("/ui/me", recorded.requestUrl?.encodedPath)
        assertEquals("GET", recorded.method)
    }

    @Test
    fun missingFixture_throwsClearMessage() {
        val ex = assertThrows(IllegalArgumentException::class.java) { Fixtures.json("does_not_exist") }
        assertTrue(ex.message!!.contains("Missing fixture: fixtures/does_not_exist.json"))
    }

    @Test
    fun knownFixtures_load() {
        listOf(
            FixtureName.SESSION_START_MFA,
            FixtureName.MFA_TOTP_VERIFY_OK,
            FixtureName.SESSION_FINALIZE_OK,
            FixtureName.ME,
            FixtureName.SESSIONS,
            FixtureName.SESSION_REFRESH_OK,
            FixtureName.ERROR_DETAIL_STRING,
            FixtureName.ERROR_DETAIL_LIST,
            FixtureName.ERROR_DETAIL_OBJECT,
        ).forEach { assertTrue(Fixtures.json(it).isNotBlank()) }
    }
}
