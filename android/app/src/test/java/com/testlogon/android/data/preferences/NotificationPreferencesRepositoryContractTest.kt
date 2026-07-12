package com.testlogon.android.data.preferences

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.NotificationTypePreference
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-083 — notification (alert type) preferences round-trip (POST one type, then re-GET). */
class NotificationPreferencesRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): NotificationPreferencesRepositoryImpl {
        val api = backend.retrofit(moshi).create(NotificationPreferencesApi::class.java)
        return NotificationPreferencesRepositoryImpl(api, ApiErrorParser(moshi))
    }

    @Test
    fun getTypePreferences_decodesTolerantList() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"type_preferences":{"security_alerts":{"enabled":true,"push":true,"email":true,"sms":false,"in_app":true}}}""",
            ),
        )
        val result = repo().getTypePreferences()
        assertTrue(result is ApiResult.Success)
        val list = (result as ApiResult.Success).data
        assertEquals(1, list.size)
        assertEquals("security_alerts", list[0].alertType)
        assertTrue(list[0].push)
        assertTrue(list[0].email)

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/alerts/type-preferences", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun updateTypePreference_postsUpdate_thenReGets() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        backend.enqueue(
            Fixtures.okBody(
                """{"type_preferences":{"marketing":{"enabled":true,"push":false,"email":true,"sms":true,"in_app":false}}}""",
            ),
        )

        val result = repo().updateTypePreference(
            NotificationTypePreference(alertType = "marketing", email = true, sms = true),
        )
        assertTrue(result is ApiResult.Success)
        val list = (result as ApiResult.Success).data
        assertEquals(true, list.first { it.alertType == "marketing" }.sms)

        val post = backend.takeRequest()
        assertEquals("POST", post.method)
        assertEquals("/ui/alerts/type-preferences", post.requestUrl?.encodedPath)
        val body = post.body.readUtf8()
        assertTrue(body.contains("\"alert_type\":\"marketing\""))
        assertTrue(body.contains("\"sms\":true"))

        val reGet = backend.takeRequest()
        assertEquals("GET", reGet.method)
    }

    @Test
    fun updateTypePreference_postFails_doesNotReGet() = runTest {
        backend.enqueue(Fixtures.error("\"nope\"", 500))
        val result = repo().updateTypePreference(NotificationTypePreference(alertType = "billing"))
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
        assertEquals(1, backend.requestCount)
    }
}
