package com.testlogon.android.data.auth

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.FixtureName
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-043 contract tests for SessionsRepository against MockWebServer (real Retrofit/Moshi). */
class SessionsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): SessionsRepositoryImpl {
        val api = backend.retrofit(moshi).create(AuthApi::class.java)
        return SessionsRepositoryImpl(
            api = api,
            authRepository = FakeAuthRepository(),
            errorParser = ApiErrorParser(moshi),
            cache = AuthAreaCache(),
        )
    }

    @Test
    fun listSessions_parsesAndSorts_currentPinned() = runTest {
        backend.enqueue(Fixtures.ok(FixtureName.SESSIONS))
        val result = repo().listSessions()
        assertTrue(result is ApiResult.Success)
        val rows = (result as ApiResult.Success).data
        assertEquals(3, rows.size)
        assertEquals("sess-1", rows.first().sessionId) // is_current pinned to top
        val recorded = backend.takeRequest()
        assertEquals("/ui/sessions", recorded.requestUrl?.encodedPath)
        assertEquals("GET", recorded.method)
    }

    @Test
    fun revoke_postsSessionId() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ok"}"""))
        val result = repo().revoke("sess-2")
        assertTrue(result is ApiResult.Success)
        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/sessions/revoke", recorded.requestUrl?.encodedPath)
        assertEquals("sess-2", recorded.bodyJson()["session_id"])
    }

    @Test
    fun revokeOthers_postsUnderscorePath_noBody() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ok"}"""))
        val result = repo().revokeOthers()
        assertTrue(result is ApiResult.Success)
        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/sessions/revoke_others", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun listSessions_403_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"Invalid CSRF token\"", 403))
        val result = repo().listSessions()
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }
}
