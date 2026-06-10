package com.testlogon.android.data.messaging.typing

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/** AND-146 — MockWebServer contract tests for [TypingApi] and the best-effort [TypingRepository]. */
class TypingApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private fun api(): TypingApi = backend.retrofit(moshi).create(TypingApi::class.java)
    private fun repo(): TypingRepository = DefaultTypingRepository(api())

    @Test
    fun start_postsIsTypingTrue() = runTest {
        backend.enqueue(Fixtures.okBody("{}"))
        repo().start("c1")
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/c1/typing", req.requestUrl?.encodedPath)
        assertEquals(true, req.bodyJson()["is_typing"])
    }

    @Test
    fun stop_postsIsTypingFalse() = runTest {
        backend.enqueue(Fixtures.okBody("{}"))
        repo().stop("c1")
        val req = backend.takeRequest()
        assertEquals(false, req.bodyJson()["is_typing"])
    }

    @Test
    fun send_swallowsServerError() = runTest {
        backend.enqueue(Fixtures.error("\"nope\"", code = 503))
        // Best-effort: must not throw.
        repo().start("c1")
        backend.takeRequest()
    }

    @Test
    fun poll_decodesTypingUsers_andEmptyOnError() = runTest {
        backend.enqueue(
            Fixtures.okBody("""[{"user_id":"u1","updated_at":5},{"user_id":"u2","updated_at":7}]"""),
        )
        val users = repo().poll("c1")
        assertEquals(2, users.size)
        assertEquals("u1", users[0].userId)
        backend.takeRequest()

        backend.enqueue(Fixtures.error("\"nope\"", code = 500))
        assertEquals(emptyList<TypingUserDto>(), repo().poll("c1"))
    }
}
