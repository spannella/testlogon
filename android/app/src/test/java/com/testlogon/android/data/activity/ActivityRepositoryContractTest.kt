package com.testlogon.android.data.activity

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-096 — contract tests for [ActivityRepositoryImpl] against MockWebServer (real Retrofit/Moshi).
 * Verifies the AND-091 wire contract: path/params/verb, DTO mapping (epoch-seconds, unknown type,
 * empty target -> null), cursor pagination, and error folding.
 */
class ActivityRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): ActivityRepositoryImpl {
        val api = backend.retrofit(moshi).create(ActivityApi::class.java)
        return ActivityRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun feed_decodesPage_mapsDomain_andSendsParams() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"items":[
                  {"activity_id":"act_1","actor_id":"usr_1","activity_type":"login_success",
                   "target_type":"session","target_id":"sess_9","created_at":1749132202,"read":false,
                   "metadata":{"ip":"203.0.113.7"}},
                  {"activity_id":"act_2","actor_id":"usr_1","activity_type":"weird_kind",
                   "target_type":"","target_id":"","created_at":0}
                ],"next_cursor":"c2","total_unread":3}
                """.trimIndent(),
            ),
        )
        val result = repo().feed(cursor = null, limit = 20)

        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(2, page.items.size)
        assertEquals("c2", page.nextCursor)
        assertEquals(3, page.totalUnread)
        assertEquals(ActivityEventType.LOGIN_SUCCESS, page.items[0].type)
        assertEquals(1749132202L, page.items[0].createdAtEpochSeconds)
        assertEquals("203.0.113.7", page.items[0].detail) // derived from metadata ip
        assertEquals(ActivityEventType.UNKNOWN, page.items[1].type) // unknown token -> UNKNOWN
        assertEquals("weird_kind", page.items[1].rawType)
        assertNull(page.items[1].targetType) // "" -> null
        assertNull(page.items[1].detail)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/activity/feed", req.requestUrl?.encodedPath)
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun feed_secondPage_sendsCursor_andEndsOnNull() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[],"next_cursor":null,"total_unread":0}"""))
        val result = repo().feed(cursor = "c2", limit = 20)

        assertTrue(result is ApiResult.Success)
        assertNull((result as ApiResult.Success).data.nextCursor)

        val req = backend.takeRequest()
        assertEquals("c2", req.requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun feed_422_mapsToFailure_neverThrows() = runTest {
        backend.enqueue(Fixtures.error("""[{"msg":"bad cursor","type":"value_error"}]""", 422))
        val result = repo().feed()
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun feed_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().feed()
        assertTrue(result is ApiResult.NetworkError)
        assertTrue((result as ApiResult.NetworkError).isTimeout)
    }
}
