package com.testlogon.android.data.notifications

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-090 — contract tests for [NotificationRepositoryImpl] against MockWebServer (real
 * Retrofit/Moshi codegen). Verifies the verified wire contract from AND-084: list paging + mapping,
 * mark-read body, mark-all-read empty body, unread-count, the unread StateFlow, and error folding.
 */
class NotificationRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): NotificationRepositoryImpl {
        val api = backend.retrofit(moshi).create(NotificationsApi::class.java)
        return NotificationRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun list_decodesPage_mapsDomain_andUpdatesBadge() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"items":[
                  {"notification_id":"ntf_1","notification_type":"follow","title":"Hi","body":"b",
                   "read":false,"created_at":1749124800,"data":{"u_identifier":"alice"},
                   "batch_count":1,"batch_actors":[]},
                  {"notification_id":"ntf_2","notification_type":"weird","title":"T2","body":"",
                   "read":true,"created_at":0,"server_time":"ignored"}
                ],"next_cursor":"c2","unread_count":3}
                """.trimIndent(),
            ),
        )
        val r = repo()
        val result = r.list(cursor = null, limit = 20)

        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(2, page.items.size)
        assertEquals("c2", page.nextCursor)
        assertEquals(NotificationType.FOLLOW, page.items[0].type)
        assertEquals(NotificationType.UNKNOWN, page.items[1].type) // unknown token -> UNKNOWN
        assertEquals(1749124800L, page.items[0].createdAtEpochSeconds)
        assertEquals(3, r.unreadCount.value) // StateFlow refreshed from unread_count

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/notifications", req.requestUrl?.encodedPath)
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("unread_only")) // no such param
    }

    @Test
    fun markRead_postsNotificationIds_andReturnsMarkedCount() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"marked_count":2}"""))
        val result = repo().markRead(listOf("ntf_1", "ntf_2"))

        assertTrue(result is ApiResult.Success)
        assertEquals(2, (result as ApiResult.Success).data)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/notifications/mark-read", req.requestUrl?.encodedPath)
        val ids = req.bodyJson()["notification_ids"] as List<*>
        assertEquals(listOf("ntf_1", "ntf_2"), ids)
    }

    @Test
    fun markAllRead_postsEmptyObject_zeroesBadge() = runTest {
        val r = repo()
        // seed badge via a list first.
        backend.enqueue(Fixtures.okBody("""{"items":[],"next_cursor":null,"unread_count":4}"""))
        r.list()
        assertEquals(4, r.unreadCount.value)

        backend.takeRequest() // consume the list request
        backend.enqueue(Fixtures.okBody("""{"ok":true,"marked_count":5}"""))
        val result = r.markAllRead()

        assertTrue(result is ApiResult.Success)
        assertEquals(5, (result as ApiResult.Success).data)
        assertEquals(0, r.unreadCount.value)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/notifications/mark-all-read", req.requestUrl?.encodedPath)
        assertTrue(req.bodyJson().isEmpty()) // empty JSON object
    }

    @Test
    fun unreadCount_decodesCountField_andUpdatesBadge() = runTest {
        backend.enqueue(Fixtures.okBody("""{"count":7}"""))
        val r = repo()
        val result = r.refreshUnreadCount()

        assertTrue(result is ApiResult.Success)
        assertEquals(7, (result as ApiResult.Success).data)
        assertEquals(7, r.unreadCount.value)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/notifications/unread-count", req.requestUrl?.encodedPath)
    }

    @Test
    fun list_403_mapsToFailure_neverThrows() = runTest {
        backend.enqueue(Fixtures.error("\"Forbidden\"", 403))
        val result = repo().list()
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun list_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().list()
        assertTrue(result is ApiResult.NetworkError)
        assertTrue((result as ApiResult.NetworkError).isTimeout)
    }
}
