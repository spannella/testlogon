package com.testlogon.android.data.privacy

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-386 - contract tests for [DefaultAccountDeletionRepository] against MockWebServer
 * (TC-AND-386-01, 02, 04, 06, 07, 08). Asserts the REAL wire contract:
 *  - GET ui/privacy/account-deletion/requests -> derive Pending (status == "pending"), epoch SECONDS -> ms,
 *  - POST ui/privacy/account-deletion/request with {password, confirm_text, reason?} + CSRF + 201,
 *  - the request POST is issued exactly ONCE (no retry) on a 422,
 *  - cancel POST at .../requests/{id}/cancel + 200, then a re-fetch of the authoritative state,
 *  - a 404/409 on cancel is swallowed -> re-fetch (recoverable).
 */
class AccountDeletionRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun csrfClient(): OkHttpClient {
        val csrf = Interceptor { chain ->
            val req = chain.request()
            val out = if (req.method in MUTATING) {
                req.newBuilder().header("X-CSRF-Token", CSRF).build()
            } else {
                req
            }
            chain.proceed(out)
        }
        return defaultTestClient().newBuilder().addInterceptor(csrf).build()
    }

    private fun repo(client: OkHttpClient = csrfClient()): DefaultAccountDeletionRepository {
        val rf = backend.retrofit(moshi, client)
        return DefaultAccountDeletionRepository(
            api = rf.create(PrivacyApi::class.java),
            statusStore = FakeAccountDeletionStatusStore(),
            errorParser = ApiErrorParser(moshi),
        )
    }

    // TC-AND-386-01 + 02
    @Test
    fun getStatus_derivesPending_fromList_andEpochSecondsToMs() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"requests":[
                   {"request_id":"del_01J9","status":"pending","created_at":1749132131,
                    "scheduled_for":1750341731,"grace_days_remaining":14,"can_cancel":true,
                    "retention_hold":false,"reason":null}
                  ],"total":1}""",
            ),
        )
        val result = repo().getStatus()
        assertTrue(result is ApiResult.Success)
        val status = (result as ApiResult.Success).data as DeletionStatus.Pending
        assertEquals("del_01J9", status.requestId)
        assertEquals(1749132131L * 1000L, status.createdAtEpochMs)
        assertEquals(1750341731L * 1000L, status.scheduledForEpochMs)
        assertEquals(14, status.graceDaysRemaining)
        assertTrue(status.canCancel)

        val get = backend.takeRequest()
        assertEquals("GET", get.method)
        assertEquals("/ui/privacy/account-deletion/requests", get.requestUrl?.encodedPath)
    }

    @Test
    fun getStatus_emptyList_mapsToActive_andNullScheduledHandled() = runTest {
        backend.enqueue(Fixtures.okBody("""{"requests":[],"total":0}"""))
        val result = repo().getStatus()
        assertEquals(DeletionStatus.Active, (result as ApiResult.Success).data)
    }

    @Test
    fun getStatus_pendingWithNullScheduled_mapsToNull() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"requests":[{"request_id":"del_2","status":"pending","created_at":1749132131,
                   "scheduled_for":null,"grace_days_remaining":null,"can_cancel":false}],"total":1}""",
            ),
        )
        val status = (repo().getStatus() as ApiResult.Success).data as DeletionStatus.Pending
        assertNull(status.scheduledForEpochMs)
        assertNull(status.graceDaysRemaining)
    }

    // TC-AND-386-04
    @Test
    fun requestDeletion_postsBodyAndCsrf_201_mapsPending() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"request_id":"del_new","status":"pending","created_at":1749132131,
                   "scheduled_for":1750341731,"grace_days_remaining":14,"can_cancel":true}""",
                code = 201,
            ),
        )
        val result = repo().requestDeletion("pw", "DELETE MY ACCOUNT", "leaving")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/privacy/account-deletion/request", req.requestUrl?.encodedPath)
        assertEquals(CSRF, req.getHeader("X-CSRF-Token"))
        val body = req.bodyJson()
        assertEquals("pw", body["password"])
        assertEquals("DELETE MY ACCOUNT", body["confirm_text"])
        assertEquals("leaving", body["reason"])

        val pending = (result as ApiResult.Success).data
        assertEquals("del_new", pending.requestId)
        assertTrue(pending.canCancel)
    }

    // TC-AND-386-06: no retry on a 422 mutation -> exactly one recorded POST.
    @Test
    fun requestDeletion_422_singlePostNoRetry_failure() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"detail":[{"loc":["body","password"],"msg":"invalid","type":"value_error"}]}""",
                code = 422,
            ),
        )
        val result = repo().requestDeletion("wrong", "DELETE MY ACCOUNT", null)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        assertEquals(1, backend.requestCount)
    }

    // TC-AND-386-07: cancel happy path posts once then re-fetches -> Active.
    @Test
    fun cancelDeletion_posts_thenRefetches_active() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"request_id":"del_x","status":"cancelled","cancelled_at":1749132200}""",
            ),
        )
        backend.enqueue(Fixtures.okBody("""{"requests":[],"total":0}"""))

        val result = repo().cancelDeletion("del_x")
        assertEquals(DeletionStatus.Active, (result as ApiResult.Success).data)

        val cancel = backend.takeRequest()
        assertEquals("POST", cancel.method)
        assertEquals("/ui/privacy/account-deletion/requests/del_x/cancel", cancel.requestUrl?.encodedPath)
        assertEquals(CSRF, cancel.getHeader("X-CSRF-Token"))
        val refetch = backend.takeRequest()
        assertEquals("GET", refetch.method)
        assertEquals("/ui/privacy/account-deletion/requests", refetch.requestUrl?.encodedPath)
    }

    // TC-AND-386-08: a 404 on cancel is swallowed -> re-fetch -> recoverable Active.
    @Test
    fun cancelDeletion_404_swallowed_thenRefetch() = runTest {
        backend.enqueue(Fixtures.okBody("""{"detail":"gone"}""", code = 404))
        backend.enqueue(Fixtures.okBody("""{"requests":[],"total":0}"""))

        val result = repo().cancelDeletion("del_gone")
        assertEquals(DeletionStatus.Active, (result as ApiResult.Success).data)
        assertEquals(2, backend.requestCount)
    }

    // Offline status -> NetworkError (no enqueued response -> short-timeout transport error).
    @Test
    fun getStatus_offline_returnsNetworkError() = runTest {
        val result = repo().getStatus()
        assertTrue(result is ApiResult.NetworkError)
    }

    private companion object {
        const val CSRF = "csrf-test-token"
        val MUTATING = setOf("POST", "PUT", "PATCH", "DELETE")
    }
}
