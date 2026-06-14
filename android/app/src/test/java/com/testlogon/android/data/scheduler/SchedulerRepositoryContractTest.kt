package com.testlogon.android.data.scheduler

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-275 — MockWebServer contract tests for [SchedulerRepositoryImpl]. Verifies create
 * (POST .../actions, 201), reschedule (PATCH .../actions/{id}, 200), cancel (DELETE .../actions/{id},
 * 200, no scope param), the list envelope, epoch-seconds wire shape, and error propagation.
 */
class SchedulerRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): SchedulerRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return SchedulerRepositoryImpl(
            api = retrofit.create(SchedulerApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun create_postsIntegerScheduledAt_decodesOut() = runTest {
        backend.enqueue(Fixtures.okBody(ACTION_OUT_JSON, code = 201))
        val result = repo().create(
            ScheduledActionCreateInDto(actionType = "post", scheduledAt = 1749580200L, title = "t"),
        )
        assertTrue(result is ApiResult.Success)
        val action = (result as ApiResult.Success).data
        assertEquals("act_01J2C7", action.actionId)
        assertEquals("pending", action.status)
        assertEquals(3, action.maxRetries)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/scheduler/actions", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"action_type\":\"post\""))
        assertTrue(body.contains("\"scheduled_at\":1749580200"))
    }

    @Test
    fun reschedule_patchesPartialBody() = runTest {
        backend.enqueue(Fixtures.okBody(ACTION_OUT_JSON))
        val result = repo().reschedule(
            "act_01J2C7",
            ScheduledActionUpdateInDto(scheduledAt = 1749672000L, title = "moved"),
        )
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("PATCH", req.method)
        assertEquals("/ui/scheduler/actions/act_01J2C7", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"scheduled_at\":1749672000"))
        assertTrue("action_type must be absent on update", !body.contains("action_type"))
    }

    @Test
    fun cancel_deletesWithNoScopeParam_200() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"action_id":"act_01J2C7","status":"cancelled"}"""))
        val result = repo().cancel("act_01J2C7")
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/ui/scheduler/actions/act_01J2C7", req.requestUrl?.encodedPath)
        assertEquals(null, req.requestUrl?.queryParameter("scope"))
    }

    @Test
    fun list_decodesEnvelope_sorted() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"actions":[
                   {"action_id":"a2","action_type":"post","status":"pending","scheduled_at":2000,
                    "created_at":100},
                   {"action_id":"a1","action_type":"message","status":"pending","scheduled_at":1000,
                    "created_at":100}
                   ],"cursor":null}""",
            ),
        )
        val result = repo().listActions()
        assertTrue(result is ApiResult.Success)
        val actions = (result as ApiResult.Success).data
        assertEquals(listOf("a1", "a2"), actions.map { it.actionId })
        assertEquals("/ui/scheduler/actions", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun loadAction_404_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val result = repo().loadAction("act_x")
        assertTrue(result is ApiResult.Failure)
        assertEquals(404, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun create_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().create(ScheduledActionCreateInDto(actionType = "post", scheduledAt = 1L))
        assertTrue(result is ApiResult.NetworkError)
    }

    private companion object {
        const val ACTION_OUT_JSON = """
            {"action_id":"act_01J2C7","action_type":"post","status":"pending",
             "scheduled_at":1749580200,"created_at":1749132000,"updated_at":null,"completed_at":null,
             "title":"Launch teaser","description":"","payload":{},"error":null,"retry_count":0,
             "max_retries":3,"notify_before_seconds":0,"reminder_sent":false}
        """
    }
}
