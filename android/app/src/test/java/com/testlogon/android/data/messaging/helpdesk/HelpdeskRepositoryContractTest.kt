package com.testlogon.android.data.messaging.helpdesk

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.auth.FakeAuthStateStore
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-161/AND-162 — contract tests for [HelpdeskRepositoryImpl] against MockWebServer: required
 * group_id query, 200 bare-array mapping, 403 -> Failure(403) (not-an-agent), empty array -> empty
 * success, and the claim path/shape.
 */
class HelpdeskRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private val auth = FakeAuthStateStore().apply { runBlocking { setAuthenticated("usr_me") } }

    private fun repo(): HelpdeskRepositoryImpl {
        val api = backend.retrofit(moshi).create(HelpdeskApi::class.java)
        return HelpdeskRepositoryImpl(
            api = api,
            errorParser = ApiErrorParser(moshi),
            authStateStore = auth,
            helpdeskGroupId = "e2e-helpdesk",
        )
    }

    @Test
    fun loadQueue_sendsRequiredGroupId_andMapsBareArray() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [{"conversation_id":"conv_1","type":"dm","title":"Help me","created_at":1,"created_by":"u",
                  "participant_count":2,"status":"active","last_message_preview":"hi","last_message_at":1749132069,
                  "unread_count":2,"routing_state":"awaiting_agent","active_agent_user_id":null}]
                """.trimIndent(),
            ),
        )
        val r = repo().loadQueue()
        assertTrue(r is ApiResult.Success)
        assertEquals("conv_1", (r as ApiResult.Success).data.single().conversationId)

        val req = backend.takeRequest()
        assertEquals("/messaging/helpdesk/queue", req.requestUrl?.encodedPath)
        assertEquals("e2e-helpdesk", req.requestUrl?.queryParameter("group_id"))
        assertEquals("50", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun loadQueue_emptyArray_isEmptySuccess() = runTest {
        backend.enqueue(Fixtures.okBody("[]"))
        val r = repo().loadQueue()
        assertTrue(r is ApiResult.Success)
        assertTrue((r as ApiResult.Success).data.isEmpty())
    }

    @Test
    fun loadQueue_403_isForbiddenFailure() = runTest {
        backend.enqueue(Fixtures.error("\"forbidden\"", 403))
        val r = repo().loadQueue()
        assertTrue(r is ApiResult.Failure)
        assertEquals(HelpdeskRepositoryImpl.HTTP_FORBIDDEN, (r as ApiResult.Failure).error.status)
        assertEquals(1, backend.requestCount) // the request IS made (403 is the role signal)
    }

    @Test
    fun loadQueue_422_isFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query","group_id"],"msg":"required","type":"missing"}]""", 422))
        val r = repo().loadQueue()
        assertTrue(r is ApiResult.Failure)
        assertEquals(422, (r as ApiResult.Failure).error.status)
    }

    @Test
    fun claim_postsCorrectPath_andMapsAssignedToMe() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"conversation_id":"conv_1","state":"assigned",
                   "assigned_agent_user_id":"usr_me","assignment_version":3,"idempotent":false}""",
            ),
        )
        val r = repo().claim("conv_1")
        assertTrue(r is ApiResult.Success)
        assertEquals(HelpdeskAssignment.ASSIGNED_TO_ME, (r as ApiResult.Success).data.assignment)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/helpdesk/conversations/conv_1/claim", req.requestUrl?.encodedPath)
    }

    @Test
    fun claim_200WithOtherAgent_isAssignedToOther() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"conversation_id":"conv_1","state":"assigned",
                   "assigned_agent_user_id":"usr_other","assignment_version":4,"idempotent":false}""",
            ),
        )
        val r = repo().claim("conv_1")
        assertTrue(r is ApiResult.Success)
        assertEquals(HelpdeskAssignment.ASSIGNED_TO_OTHER, (r as ApiResult.Success).data.assignment)
    }
}
