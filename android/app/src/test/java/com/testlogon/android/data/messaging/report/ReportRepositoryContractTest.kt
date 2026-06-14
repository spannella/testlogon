package com.testlogon.android.data.messaging.report

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-163 — contract tests for [ReportRepositoryImpl] against MockWebServer, asserting the REAL wire
 * contract verified from reference/openapi.pretty.json (ReportMessageIn / ReportMessageOut) and the web
 * client (reportMessage): the POST path with BOTH conversation+message ids, the exact request body
 * `{reason_code, statement}`, the 200 ReportMessageOut parse (status const "submitted", integer
 * created_at), and the MessageControlsErrorOut error path (single `detail` string, not the array).
 */
class ReportRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): ReportRepositoryImpl {
        val api = backend.retrofit(moshi).create(ReportApi::class.java)
        return ReportRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun reportMessage_postsCorrectPath_andExactBody_andParsesSubmitted() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"ok":true,"report_id":"rpt_01HY","conversation_id":"c1","message_id":"m1",
                 "reason_code":"sexual","status":"submitted","created_at":1717588800}
                """.trimIndent(),
            ),
        )
        val r = repo().reportMessage("c1", "m1", ReportReason.SEXUAL, "looks sexual")

        assertTrue(r is ApiResult.Success)
        val report = (r as ApiResult.Success).data
        assertEquals("rpt_01HY", report.reportId)
        assertEquals(ReportStatus.SUBMITTED, report.status)
        assertEquals(1717588800L, report.createdAtEpochSeconds)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1/report", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("sexual", body["reason_code"])
        assertEquals("looks sexual", body["statement"])
        assertEquals(2, body.size) // exactly reason_code + statement, nothing else
    }

    @Test
    fun reportMessage_sendsChosenReasonCodeVerbatim() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"report_id":"r","conversation_id":"c1","message_id":"m1",
                   "reason_code":"racist","status":"submitted","created_at":1}""",
            ),
        )
        repo().reportMessage("c1", "m1", ReportReason.RACIST, "hate speech here")
        assertEquals("racist", backend.takeRequest().bodyJson()["reason_code"])
    }

    @Test
    fun reportMessage_success_reconcilesStatusPendingToSubmitted() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"report_id":"r","conversation_id":"c1","message_id":"m1",
                   "reason_code":"spam","status":"submitted","created_at":1}""",
            ),
        )
        val repo = repo()
        repo.reportMessage("c1", "m1", ReportReason.SPAM, "spam spam")
        assertEquals(ReportStatus.SUBMITTED, repo.observeStatus("m1").first())
    }

    @Test
    fun reportMessage_422MessageControlsError_isFailure_andRollsBackStatus() = runTest {
        // MessageControlsErrorOut: a single `detail` STRING (not the FastAPI [{msg}] array).
        backend.enqueue(Fixtures.error("\"statement too short\"", 422))
        val repo = repo()
        val r = repo.reportMessage("c1", "m1", ReportReason.SPAM, "tiny")

        assertTrue(r is ApiResult.Failure)
        assertEquals(422, (r as ApiResult.Failure).error.status)
        assertEquals("statement too short", r.error.message)
        // Optimistic PENDING rolled back to NONE.
        assertEquals(ReportStatus.NONE, repo.observeStatus("m1").first())
    }

    @Test
    fun reportMessage_429_carriesErrorCodeForBranching() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"rate_limited"}""", 429))
        val r = repo().reportMessage("c1", "m1", ReportReason.SPAM, "spammy")
        assertTrue(r is ApiResult.Failure)
        assertEquals(429, (r as ApiResult.Failure).error.status)
    }

    @Test
    fun reportMessage_disconnect_isNetworkError_andRollsBack() = runTest {
        backend.enqueue(Fixtures.disconnect())
        val repo = repo()
        val r = repo.reportMessage("c1", "m1", ReportReason.CRIMINAL, "illegal")
        assertTrue(r is ApiResult.NetworkError)
        assertEquals(ReportStatus.NONE, repo.observeStatus("m1").first())
    }

    @Test
    fun observeStatus_defaultsToNone() = runTest {
        assertEquals(ReportStatus.NONE, repo().observeStatus("never_reported").first())
    }

    @Test
    fun reasonCatalog_isHardCodedFiveTopics() {
        assertEquals(
            listOf("sexual", "extortion", "criminal", "spam", "racist"),
            repo().reasonCatalog().map { it.code },
        )
        assertNull(ReportReason.entries.firstOrNull { it.code == "harassment" }) // old enum gone
    }
}
