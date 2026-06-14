package com.testlogon.android.data.report

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.messaging.report.ReportApi
import com.testlogon.android.data.messaging.report.ReportReason
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-383 — contract tests for [ReportFlowRepositoryImpl] against MockWebServer (TC-AND-383-07..09).
 *
 * Asserts the REAL two-endpoint wire contract: USER/CONTENT route to POST moderation/reports
 * (CreateModerationReportIn body), MESSAGE routes to AND-163's message-scoped endpoint
 * (ReportMessageIn body). The double-submit X-CSRF-Token header is verified by attaching a CSRF-copying
 * interceptor (mirroring core-network's CsrfInterceptor) over a cookie jar seeded with ui_csrf. Also
 * covers the three FastAPI 422 `detail` shapes + the MessageControlsErrorOut shape mapping via ApiError.
 */
class ReportFlowRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    /** A client that mirrors the production CsrfInterceptor: stamps X-CSRF-Token on mutating verbs. */
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

    private fun repo(client: OkHttpClient): ReportFlowRepositoryImpl {
        val rf = backend.retrofit(moshi, client)
        return ReportFlowRepositoryImpl(
            moderationApi = rf.create(ModerationReportApi::class.java),
            messageApi = rf.create(ReportApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    // TC-AND-383-07
    @Test
    fun content_postsModerationPath_exactBody_andCsrfHeader() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"report_id":"rpt_07","ticket_id":"tk_07","status":"submitted","created_at":1717}""",
            ),
        )
        val r = repo(csrfClient()).submit(
            target = ReportTarget.Content(id = "post_8131", contentType = "feed_post"),
            topics = setOf(ReportReason.SPAM, ReportReason.CRIMINAL),
            reasonText = "repeated spam links",
        )
        assertTrue(r is ApiResult.Success)
        assertEquals("rpt_07", (r as ApiResult.Success).data.reportId)
        assertEquals(false, r.data.alreadyReported)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/moderation/reports", req.requestUrl?.encodedPath)
        assertEquals(CSRF, req.getHeader("X-CSRF-Token"))
        val body = req.bodyJson()
        assertEquals("feed_post", body["content_type"])
        assertEquals("post_8131", body["content_id"])
        assertEquals("post_8131", body["post_id"])
        assertEquals("repeated spam links", body["reason_text"])
        @Suppress("UNCHECKED_CAST")
        assertEquals(listOf("criminal", "spam"), (body["topics"] as List<String>).sorted())
    }

    // TC-AND-383-07 (USER variant — profile_photo + profile_user_id)
    @Test
    fun user_postsProfilePhotoContentType_withProfileUserId() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"report_id":"rpt_u","ticket_id":"tk_u","status":"deduplicated","created_at":1}""",
            ),
        )
        val r = repo(csrfClient()).submit(
            target = ReportTarget.User(id = "user_42", displayName = "Bob"),
            topics = setOf(ReportReason.RACIST),
            reasonText = "abusive profile photo",
        )
        assertTrue(r is ApiResult.Success)
        assertEquals(true, (r as ApiResult.Success).data.alreadyReported) // status=deduplicated -> FR-8

        val body = backend.takeRequest().bodyJson()
        assertEquals("profile_photo", body["content_type"])
        assertEquals("user_42", body["content_id"])
        assertEquals("user_42", body["profile_user_id"])
    }

    // TC-AND-383-08
    @Test
    fun message_postsMessagePath_reasonCodeFirstTopic_andStatement() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"report_id":"rpt_08","conversation_id":"c1","message_id":"m1",
                   "reason_code":"sexual","status":"submitted","created_at":2}""",
            ),
        )
        val r = repo(csrfClient()).submit(
            target = ReportTarget.Message(id = "m1", conversationId = "c1"),
            topics = setOf(ReportReason.SEXUAL, ReportReason.SPAM),
            reasonText = "repeated unwanted DMs",
        )
        assertTrue(r is ApiResult.Success)
        assertEquals(false, (r as ApiResult.Success).data.alreadyReported)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/conversations/c1/messages/m1/report", req.requestUrl?.encodedPath)
        assertEquals(CSRF, req.getHeader("X-CSRF-Token"))
        val body = req.bodyJson()
        // First topic in stable order (sexual precedes spam) is sent as reason_code.
        assertEquals("sexual", body["reason_code"])
        assertEquals("repeated unwanted DMs", body["statement"])
        assertEquals(2, body.size) // exactly reason_code + statement
    }

    // TC-AND-383-09 — 422 detail string
    @Test
    fun moderation_422_detailString_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"reason_text too short\"", 422))
        val r = repo(csrfClient()).submit(
            ReportTarget.Content("post_1", "feed_post"),
            setOf(ReportReason.SPAM),
            "tiny",
        )
        assertTrue(r is ApiResult.Failure)
        assertEquals(422, (r as ApiResult.Failure).error.status)
        assertEquals("reason_text too short", r.error.message)
    }

    // TC-AND-383-09 — 422 detail list [{msg}]
    @Test
    fun moderation_422_detailList_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["body","reason_text"],"msg":"field required","type":"x"}]""", 422))
        val r = repo(csrfClient()).submit(
            ReportTarget.Content("post_1", "feed_post"),
            setOf(ReportReason.SPAM),
            "short",
        )
        assertTrue(r is ApiResult.Failure)
        assertEquals(422, (r as ApiResult.Failure).error.status)
    }

    // TC-AND-383-09 — 422 detail object {code}
    @Test
    fun moderation_422_detailObject_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"invalid_topic"}""", 422))
        val r = repo(csrfClient()).submit(
            ReportTarget.Content("post_1", "feed_post"),
            setOf(ReportReason.SPAM),
            "valid reason",
        )
        assertTrue(r is ApiResult.Failure)
        assertEquals(422, (r as ApiResult.Failure).error.status)
        assertEquals("invalid_topic", r.error.code)
    }

    // TC-AND-383-09 — message MessageControlsErrorOut (single detail string)
    @Test
    fun message_429_messageControlsError_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"rate limited\"", 429))
        val r = repo(csrfClient()).submit(
            ReportTarget.Message(id = "m1", conversationId = "c1"),
            setOf(ReportReason.SPAM),
            "spammy DMs",
        )
        assertTrue(r is ApiResult.Failure)
        assertEquals(429, (r as ApiResult.Failure).error.status)
    }

    @Test
    fun disconnect_isNetworkError() = runTest {
        backend.enqueue(Fixtures.disconnect())
        val r = repo(csrfClient()).submit(
            ReportTarget.Content("post_1", "feed_post"),
            setOf(ReportReason.SPAM),
            "valid reason",
        )
        assertTrue(r is ApiResult.NetworkError)
    }

    @Test
    fun topics_taxonomy_isFiveStableWireCodes() {
        assertEquals(
            listOf("sexual", "extortion", "criminal", "spam", "racist"),
            ReportTopics.ALL.map { it.code },
        )
        assertEquals(ReportTopics.ALL, ReportTopics.forKind(ReportKind.USER))
        assertNull(ReportReason.entries.firstOrNull { it.code == "other" })
    }

    companion object {
        private const val CSRF = "csrf-test-token"
        private val MUTATING = setOf("POST", "PUT", "PATCH", "DELETE")
    }
}
