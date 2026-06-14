package com.testlogon.android.data.admin

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.admin.DashboardChannel
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-404 - contract tests for [DefaultMessagingDashboardRepository] against MockWebServer (TC-08/09/10).
 *
 * Covers: the corrected per-channel GET paths/verbs + query params (`stats?days=7` + `deliveries?limit=50`), the
 * @JsonClass DTO round-trip + masked merge, the PARTIAL fan-out path (stats OK + deliveries 5xx -> Success with
 * activityFailed, not a blanked screen), the stats-critical 403 -> Failure(403), and a 422 -> Failure(422). A
 * path-keyed [Dispatcher] keeps the concurrent fan-out order-independent. Plain Moshi (codegen adapters resolve
 * without reflection).
 */
class MessagingDashboardRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(role: AdminRole = AdminRole.UNKNOWN): DefaultMessagingDashboardRepository {
        val api = backend.retrofit(moshi).create(MessagingDashboardApi::class.java)
        val roleProvider = object : AdminRoleProvider {
            override fun currentRole(): AdminRole = role
        }
        return DefaultMessagingDashboardRepository(
            api = api,
            errorParser = ApiErrorParser(moshi),
            roleProvider = roleProvider,
        )
    }

    private val emailStatsBody = """
        {
          "sent": 12840, "delivered": 12111, "bounced": 412, "complained": 7,
          "failed": 96, "suppressed": 33, "total": 12840,
          "delivery_rate": 94.3, "bounce_rate": 3.2, "complaint_rate": 0.05, "period_days": 7
        }
    """.trimIndent()

    private val emailDeliveriesBody = """
        {
          "items": [
            { "to_email": "jane@example.com", "subject": "Welcome", "status": "delivered",
              "created_at": 1749132131, "bounce_type": null }
          ],
          "next_cursor": null
        }
    """.trimIndent()

    private fun emailDispatcher(stats: MockResponse, deliveries: MockResponse) = object : Dispatcher() {
        override fun dispatch(request: RecordedRequest): MockResponse {
            val path = request.path.orEmpty()
            return when {
                path.contains("/ui/admin/email/dashboard/stats") -> stats
                path.contains("/ui/admin/email/deliveries") -> deliveries
                else -> MockResponse().setResponseCode(404)
            }
        }
    }

    private fun ok(body: String) = MockResponse()
        .setResponseCode(200)
        .setHeader("Content-Type", "application/json")
        .setBody(body)

    private fun err(code: Int, detail: String = "\"nope\"") = MockResponse()
        .setResponseCode(code)
        .setHeader("Content-Type", "application/json")
        .setBody("""{"detail":$detail}""")

    @Test
    fun dashboard_email_hitsBothPathsWithParams_andMergesMasked() = runTest {
        backend.server.dispatcher = emailDispatcher(ok(emailStatsBody), ok(emailDeliveriesBody))

        val result = repo().dashboard(DashboardChannel.EMAIL)
        assertTrue(result is ApiResult.Success)
        val dashboard = (result as ApiResult.Success).data

        assertEquals("12,840", dashboard.metrics.first { it.key == METRIC_MSG_SENT }.value)
        assertEquals(1, dashboard.activity.size)
        // Recipient is MASKED in the merge (full PII never reaches the model).
        assertEquals("j***@e***.com", dashboard.activity.first().maskedRecipient)
        assertFalse(dashboard.activityFailed)

        // Both verified paths + query params were hit (order-independent).
        val urls = listOf(backend.takeRequest(), backend.takeRequest()).map { it.requestUrl }
        val statsReq = urls.first { it?.encodedPath == "/ui/admin/email/dashboard/stats" }
        val delivReq = urls.first { it?.encodedPath == "/ui/admin/email/deliveries" }
        assertEquals("7", statsReq?.queryParameter("days"))
        assertEquals("50", delivReq?.queryParameter("limit"))
    }

    @Test
    fun dashboard_partialFailure_deliveries5xx_keepsMetrics_marksActivityFailed() = runTest {
        backend.server.dispatcher = emailDispatcher(ok(emailStatsBody), err(500))
        val result = repo().dashboard(DashboardChannel.EMAIL)
        assertTrue(result is ApiResult.Success)
        val dashboard = (result as ApiResult.Success).data
        // Metrics present; activity degraded (non-blocking), screen not blanked.
        assertTrue(dashboard.metrics.isNotEmpty())
        assertTrue(dashboard.activity.isEmpty())
        assertTrue(dashboard.activityFailed)
        assertFalse(dashboard.isEmpty)
    }

    @Test
    fun dashboard_statsCritical_403_mapsFailure403() = runTest {
        backend.server.dispatcher = emailDispatcher(err(403, "{\"code\":\"role_required\"}"), ok(emailDeliveriesBody))
        val result = repo().dashboard(DashboardChannel.EMAIL)
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun dashboard_statsCritical_422_mapsFailure422() = runTest {
        backend.server.dispatcher = emailDispatcher(
            err(422, "[{\"loc\":[\"query\",\"days\"],\"msg\":\"bad\",\"type\":\"x\"}]"),
            ok(emailDeliveriesBody),
        )
        val result = repo().dashboard(DashboardChannel.EMAIL)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun isAdmin_falseForVerifiedNonAdmin_trueOtherwise() {
        assertFalse(repo(AdminRole.NONE).isAdmin())
        assertTrue(repo(AdminRole.UNKNOWN).isAdmin())
        assertTrue(repo(AdminRole.ADMIN).isAdmin())
    }
}
