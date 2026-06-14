package com.testlogon.android.data.admin

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.admin.AlertSeverity
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-403 - contract tests for [DefaultAdminRepository] against MockWebServer (TC-01/TC-04/TC-07).
 *
 * Covers: the two verified general-admin GET paths/verbs (`ui/admin/jobs/health` + `ui/admin/webhooks/health`),
 * the full DTO round-trip + client-side aggregation (alerts derived + sorted, metric tiles built), the atomic
 * 403 -> Failure(403) authorization path, and a 5xx on either read -> Failure (atomic, no partial dashboard).
 *
 * Concurrency note: the repo fires both reads CONCURRENTLY, so requests can arrive in either order - a
 * path-keyed [Dispatcher] is used (NOT a FIFO enqueue) to keep the test order-independent. The @JsonClass
 * codegen DTOs decode with a plain Moshi (codegen adapters resolve without reflection).
 */
class AdminRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(role: AdminRole = AdminRole.UNKNOWN): DefaultAdminRepository {
        val api = backend.retrofit(moshi).create(AdminApi::class.java)
        val roleProvider = object : AdminRoleProvider {
            override fun currentRole(): AdminRole = role
        }
        return DefaultAdminRepository(api = api, errorParser = ApiErrorParser(moshi), roleProvider = roleProvider)
    }

    private val jobsBody = """
        {
          "jobs": [
            {"name": "payouts", "label": "Payouts", "health": "failed", "last_finished_at": 90, "last_error": "boom"},
            {"name": "digest", "label": "Digest", "health": "healthy", "last_finished_at": 100}
          ],
          "timestamp": 1717200000
        }
    """.trimIndent()

    private val webhookBody = """
        {
          "total_endpoints": 5, "enabled_endpoints": 4, "disabled_endpoints": 1,
          "total_deliveries_24h": 120, "success_count_24h": 100,
          "failed_count_24h": 18, "dead_letter_count_24h": 2
        }
    """.trimIndent()

    /** A path-keyed dispatcher so concurrent reads resolve regardless of arrival order. */
    private fun dispatcher(
        jobs: MockResponse,
        webhook: MockResponse,
    ) = object : Dispatcher() {
        override fun dispatch(request: RecordedRequest): MockResponse {
            val path = request.path.orEmpty()
            return when {
                path.contains("/ui/admin/jobs/health") -> jobs
                path.contains("/ui/admin/webhooks/health") -> webhook
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
    fun loadDashboard_hitsBothAdminPaths_andAggregates() = runTest {
        backend.server.dispatcher = dispatcher(ok(jobsBody), ok(webhookBody))

        val result = repo().loadDashboard()
        assertTrue(result is ApiResult.Success)
        val dashboard = (result as ApiResult.Success).data

        // Metrics: 8 tiles built; total jobs = 2.
        assertEquals("2", dashboard.metrics.first { it.key == METRIC_TOTAL_JOBS }.value)
        assertEquals("5", dashboard.metrics.first { it.key == METRIC_WEBHOOK_ENDPOINTS }.value)

        // Alerts: failed job (CRITICAL) + webhook dead-letter (CRITICAL) + webhook failed (WARNING).
        val ids = dashboard.alerts.map { it.id }
        assertTrue(ids.contains("job_payouts"))
        assertTrue(ids.contains("webhook_failed"))
        assertTrue(ids.contains("webhook_dead_letter"))
        // healthy "digest" job is NOT an alert.
        assertTrue(!ids.contains("job_digest"))
        // CRITICAL alerts sort first.
        assertEquals(AlertSeverity.CRITICAL, dashboard.alerts.first().severity)

        // Both verified admin paths were hit (order-independent).
        val paths = listOf(backend.takeRequest(), backend.takeRequest()).map { it.requestUrl?.encodedPath }
        assertTrue(paths.contains("/ui/admin/jobs/health"))
        assertTrue(paths.contains("/ui/admin/webhooks/health"))
    }

    @Test
    fun loadDashboard_403OnEither_mapsFailureWith403() = runTest {
        backend.server.dispatcher = dispatcher(err(403, "\"Admin access required\""), ok(webhookBody))
        val result = repo().loadDashboard()
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun loadDashboard_5xxOnEither_mapsFailure_atomic() = runTest {
        backend.server.dispatcher = dispatcher(ok(jobsBody), err(500))
        val result = repo().loadDashboard()
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun loadDashboard_malformed_neverCrashes() = runTest {
        val malformed = MockResponse().setResponseCode(200).setBody("{not json")
        backend.server.dispatcher = dispatcher(malformed, ok(webhookBody))
        val result = repo().loadDashboard()
        assertTrue(result is ApiResult.Failure || result is ApiResult.NetworkError)
    }

    @Test
    fun isAdmin_falseForVerifiedNonAdmin_trueForUnknownAndAdmin() {
        assertTrue(!repo(AdminRole.NONE).isAdmin())
        assertTrue(repo(AdminRole.UNKNOWN).isAdmin())
        assertTrue(repo(AdminRole.ADMIN).isAdmin())
        assertTrue(repo(AdminRole.ROOT).isAdmin())
    }
}
