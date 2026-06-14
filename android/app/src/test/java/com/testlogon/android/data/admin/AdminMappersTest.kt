package com.testlogon.android.data.admin

import com.testlogon.android.core.model.admin.AlertSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-403 - mapper/aggregation unit tests (TC-02): severity mapping with the UNKNOWN fallback, alert ordering
 * (severity-desc then createdAt-desc), derived webhook alerts, metric tile order, and the empty-dashboard case.
 * Pure JVM (core-model + :app, no Android, no network).
 */
class AdminMappersTest {

    private fun job(
        name: String,
        health: String,
        lastFinishedAt: Long? = null,
        lastError: String? = null,
    ) = JobHealthEntryDto(
        name = name,
        health = health,
        lastFinishedAt = lastFinishedAt,
        lastError = lastError,
    )

    private val zeroWebhook = WebhookHealthSummaryDto()

    @Test
    fun severityMapping_knownAndUnknown() {
        assertEquals(AlertSeverity.CRITICAL, mapJobHealthSeverity("failed"))
        assertEquals(AlertSeverity.CRITICAL, mapJobHealthSeverity("UNHEALTHY"))
        assertEquals(AlertSeverity.WARNING, mapJobHealthSeverity("degraded"))
        assertEquals(AlertSeverity.WARNING, mapJobHealthSeverity("stale"))
        assertEquals(AlertSeverity.INFO, mapJobHealthSeverity("healthy"))
        assertEquals(AlertSeverity.UNKNOWN, mapJobHealthSeverity("unknown"))
        assertEquals(AlertSeverity.UNKNOWN, mapJobHealthSeverity(null))
        // An unrecognised wire string must fall back to UNKNOWN, never throw.
        assertEquals(AlertSeverity.UNKNOWN, mapJobHealthSeverity("totally_new_state"))
    }

    @Test
    fun alerts_sortedBySeverityThenTimeDesc_andUnknownSurfaced() {
        val jobs = JobHealthDto(
            jobs = listOf(
                job("a_info", "healthy", lastFinishedAt = 100),       // not an alert
                job("b_warn", "degraded", lastFinishedAt = 50),
                job("c_crit_old", "failed", lastFinishedAt = 10, lastError = "boom"),
                job("d_crit_new", "failed", lastFinishedAt = 90, lastError = "kaboom"),
                job("e_unknown", "weird", lastFinishedAt = 200),
            ),
        )
        val alerts = buildAdminAlerts(jobs, zeroWebhook)

        // healthy job is excluded; the other four become alerts.
        assertEquals(4, alerts.size)
        // Order: CRITICAL (newest-first) then WARNING then UNKNOWN.
        assertEquals(listOf("job_d_crit_new", "job_c_crit_old", "job_b_warn", "job_e_unknown"), alerts.map { it.id })
        assertEquals(AlertSeverity.UNKNOWN, alerts.last().severity)
    }

    @Test
    fun webhookCounts_deriveFailedAndDeadLetterAlerts() {
        val webhook = WebhookHealthSummaryDto(failedCount24h = 3, deadLetterCount24h = 2)
        val alerts = buildAdminAlerts(JobHealthDto(), webhook)

        val ids = alerts.map { it.id }
        assertTrue(ids.contains("webhook_failed"))
        assertTrue(ids.contains("webhook_dead_letter"))
        // dead-letter is CRITICAL so it sorts above the WARNING failed alert.
        assertEquals("webhook_dead_letter", alerts.first().id)
        assertEquals(AlertSeverity.CRITICAL, alerts.first().severity)
    }

    @Test
    fun noWebhookProblems_produceNoWebhookAlerts() {
        val alerts = buildAdminAlerts(JobHealthDto(), zeroWebhook)
        assertTrue(alerts.isEmpty())
    }

    @Test
    fun metrics_buildInDeterministicOrder() {
        val jobs = JobHealthDto(
            jobs = listOf(job("x", "failed"), job("y", "healthy"), job("z", "degraded")),
        )
        val webhook = WebhookHealthSummaryDto(totalEndpoints = 5, enabledEndpoints = 4)
        val metrics = buildAdminMetrics(jobs, webhook)

        assertEquals(
            listOf(
                METRIC_TOTAL_JOBS,
                METRIC_UNHEALTHY_JOBS,
                METRIC_WEBHOOK_ENDPOINTS,
                METRIC_WEBHOOK_ENABLED,
                METRIC_WEBHOOK_DELIVERIES,
                METRIC_WEBHOOK_SUCCESS,
                METRIC_WEBHOOK_FAILED,
                METRIC_WEBHOOK_DEAD_LETTER,
            ),
            metrics.map { it.key },
        )
        // 2 unhealthy jobs (failed + degraded); healthy is not unhealthy.
        assertEquals("2", metrics.first { it.key == METRIC_UNHEALTHY_JOBS }.value)
        assertEquals("5", metrics.first { it.key == METRIC_WEBHOOK_ENDPOINTS }.value)
    }

    @Test
    fun fullyEmpty_dashboardIsEmpty() {
        val dashboard = toAdminDashboard(JobHealthDto(), zeroWebhook)
        assertTrue(dashboard.alerts.isEmpty())
        // metrics are always built (8 tiles), so the dashboard is NOT empty when health reads succeed with
        // zero counts; isEmpty is only true when BOTH lists are empty.
        assertTrue(dashboard.metrics.isNotEmpty())
        assertTrue(!dashboard.isEmpty)
    }
}
