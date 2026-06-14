package com.testlogon.android.data.admin

import com.testlogon.android.core.model.admin.AdminAlert
import com.testlogon.android.core.model.admin.AdminDashboard
import com.testlogon.android.core.model.admin.AdminMetric
import com.testlogon.android.core.model.admin.AlertSeverity
import com.testlogon.android.core.model.admin.rank
import java.text.NumberFormat
import java.util.Locale

/**
 * AND-403 - DTO -> domain mappers for the READ-ONLY admin alerts/dashboards surface. They live in :app (NOT
 * core-model) because core-model cannot depend on core-network/Moshi DTOs (mirrors the AND-398 WebhookMappers
 * and AND-248 billing-config pattern).
 *
 * This is the heart of the CLIENT-SIDE AGGREGATION (AND-403 §4/§5): the two verified general-admin health reads
 * are folded into a single [AdminDashboard]. "Alerts" are DERIVED (unhealthy jobs + non-zero webhook failure /
 * dead-letter counts); "metric tiles" are derived from both summaries. Severity strings map with an UNKNOWN
 * fallback (NEVER throws on an unknown value - GOTCHA: enum-like wire fields). Alerts are sorted severity-desc
 * then createdAt-desc (AND-403 FR-10 / AC-4); metrics preserve a deterministic build order.
 *
 * The metric LABELS here are NON-localised English fallbacks held in the domain `value`/`label` only as a last
 * resort; the SCREEN renders user-facing tile labels from string resources keyed by [AdminMetric.key] (AND-403
 * §9 - all UI strings externalised). The `label` is kept for accessibility / non-resource contexts and the
 * count `value` is locale-formatted here (the tile is a dumb renderer).
 */

/** Maps a wire `health` string to an [AlertSeverity] (UNKNOWN fallback; never throws). */
fun mapJobHealthSeverity(health: String?): AlertSeverity = when (health?.trim()?.lowercase(Locale.ROOT)) {
    "healthy", "ok", "up" -> AlertSeverity.INFO
    "degraded", "warning", "warn", "stale" -> AlertSeverity.WARNING
    "failed", "error", "critical", "down", "unhealthy" -> AlertSeverity.CRITICAL
    "unknown", null, "" -> AlertSeverity.UNKNOWN
    else -> AlertSeverity.UNKNOWN
}

/** Locale-formats an integer count for a metric tile value (e.g. 1284 -> "1,284"). */
fun formatCount(value: Long): String = NumberFormat.getIntegerInstance(Locale.getDefault()).format(value)

/**
 * Builds the DERIVED alert list from the two health reads.
 *
 *  - Each job whose mapped severity is WARNING or CRITICAL becomes an alert (a healthy/info job is NOT an alert;
 *    an UNKNOWN-health job is surfaced as an UNKNOWN-severity alert so an operator still sees it).
 *  - A non-zero webhook `failed_count_24h` becomes a WARNING alert; a non-zero `dead_letter_count_24h` becomes a
 *    CRITICAL alert (dead-lettered deliveries are the most actionable webhook signal).
 *
 * The result is sorted severity-desc (CRITICAL first) then createdAt-desc (most-recent first), with a stable
 * id-asc tiebreak so ordering is deterministic for tests (AND-403 FR-10 / AC-4 / TC-02).
 */
fun buildAdminAlerts(
    jobHealth: JobHealthDto,
    webhookHealth: WebhookHealthSummaryDto,
): List<AdminAlert> {
    val alerts = mutableListOf<AdminAlert>()

    for (job in jobHealth.jobs) {
        val severity = mapJobHealthSeverity(job.health)
        if (severity == AlertSeverity.INFO) continue // a healthy job is not an alert
        val display = job.label.ifBlank { job.name }
        alerts += AdminAlert(
            id = "job_${job.name}",
            severity = severity,
            title = display,
            message = job.lastError ?: job.lastStatus,
            source = "jobs",
            createdAtEpochSeconds = job.lastFinishedAt ?: job.lastRunAt,
        )
    }

    if (webhookHealth.failedCount24h > 0L) {
        alerts += AdminAlert(
            id = "webhook_failed",
            severity = AlertSeverity.WARNING,
            title = "Webhook delivery failures (24h)",
            message = "${formatCount(webhookHealth.failedCount24h)} failed deliveries in the last 24h.",
            source = "webhooks",
            createdAtEpochSeconds = null,
        )
    }
    if (webhookHealth.deadLetterCount24h > 0L) {
        alerts += AdminAlert(
            id = "webhook_dead_letter",
            severity = AlertSeverity.CRITICAL,
            title = "Webhook dead-letter queue (24h)",
            message = "${formatCount(webhookHealth.deadLetterCount24h)} dead-lettered deliveries in the last 24h.",
            source = "webhooks",
            createdAtEpochSeconds = null,
        )
    }

    return alerts.sortedWith(
        compareByDescending<AdminAlert> { it.severity.rank }
            .thenByDescending { it.createdAtEpochSeconds ?: Long.MIN_VALUE }
            .thenBy { it.id },
    )
}

/**
 * Builds the metric-tile list (deterministic order). [AdminMetric.key] is the stable id the SCREEN uses to look
 * up a localised label; [label] is the English fallback / a11y label; [value] is the locale-formatted count.
 */
fun buildAdminMetrics(
    jobHealth: JobHealthDto,
    webhookHealth: WebhookHealthSummaryDto,
): List<AdminMetric> {
    val unhealthyJobs = jobHealth.jobs.count {
        val s = mapJobHealthSeverity(it.health)
        s == AlertSeverity.WARNING || s == AlertSeverity.CRITICAL
    }
    return listOf(
        AdminMetric(
            key = METRIC_TOTAL_JOBS,
            label = "Background jobs",
            value = formatCount(jobHealth.jobs.size.toLong()),
        ),
        AdminMetric(
            key = METRIC_UNHEALTHY_JOBS,
            label = "Unhealthy jobs",
            value = formatCount(unhealthyJobs.toLong()),
        ),
        AdminMetric(
            key = METRIC_WEBHOOK_ENDPOINTS,
            label = "Webhook endpoints",
            value = formatCount(webhookHealth.totalEndpoints),
        ),
        AdminMetric(
            key = METRIC_WEBHOOK_ENABLED,
            label = "Enabled endpoints",
            value = formatCount(webhookHealth.enabledEndpoints),
        ),
        AdminMetric(
            key = METRIC_WEBHOOK_DELIVERIES,
            label = "Deliveries (24h)",
            value = formatCount(webhookHealth.totalDeliveries24h),
        ),
        AdminMetric(
            key = METRIC_WEBHOOK_SUCCESS,
            label = "Successful (24h)",
            value = formatCount(webhookHealth.successCount24h),
        ),
        AdminMetric(
            key = METRIC_WEBHOOK_FAILED,
            label = "Failed (24h)",
            value = formatCount(webhookHealth.failedCount24h),
        ),
        AdminMetric(
            key = METRIC_WEBHOOK_DEAD_LETTER,
            label = "Dead-lettered (24h)",
            value = formatCount(webhookHealth.deadLetterCount24h),
        ),
    )
}

/** Folds the two health reads into the aggregated [AdminDashboard]. */
fun toAdminDashboard(
    jobHealth: JobHealthDto,
    webhookHealth: WebhookHealthSummaryDto,
): AdminDashboard = AdminDashboard(
    alerts = buildAdminAlerts(jobHealth, webhookHealth),
    metrics = buildAdminMetrics(jobHealth, webhookHealth),
)

// Stable metric keys (the screen maps these to localised labels; kept here so tests and UI agree).
const val METRIC_TOTAL_JOBS = "total_jobs"
const val METRIC_UNHEALTHY_JOBS = "unhealthy_jobs"
const val METRIC_WEBHOOK_ENDPOINTS = "webhook_endpoints"
const val METRIC_WEBHOOK_ENABLED = "webhook_enabled_endpoints"
const val METRIC_WEBHOOK_DELIVERIES = "webhook_deliveries_24h"
const val METRIC_WEBHOOK_SUCCESS = "webhook_success_24h"
const val METRIC_WEBHOOK_FAILED = "webhook_failed_24h"
const val METRIC_WEBHOOK_DEAD_LETTER = "webhook_dead_letter_24h"
