package com.testlogon.android.core.model.admin

/**
 * AND-403 - domain models for the READ-ONLY admin alerts/dashboards surface.
 *
 * core-model has NO Moshi / core-network dependency: these are plain domain types. The DTO -> domain bridge
 * lives in the :app feature (AdminMappers) since core-model cannot depend on core-network (mirrors the AND-398
 * webhooks + AND-248 billing-config pattern).
 *
 * CONTRACT NOTE (see the AND-403 CORRECTED spec, §2/§5/§16): there is NO `GET /ui/admin/alerts` and NO
 * `GET /ui/admin/metrics` endpoint and NO `severity`/`created_at` wire schema - the combined "alerts + metric
 * tiles" model is a CLIENT-SIDE AGGREGATION over the verified general-admin read endpoints
 * `GET ui/admin/jobs/health` ([JobHealthOut]) and `GET ui/admin/webhooks/health` ([WebhookHealthSummary]).
 * "Alerts" are DERIVED from unhealthy jobs and non-zero webhook failure / dead-letter counts; "metric tiles"
 * are derived from both health summaries. The fields below are therefore the client model, not a 1:1 wire shape.
 *
 * TIME: [AdminAlert.createdAtEpochSeconds] is an EPOCH-SECONDS [Long] (NOT java.time.Instant) to stay
 * minSdk-24-safe and keep core-model JVM unit tests java.time-free, matching the rest of core-model
 * (Webhook.createdAt, AccountStatus, etc.). The wire job timestamps are epoch-seconds integers; relative-time
 * formatting happens at the UI via DateUtils.
 */

/**
 * Visual + ordering severity for an [AdminAlert]. [UNKNOWN] is the safe fallback for an unrecognised wire
 * health string (the mapper NEVER throws on an unknown value). The declaration order is the SORT order
 * (CRITICAL first); see [AlertSeverity.rank].
 */
enum class AlertSeverity {
    CRITICAL,
    WARNING,
    INFO,
    UNKNOWN,
}

/**
 * Ordering rank for severity-desc sorting (CRITICAL highest). UNKNOWN sorts last (below INFO) so an
 * unclassifiable alert never masquerades as more urgent than a known one.
 */
val AlertSeverity.rank: Int
    get() = when (this) {
        AlertSeverity.CRITICAL -> 3
        AlertSeverity.WARNING -> 2
        AlertSeverity.INFO -> 1
        AlertSeverity.UNKNOWN -> 0
    }

/**
 * One read-only operational alert. [id] is a stable client-derived id (e.g. "job_<name>" /
 * "webhook_dead_letter"). [message] / [source] are nullable (some derived alerts have no extra body). The
 * alert carries NO acknowledge / dismiss / resolve affordance - this surface is read-only by construction
 * (AND-403 FR-5 / AC-3).
 */
data class AdminAlert(
    val id: String,
    val severity: AlertSeverity,
    val title: String,
    val message: String? = null,
    val source: String? = null,
    val createdAtEpochSeconds: Long? = null,
)

/**
 * One dashboard metric tile. [key] is a stable client id (e.g. "webhook_endpoints"); [label] is display copy;
 * [value] is the PRE-FORMATTED display string (the mapper formats counts, so the UI tile is dumb). [unit] /
 * [trend] are optional adornments.
 */
data class AdminMetric(
    val key: String,
    val label: String,
    val value: String,
    val unit: String? = null,
    val trend: String? = null,
)

/**
 * The aggregated read-only admin dashboard: [alerts] are pre-sorted by the mapper (severity-desc then
 * createdAt-desc); [metrics] preserve the mapper's deterministic build order (server is the source of truth -
 * AND-403 §6). [isEmpty] is true only when BOTH lists are empty (drives the VM's Empty state).
 */
data class AdminDashboard(
    val alerts: List<AdminAlert> = emptyList(),
    val metrics: List<AdminMetric> = emptyList(),
) {
    val isEmpty: Boolean get() = alerts.isEmpty() && metrics.isEmpty()
}
