package com.testlogon.android.data.admin

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET

/**
 * AND-403 - Retrofit binding + Moshi DTOs for the READ-ONLY admin alerts/dashboards surface.
 *
 * [CORRECTED contract - AND-403 §2/§4/§5/§16]: `GET /ui/admin/alerts` and `GET /ui/admin/metrics` DO NOT EXIST
 * (not in the backend OpenAPI). The combined "alerts + metric tiles" dashboard is a CLIENT-SIDE AGGREGATION
 * over the verified, general-admin (`admin`/`root`) read endpoints:
 *   GET ui/admin/jobs/health      -> [JobHealthDto]            (JobHealthOut: { jobs[], timestamp })
 *   GET ui/admin/webhooks/health  -> [WebhookHealthSummaryDto] (WebhookHealthSummary: 7 counts)
 *
 * Both are idempotent suspend GETs, with NO params, eligible for the shared GET-only bounded backoff. They live
 * on the SAME shared (authenticated) Retrofit configured by AND-027 (cookie jar + CSRF + 401-refresh
 * authenticator) - this ticket adds NO new auth/network plumbing and redefines NO auth/session method (mirrors
 * the AND-248 AdminBillingConfigApi reuse). Relative paths, NO leading slash; the @Path-free reads need no
 * tokens. The "alerts" list is DERIVED in the mapper from unhealthy jobs + non-zero webhook failure /
 * dead-letter counts; the "metric tiles" are derived from both summaries.
 *
 * This is a STRICTLY READ-ONLY interface (AND-403 FR-5 / AC-3 / §8): there is NO non-GET method anywhere; there
 * is nothing this screen can mutate server-side.
 *
 * CODEGEN: these are :app FEATURE DTOs and use @JsonClass(generateAdapter = true) codegen (the established :app
 * pattern - cf. AdminBillingConfigDto). The wire shapes are verified against the backend models
 * (app/models.py: JobHealthOut / JobHealthEntry / WebhookHealthSummary). Required keys per the backend: a job
 * entry's `name` (no default). Everything else carries a default so a row renders defensively; unknown wire
 * keys are tolerated by the codegen adapter.
 */
interface AdminApi {

    /** Per-job health (last/next run, status, error). General-admin gated; idempotent GET, no params. */
    @GET("ui/admin/jobs/health")
    suspend fun getJobHealth(): JobHealthDto

    /** Webhook delivery health summary (24h counts). General-admin gated; idempotent GET, no params. */
    @GET("ui/admin/webhooks/health")
    suspend fun getWebhookHealth(): WebhookHealthSummaryDto
}

// ---- DTOs (AND-403) - verified 1:1 against app/models.py JobHealthOut / JobHealthEntry ----

/** The job-health envelope: a list of per-job entries + the server snapshot timestamp (epoch seconds). */
@JsonClass(generateAdapter = true)
data class JobHealthDto(
    @Json(name = "jobs") val jobs: List<JobHealthEntryDto> = emptyList(),
    @Json(name = "timestamp") val timestamp: Long = 0L,
)

/**
 * One background job's derived health (the backend JobHealthEntry). `name` is the only required wire key; the
 * `health` string is OPEN ("healthy"/"degraded"/"failed"/"stale"/"unknown" observed) and is mapped to
 * [com.testlogon.android.core.model.admin.AlertSeverity] with an UNKNOWN fallback (never throws). `last_error` /
 * `last_status` feed an alert body; `last_finished_at` is the relative timestamp source.
 */
@JsonClass(generateAdapter = true)
data class JobHealthEntryDto(
    @Json(name = "name") val name: String,
    @Json(name = "label") val label: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "health") val health: String = "unknown",
    @Json(name = "last_status") val lastStatus: String? = null,
    @Json(name = "last_run_at") val lastRunAt: Long? = null,
    @Json(name = "last_finished_at") val lastFinishedAt: Long? = null,
    @Json(name = "last_error") val lastError: String? = null,
    @Json(name = "last_items_processed") val lastItemsProcessed: Long = 0L,
    @Json(name = "last_items_failed") val lastItemsFailed: Long = 0L,
    @Json(name = "next_run_at") val nextRunAt: Long? = null,
)

/**
 * The webhook delivery health summary (the backend WebhookHealthSummary). All seven fields are counts that
 * default to 0, so a partial/empty body still maps. `failed_count_24h` and `dead_letter_count_24h` drive
 * derived alerts when non-zero; all seven feed metric tiles.
 */
@JsonClass(generateAdapter = true)
data class WebhookHealthSummaryDto(
    @Json(name = "total_endpoints") val totalEndpoints: Long = 0L,
    @Json(name = "enabled_endpoints") val enabledEndpoints: Long = 0L,
    @Json(name = "disabled_endpoints") val disabledEndpoints: Long = 0L,
    @Json(name = "total_deliveries_24h") val totalDeliveries24h: Long = 0L,
    @Json(name = "success_count_24h") val successCount24h: Long = 0L,
    @Json(name = "failed_count_24h") val failedCount24h: Long = 0L,
    @Json(name = "dead_letter_count_24h") val deadLetterCount24h: Long = 0L,
)
