package com.testlogon.android.data.admin

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-404 - Retrofit binding + Moshi DTOs for the READ-ONLY admin email/SMS delivery dashboards.
 *
 * [CORRECTED contract - AND-404 §5/§16, verified against /openapi.json and the web
 * `adminMessagingDashboards.ts`]: the drafted `/dashboard/summary` + `/dashboard/activity` endpoints DO NOT
 * EXIST. The real, verified, idempotent GETs are:
 *   GET ui/admin/email/dashboard/stats?days=7  -> [EmailStatsDto]  (EmailDashboardStatsOut)
 *   GET ui/admin/sms/dashboard/stats?days=7    -> [SmsStatsDto]    (SmsDashboardStatsOut)
 *   GET ui/admin/email/deliveries?limit=50     -> [DeliveryListDto] (MessagingDeliveryList - "recent activity")
 *   GET ui/admin/sms/deliveries?limit=50       -> [DeliveryListDto] (MessagingDeliveryList)
 *
 * There is NO combined document; the repository fans out stats + deliveries per channel concurrently and
 * merges. All four live on the SAME shared (authenticated) Retrofit from AND-027 (cookie jar + CSRF + Bearer +
 * 401-refresh) reused by AND-403 - this ticket adds NO auth/network plumbing. Relative paths, NO leading slash;
 * params are passed via @Query (`days` default 7; `limit` 50). All are GET-only -> eligible for the shared
 * bounded backoff; NO mutating method exists anywhere on this interface (AND-404 FR5 / AC2 / §8).
 *
 * CODEGEN: these are :app FEATURE DTOs and use @JsonClass(generateAdapter = true) codegen (the established :app
 * pattern - cf. AND-403 AdminApi). Every numeric field carries a default so a partial/empty body still maps;
 * unknown wire keys are tolerated by the codegen adapter; rate fields are PERCENTAGES 0-100 (NOT 0..1).
 */
interface MessagingDashboardApi {

    /** Email delivery stats (volume + delivery/bounce/complaint rates) over [days]. Idempotent GET. */
    @GET("ui/admin/email/dashboard/stats")
    suspend fun getEmailStats(@Query("days") days: Int = DEFAULT_DAYS): EmailStatsDto

    /** SMS delivery stats (volume + delivery/failure rates + segments/cost) over [days]. Idempotent GET. */
    @GET("ui/admin/sms/dashboard/stats")
    suspend fun getSmsStats(@Query("days") days: Int = DEFAULT_DAYS): SmsStatsDto

    /** Recent email deliveries (the activity list). Bounded recent slice; cursor ignored this ticket. */
    @GET("ui/admin/email/deliveries")
    suspend fun getEmailDeliveries(@Query("limit") limit: Int = DEFAULT_LIMIT): DeliveryListDto

    /** Recent SMS deliveries (the activity list). Bounded recent slice; cursor ignored this ticket. */
    @GET("ui/admin/sms/deliveries")
    suspend fun getSmsDeliveries(@Query("limit") limit: Int = DEFAULT_LIMIT): DeliveryListDto

    companion object {
        /** Backend/web default window (min 1, max 365). AND-404 sends 7 and exposes no selector (FR7). */
        const val DEFAULT_DAYS = 7

        /** Bounded recent-activity slice; `next_cursor` is ignored this ticket (a "showing recent N" footer). */
        const val DEFAULT_LIMIT = 50
    }
}

// ---- DTOs (AND-404) - verified 1:1 against EmailDashboardStatsOut / SmsDashboardStatsOut / MessagingDeliveryList ----

/**
 * EmailDashboardStatsOut. Rate fields are PERCENTAGES 0-100 (verified: `minimum:0, maximum:100`). There is NO
 * `total_sent` / `pending` / `provider` / `window` (drafted fields removed on review).
 */
@JsonClass(generateAdapter = true)
data class EmailStatsDto(
    @Json(name = "sent") val sent: Int = 0,
    @Json(name = "delivered") val delivered: Int = 0,
    @Json(name = "bounced") val bounced: Int = 0,
    @Json(name = "complained") val complained: Int = 0,
    @Json(name = "failed") val failed: Int = 0,
    @Json(name = "suppressed") val suppressed: Int = 0,
    @Json(name = "total") val total: Int = 0,
    @Json(name = "delivery_rate") val deliveryRate: Double = 0.0,
    @Json(name = "bounce_rate") val bounceRate: Double = 0.0,
    @Json(name = "complaint_rate") val complaintRate: Double = 0.0,
    @Json(name = "period_days") val periodDays: Int = MessagingDashboardApi.DEFAULT_DAYS,
)

/**
 * SmsDashboardStatsOut. No `bounced` (SMS has no bounce); adds segments/cost/failure_rate. Rate fields are
 * PERCENTAGES 0-100.
 */
@JsonClass(generateAdapter = true)
data class SmsStatsDto(
    @Json(name = "sent") val sent: Int = 0,
    @Json(name = "delivered") val delivered: Int = 0,
    @Json(name = "failed") val failed: Int = 0,
    @Json(name = "total") val total: Int = 0,
    @Json(name = "total_segments") val totalSegments: Int = 0,
    @Json(name = "estimated_cost_usd") val estimatedCostUsd: Double = 0.0,
    @Json(name = "suppressed_numbers") val suppressedNumbers: Int = 0,
    @Json(name = "delivery_rate") val deliveryRate: Double = 0.0,
    @Json(name = "failure_rate") val failureRate: Double = 0.0,
    @Json(name = "period_days") val periodDays: Int = MessagingDashboardApi.DEFAULT_DAYS,
)

/**
 * One MessagingDeliveryItem (a "recent activity" row). The recipient is `to_email` (email channel) or `phone`
 * (sms channel) and is FULL UNMASKED PII on the wire (the :app mapper masks it). `created_at` is EPOCH SECONDS
 * (a number; the mapper does `Instant.ofEpochSecond` / DateUtils, NOT an ISO parse). There is NO `id` and NO
 * `provider`; the secondary line uses `subject` (email) or `bounce_type`/`error` (failure detail). Every field
 * is nullable/defaulted so a partial item still maps.
 */
@JsonClass(generateAdapter = true)
data class DeliveryItemDto(
    @Json(name = "to_email") val toEmail: String? = null,
    @Json(name = "phone") val phone: String? = null,
    @Json(name = "subject") val subject: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "bounce_type") val bounceType: String? = null,
    @Json(name = "diagnostic_code") val diagnosticCode: String? = null,
    @Json(name = "error") val error: String? = null,
    @Json(name = "segments") val segments: Int? = null,
)

/** MessagingDeliveryList. The page cursor field is `next_cursor` (NOT `next`); it is ignored this ticket. */
@JsonClass(generateAdapter = true)
data class DeliveryListDto(
    @Json(name = "items") val items: List<DeliveryItemDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)
