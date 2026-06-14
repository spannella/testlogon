package com.testlogon.android.core.model.admin

/**
 * AND-404 - domain models for the READ-ONLY admin email/SMS delivery dashboards.
 *
 * core-model has NO Moshi / core-network dependency: these are plain domain types. The DTO -> domain bridge
 * (including PII MASKING and the epoch-seconds timestamp build) lives in the :app feature
 * (MessagingDashboardMappers) since core-model cannot depend on core-network/Moshi (mirrors the AND-403
 * AdminDashboard + AdminMappers pattern).
 *
 * CONTRACT NOTE (AND-404 CORRECTED spec, §4/§5/§16): there is NO combined dashboard document. Each channel's
 * data is a CLIENT-SIDE merge of two verified idempotent GETs - `GET /ui/admin/{email,sms}/dashboard/stats?days=7`
 * (EmailDashboardStatsOut / SmsDashboardStatsOut; rate fields are PERCENTAGES 0-100, not 0..1 fractions) and
 * `GET /ui/admin/{email,sms}/deliveries?limit=50` (MessagingDeliveryList, the "recent activity"). Delivery items
 * carry NO `id` and NO `provider`; `created_at` is EPOCH SECONDS (a number, not an ISO string); the recipient is
 * `to_email` (email) or `phone` (sms) and is FULL UNMASKED PII on the wire -> the :app mapper masks it before it
 * ever reaches this model (AND-404 §8 - only masked text is held in-memory / shown).
 *
 * This surface is READ-ONLY by construction (AND-404 FR5 / AC2): no acknowledge / resend / suppress affordance
 * exists anywhere; [DeliveryActivity] rows are inert display rows.
 */

/** Which delivery channel a dashboard shows. The channel selects the stats + deliveries endpoint pair. */
enum class DashboardChannel {
    EMAIL,
    SMS,
}

/**
 * The mapped delivery status of one activity row. The wire `status` is an OPEN free-form lowercase string
 * (the backend delivery item is an open map - the closed set is not enumerated), so [UNKNOWN] is the safe
 * fallback and the mapper NEVER throws on an unrecognised value (GOTCHA: enum-like wire fields).
 */
enum class DeliveryStatus {
    DELIVERED,
    SENT,
    PENDING,
    BOUNCED,
    FAILED,
    UNKNOWN,
}

/**
 * One read-only metric tile (e.g. "Delivered", "Delivery rate"). [value] is the PRE-FORMATTED display string
 * (the mapper locale-formats counts and percentages, so the UI tile is a dumb renderer). [emphasis] marks the
 * headline tile (delivery-rate) for visual weight. Mirrors AND-403 [AdminMetric] but kept distinct so the two
 * admin surfaces evolve independently.
 */
data class DashboardMetricCard(
    val key: String,
    val label: String,
    val value: String,
    val emphasis: Boolean = false,
)

/**
 * One read-only recent-delivery activity row.
 *
 * [key] is a stable client-derived key (the wire item has NO `id`): the mapper builds it from
 * (maskedRecipient + createdAtEpochSeconds) falling back to the list index, so a [LazyColumn] key is stable
 * and tests are deterministic. [maskedRecipient] is ALREADY MASKED (e.g. "j***@e***.com" / "***-***-4821") -
 * full PII never reaches this model (AND-404 §8). [detail] is the secondary line (email subject, or the SMS
 * failure/bounce reason) since the wire item exposes no `provider`. [createdAtEpochSeconds] is EPOCH SECONDS
 * (built from the wire `created_at` number via the mapper; the UI formats relative time via DateUtils, kept
 * minSdk-24-safe and core-model java.time-free, matching AdminAlert.createdAtEpochSeconds).
 */
data class DeliveryActivity(
    val key: String,
    val maskedRecipient: String,
    val status: DeliveryStatus,
    val detail: String? = null,
    val createdAtEpochSeconds: Long? = null,
)

/**
 * The aggregated read-only delivery dashboard for one [channel]: [metrics] (pre-formatted tiles in a
 * deterministic build order) + [activity] (the recent-delivery slice). [deliveryRatePct] is the raw 0-100
 * percentage retained for accessibility copy. [isEmpty] is true only when the stats are all-zero AND the
 * activity list is empty (the backend always returns 200 with zeroed fields, so emptiness is derived
 * client-side - AND-404 §7 / Open-assumption).
 */
data class MessagingDashboard(
    val channel: DashboardChannel,
    val metrics: List<DashboardMetricCard> = emptyList(),
    val deliveryRatePct: Double? = null,
    val activity: List<DeliveryActivity> = emptyList(),
    val allZeroStats: Boolean = true,
    /**
     * AND-404 §7 partial fan-out: true when the STATS read succeeded but the DELIVERIES (activity) read failed.
     * The screen still shows the metrics and surfaces a non-blocking inline notice for the missing activity
     * rather than blanking the whole screen (TC-09).
     */
    val activityFailed: Boolean = false,
) {
    val isEmpty: Boolean get() = allZeroStats && activity.isEmpty() && !activityFailed
}
