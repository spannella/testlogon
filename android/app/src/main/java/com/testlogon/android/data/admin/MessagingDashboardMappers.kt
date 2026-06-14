package com.testlogon.android.data.admin

import com.testlogon.android.core.model.admin.DashboardChannel
import com.testlogon.android.core.model.admin.DashboardMetricCard
import com.testlogon.android.core.model.admin.DeliveryActivity
import com.testlogon.android.core.model.admin.DeliveryStatus
import com.testlogon.android.core.model.admin.MessagingDashboard
import java.text.NumberFormat
import java.util.Locale

/**
 * AND-404 - DTO -> domain mappers for the READ-ONLY admin email/SMS delivery dashboards. They live in :app (NOT
 * core-model) because core-model cannot depend on the Moshi DTOs (mirrors AND-403 AdminMappers).
 *
 * Responsibilities (AND-404 §5/§6/§8):
 *  - build the per-channel metric tiles (locale-formatted counts; rate fields are PERCENTAGES 0-100, rendered
 *    "94.3%" - NOT "9430%"); SMS shows failed/failure-rate/segments and NO bounced card;
 *  - map the delivery `status` open string -> [DeliveryStatus] with an UNKNOWN fallback (never throws);
 *  - MASK the recipient PII ([maskEmail] / [maskPhone]) BEFORE it leaves the data layer (the wire is unmasked);
 *  - build the activity timestamp from the EPOCH-SECONDS `created_at` number (no ISO parse, no *1000 here - the
 *    UI multiplies for DateUtils, matching AdminAlert.createdAtEpochSeconds);
 *  - derive a stable per-row key (the wire item has NO `id`) from maskedRecipient+createdAt, else the index;
 *  - derive emptiness client-side (all-zero stats AND empty activity), since the backend always returns 200.
 */

// ---- stable metric keys (the screen maps these to localised labels; kept here so tests + UI agree) ----
const val METRIC_MSG_SENT = "msg_sent"
const val METRIC_MSG_DELIVERED = "msg_delivered"
const val METRIC_MSG_BOUNCED = "msg_bounced"
const val METRIC_MSG_FAILED = "msg_failed"
const val METRIC_MSG_SUPPRESSED = "msg_suppressed"
const val METRIC_MSG_SEGMENTS = "msg_segments"
const val METRIC_MSG_DELIVERY_RATE = "msg_delivery_rate"

/** Maps a wire delivery `status` string to a [DeliveryStatus] (UNKNOWN fallback; never throws). */
fun mapDeliveryStatus(status: String?): DeliveryStatus = when (status?.trim()?.lowercase(Locale.ROOT)) {
    "delivered" -> DeliveryStatus.DELIVERED
    "sent" -> DeliveryStatus.SENT
    "pending", "queued", "queuing", "accepted" -> DeliveryStatus.PENDING
    "bounced", "bounce" -> DeliveryStatus.BOUNCED
    "failed", "failure", "error", "undelivered", "rejected" -> DeliveryStatus.FAILED
    else -> DeliveryStatus.UNKNOWN
}

/** Locale-formats an integer count for a metric tile value (e.g. 12840 -> "12,840"). */
fun formatMessagingCount(value: Int): String =
    NumberFormat.getIntegerInstance(Locale.getDefault()).format(value.toLong())

/** Formats a 0-100 percentage to one decimal place, locale-aware (e.g. 94.3 -> "94.3%"). */
fun formatPercent(value: Double): String {
    val nf = NumberFormat.getNumberInstance(Locale.getDefault()).apply {
        minimumFractionDigits = 0
        maximumFractionDigits = 1
    }
    return "${nf.format(value)}%"
}

/** Formats a USD cost to two decimals, locale-aware (e.g. 38.4 -> "$38.40"). */
fun formatUsd(value: Double): String = NumberFormat.getCurrencyInstance(Locale.US).format(value)

/**
 * Masks an email to "j***@e***.com" form. Keeps the first char of the local part, the first char of the domain
 * label, and the public suffix; everything else becomes "***". A malformed / blank value yields a safe
 * placeholder (no exception, no PII leak). AND-404 §8.
 */
fun maskEmail(raw: String?): String {
    val value = raw?.trim().orEmpty()
    if (value.isEmpty()) return MASKED_PLACEHOLDER
    val at = value.indexOf('@')
    if (at <= 0 || at == value.lastIndex) return MASKED_PLACEHOLDER
    val local = value.substring(0, at)
    val domain = value.substring(at + 1)
    val dot = domain.lastIndexOf('.')
    val maskedLocal = "${local.first()}***"
    return if (dot <= 0) {
        "$maskedLocal@${domain.first()}***"
    } else {
        val host = domain.substring(0, dot)
        val tld = domain.substring(dot) // includes the dot
        "$maskedLocal@${host.first()}***$tld"
    }
}

/**
 * Masks a phone number, revealing only the last 4 digits ("***-***-4821" style). Non-digits are dropped for the
 * length check; a value with fewer than 4 digits, or blank, yields a safe placeholder. AND-404 §8.
 */
fun maskPhone(raw: String?): String {
    val digits = raw?.filter { it.isDigit() }.orEmpty()
    if (digits.length < 4) return MASKED_PLACEHOLDER
    return "***-***-${digits.takeLast(4)}"
}

private const val MASKED_PLACEHOLDER = "•••"

/** Maps one wire delivery item to a masked, inert [DeliveryActivity] row for the given [channel]. */
fun toDeliveryActivity(item: DeliveryItemDto, channel: DashboardChannel, index: Int): DeliveryActivity {
    val masked = when (channel) {
        DashboardChannel.EMAIL -> maskEmail(item.toEmail)
        DashboardChannel.SMS -> maskPhone(item.phone ?: item.toEmail)
    }
    // Secondary line: email subject, else the failure/bounce reason (no `provider` exists on the wire).
    val detail = when (channel) {
        DashboardChannel.EMAIL -> item.subject?.takeIf { it.isNotBlank() }
            ?: item.bounceType?.takeIf { it.isNotBlank() }
            ?: item.error?.takeIf { it.isNotBlank() }
        DashboardChannel.SMS -> item.error?.takeIf { it.isNotBlank() }
            ?: item.bounceType?.takeIf { it.isNotBlank() }
    }
    val key = item.createdAt?.let { "$masked@$it" } ?: "$masked#$index"
    return DeliveryActivity(
        key = key,
        maskedRecipient = masked,
        status = mapDeliveryStatus(item.status),
        detail = detail,
        createdAtEpochSeconds = item.createdAt,
    )
}

/** Builds the EMAIL dashboard from the stats + deliveries reads (masked activity, derived emptiness). */
fun toEmailDashboard(stats: EmailStatsDto, deliveries: DeliveryListDto): MessagingDashboard {
    val metrics = listOf(
        DashboardMetricCard(METRIC_MSG_SENT, "Sent", formatMessagingCount(stats.sent)),
        DashboardMetricCard(METRIC_MSG_DELIVERED, "Delivered", formatMessagingCount(stats.delivered)),
        DashboardMetricCard(METRIC_MSG_BOUNCED, "Bounced", formatMessagingCount(stats.bounced)),
        DashboardMetricCard(METRIC_MSG_FAILED, "Failed", formatMessagingCount(stats.failed)),
        DashboardMetricCard(METRIC_MSG_SUPPRESSED, "Suppressed", formatMessagingCount(stats.suppressed)),
        DashboardMetricCard(
            METRIC_MSG_DELIVERY_RATE,
            "Delivery rate",
            formatPercent(stats.deliveryRate),
            emphasis = true,
        ),
    )
    val activity = deliveries.items.mapIndexed { i, item ->
        toDeliveryActivity(item, DashboardChannel.EMAIL, i)
    }
    val allZero = stats.sent == 0 && stats.delivered == 0 && stats.bounced == 0 &&
        stats.failed == 0 && stats.suppressed == 0 && stats.total == 0
    return MessagingDashboard(
        channel = DashboardChannel.EMAIL,
        metrics = metrics,
        deliveryRatePct = stats.deliveryRate,
        activity = activity,
        allZeroStats = allZero,
    )
}

/** Builds the SMS dashboard from the stats + deliveries reads (no bounced card; segments + failure-rate). */
fun toSmsDashboard(stats: SmsStatsDto, deliveries: DeliveryListDto): MessagingDashboard {
    val metrics = listOf(
        DashboardMetricCard(METRIC_MSG_SENT, "Sent", formatMessagingCount(stats.sent)),
        DashboardMetricCard(METRIC_MSG_DELIVERED, "Delivered", formatMessagingCount(stats.delivered)),
        DashboardMetricCard(METRIC_MSG_FAILED, "Failed", formatMessagingCount(stats.failed)),
        DashboardMetricCard(METRIC_MSG_SEGMENTS, "Segments", formatMessagingCount(stats.totalSegments)),
        DashboardMetricCard(METRIC_MSG_SUPPRESSED, "Suppressed", formatMessagingCount(stats.suppressedNumbers)),
        DashboardMetricCard(
            METRIC_MSG_DELIVERY_RATE,
            "Delivery rate",
            formatPercent(stats.deliveryRate),
            emphasis = true,
        ),
    )
    val activity = deliveries.items.mapIndexed { i, item ->
        toDeliveryActivity(item, DashboardChannel.SMS, i)
    }
    val allZero = stats.sent == 0 && stats.delivered == 0 && stats.failed == 0 &&
        stats.total == 0 && stats.totalSegments == 0
    return MessagingDashboard(
        channel = DashboardChannel.SMS,
        metrics = metrics,
        deliveryRatePct = stats.deliveryRate,
        activity = activity,
        allZeroStats = allZero,
    )
}
