package com.testlogon.android.data.alerts

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Framework-free alerts domain models + total DTO -> domain mappers.
 *
 * [Alert.timestampSeconds] is an epoch-seconds timestamp; [Alert.readAt] null means unread. Mapping is
 * total: absent optionals default per the schema. Time formatting uses SimpleDateFormat/Date (core-
 * library desugaring is off, so java.time is unavailable) and stays JVM-unit-testable.
 */
enum class AlertPriority { URGENT, NORMAL, LOW }

data class Alert(
    val id: String,
    val event: String,
    val title: String,
    val timestampSeconds: Long,
    val readAt: Long?,
    val priority: AlertPriority,
    val actionUrl: String?,
    val category: String,
) {
    val isUnread: Boolean get() = readAt == null

    /** Human-readable timestamp, e.g. "Jun 17, 2:41 PM". */
    fun formattedTime(): String =
        if (timestampSeconds <= 0L) "" else TIME_FORMAT.format(Date(timestampSeconds * 1000L))

    private companion object {
        private val TIME_FORMAT = SimpleDateFormat("MMM d, h:mm a", Locale.getDefault())
    }
}

data class AlertsPage(
    val alerts: List<Alert>,
    val nextCursor: String?,
) {
    val isEmpty: Boolean get() = alerts.isEmpty()
    val unreadCount: Int get() = alerts.count { it.isUnread }
}

// ---- Mappers (DTO -> domain) ----

internal fun AlertDto.toDomain(): Alert = Alert(
    id = alertId,
    event = event.orEmpty(),
    title = title.orEmpty(),
    timestampSeconds = ts ?: 0L,
    // The backend marks unread via the `read` flag; read_at is 0 (not null) when unread.
    readAt = if (read) (readAt ?: 0L) else null,
    priority = when (priority?.lowercase(Locale.US)) {
        "urgent" -> AlertPriority.URGENT
        "low" -> AlertPriority.LOW
        else -> AlertPriority.NORMAL
    },
    actionUrl = actionUrl,
    category = category.orEmpty(),
)

/** The wire payload includes a synthetic UNREAD_COUNT sentinel row; drop it. */
internal fun AlertsRespDto.toDomain(): AlertsPage = AlertsPage(
    alerts = alerts.filter { it.alertId != "UNREAD_COUNT" }.map { it.toDomain() },
    nextCursor = nextCursor,
)
