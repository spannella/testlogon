package com.testlogon.android.data.notifications

/**
 * AND-084 — domain model + mapping for notifications (framework-free, JVM-unit-test safe).
 *
 * Timestamps are kept as epoch SECONDS Long in the domain (no java.time at this layer) so the
 * mapper is minSdk24-safe and unit-testable without desugaring; relative-time formatting is a UI
 * concern. The notification "type" is normalized to [NotificationType]; unknown tokens fall back to
 * [NotificationType.UNKNOWN] (never throws) so additive backend kinds cannot crash the list.
 *
 * The verified taxonomy comes from reference/src/pages/notifications/NotificationsPage.tsx TYPE_ICONS:
 * follow, like, comment, mention, tip, message, system.
 */
enum class NotificationType {
    FOLLOW, LIKE, COMMENT, MENTION, TIP, MESSAGE, SYSTEM, UNKNOWN;

    companion object {
        fun fromToken(token: String?): NotificationType =
            entries.firstOrNull { it != UNKNOWN && it.name.equals(token, ignoreCase = true) } ?: UNKNOWN
    }
}

/** A single notification as consumed by the feature layer. */
data class Notification(
    val id: String,
    val type: NotificationType,
    val title: String,
    val body: String,
    val read: Boolean,
    /** Epoch SECONDS (server contract). 0 maps to the Unix epoch. */
    val createdAtEpochSeconds: Long,
    val batchKey: String?,
    val batchCount: Int,
    val batchActors: List<String>,
    val data: Map<String, Any?>,
)

/** One page of notifications + the opaque cursor for the next page (null = terminal). */
data class NotificationPage(
    val items: List<Notification>,
    val nextCursor: String?,
)

internal fun NotificationDto.toDomain(): Notification = Notification(
    id = notificationId,
    type = NotificationType.fromToken(notificationType),
    title = title,
    body = body,
    read = read,
    createdAtEpochSeconds = createdAt,
    batchKey = batchKey,
    batchCount = batchCount,
    batchActors = batchActors,
    data = data,
)
