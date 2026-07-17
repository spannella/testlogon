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
    FOLLOW, LIKE, COMMENT, MENTION, TIP, MESSAGE, SYSTEM,
    // MOD-D1 — poster moderation alerts (content hidden / violation confirmed / final call / dmca);
    // these deep-link to the "My content under review" screen. Reserved for a future engine bridge —
    // today moderation alerts arrive on the Alerts inbox (which deep-links via the same target).
    MODERATION,
    UNKNOWN;

    companion object {
        fun fromToken(token: String?): NotificationType {
            val t = token?.trim()?.lowercase() ?: return UNKNOWN
            // TIPX-E2 (N2): every tip vocabulary (tip_received / tip_sent / post_tip /
            // message_tip / tip_reversed / tip_refunded / tip_on_*) normalizes to TIP so
            // the client renders + deep-links tip notifications instead of dropping to UNKNOWN.
            if (t.startsWith("tip_") || t.endsWith("_tip")) return TIP
            return entries.firstOrNull { it != UNKNOWN && it.name.equals(t, ignoreCase = true) } ?: UNKNOWN
        }
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
