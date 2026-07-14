package com.testlogon.android.feature.notifications

import com.testlogon.android.data.notifications.Notification
import com.testlogon.android.data.notifications.NotificationType

/**
 * AND-089 — presentation model for a notification row.
 *
 * Adapts the domain [Notification]; [createdAtEpochSeconds] is the raw server epoch-seconds value so
 * the screen can localize relative timestamps. [target] is the resolved in-app deep-link target.
 */
data class NotificationUi(
    val id: String,
    val type: NotificationType,
    val title: String,
    val body: String,
    val isRead: Boolean,
    val createdAtEpochSeconds: Long,
    val batchCount: Int,
    val target: NotificationTarget,
)

internal fun Notification.toUi(forcedRead: Boolean = false): NotificationUi = NotificationUi(
    id = id,
    type = type,
    title = title,
    body = body,
    isRead = read || forcedRead,
    createdAtEpochSeconds = createdAtEpochSeconds,
    batchCount = batchCount,
    target = NotificationTargetResolver.resolve(type, data),
)

/**
 * AND-085 — typed in-app navigation target a notification can route to on tap.
 *
 * There is no server `deep_link`; routable hints (if any) live in the free-form `data` map. The
 * resolver fails safe to [Unknown] for unrecognized types or missing keys.
 */
sealed interface NotificationTarget {
    data class Profile(val identifier: String) : NotificationTarget
    data object Sessions : NotificationTarget
    data object Settings : NotificationTarget

    /** MOD-D1 — a poster moderation alert lands on the "My content under review" screen. */
    data object ModerationReview : NotificationTarget

    /** MODX-15 (C6): a ban / content-removal alert lands on Appeals (optionally pre-filled). */
    data class Appeals(val enforcementId: String? = null) : NotificationTarget

    data object Unknown : NotificationTarget
}

/**
 * AND-085 — pure resolver mapping a notification's type + data to a [NotificationTarget].
 *
 * The `data` payload is untyped (Record<string, unknown>); the keys below are a best-effort,
 * fail-safe convention. Any value used for navigation is validated (non-blank String) before use.
 */
object NotificationTargetResolver {

    // MODX-15: moderation events whose right next step is the appeal channel.
    private val MODERATION_ENFORCEMENT_ALERTS = setOf(
        "moderation_ban", "moderation_content_deleted", "moderation_content_removed",
    )

    fun resolve(type: NotificationType, data: Map<String, Any?>): NotificationTarget = when (type) {
        NotificationType.FOLLOW, NotificationType.MENTION ->
            stringValue(data, "u_identifier")?.let(NotificationTarget::Profile) ?: NotificationTarget.Unknown
        NotificationType.SYSTEM -> NotificationTarget.Settings
        // MOD-D1 — moderation alerts deep-link to the poster's content-review screen.
        NotificationType.MODERATION -> {
            val alertType = stringValue(data, "alert_type") ?: stringValue(data, "event")
            val enforcementId = stringValue(data, "enforcement_id")
            if (alertType in MODERATION_ENFORCEMENT_ALERTS || enforcementId != null) {
                NotificationTarget.Appeals(enforcementId)
            } else {
                NotificationTarget.ModerationReview
            }
        }
        // like / comment / tip / message have no first-party destination yet -> fail safe.
        else -> NotificationTarget.Unknown
    }

    private fun stringValue(data: Map<String, Any?>, key: String): String? =
        (data[key] as? String)?.takeIf { it.isNotBlank() }
}
