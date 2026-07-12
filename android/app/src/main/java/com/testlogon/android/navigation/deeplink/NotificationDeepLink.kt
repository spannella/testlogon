package com.testlogon.android.navigation.deeplink

import com.testlogon.android.notifications.NotificationKind
import com.testlogon.android.notifications.PushPayload

/**
 * AND-108 — typed deep-link target carried on a notification's PendingIntent and parsed back on tap.
 *
 * Pure/framework-free model (no android.* deps) so the mapping + parser logic is JVM-unit-testable.
 */
sealed interface NotificationDeepLink {
    data class Message(val threadId: String, val messageId: String? = null) : NotificationDeepLink
    data class Broadcast(val broadcastId: String) : NotificationDeepLink

    /**
     * ECOM-SELLER P1 — an alert push. [actionUrl] is the alert's relative deep-link
     * (e.g. `/seller/orders?sale={ship_group_id}`) carried in the FCM `data` payload so a
     * tapped system-tray push can route to the SAME destination as the in-app Alerts row
     * (e.g. the seller sale detail), not the app home. Null falls back to the alerts center.
     */
    data class Alert(val alertId: String, val actionUrl: String? = null) : NotificationDeepLink

    /** Generic in-app destination for kinds without a per-entity detail screen (route to a list). */
    data class Generic(val entityId: String) : NotificationDeepLink
}

/**
 * AND-107 <-> AND-108 — single source of truth for the Intent extras keys + discriminator values
 * shared by the notification presenter (producer) and the tap parser (consumer) so they never drift.
 */
object DeepLinkContract {
    const val EXTRA_TYPE = "tl.deeplink.type"
    const val EXTRA_ID = "tl.deeplink.id"
    const val EXTRA_DEEP_LINK = "tl.deeplink.uri"
    const val EXTRA_CONSUMED = "tl.deeplink.consumed"
    const val EXTRA_MESSAGE_ID = "tl.deeplink.message_id"
    // P1: the alert deep-link (relative action_url) carried on an app-built alert PendingIntent.
    const val EXTRA_ACTION_URL = "tl.deeplink.action_url"

    const val TYPE_MESSAGE = "message"
    const val TYPE_BROADCAST = "broadcast"
    const val TYPE_ALERT = "alert"
    const val TYPE_GENERIC = "generic"

    /** Maps a parsed AND-107 [PushPayload] to the canonical deep-link target. Total over the kind. */
    fun fromPayload(payload: PushPayload): NotificationDeepLink = when (payload.kind) {
        NotificationKind.MESSAGE -> NotificationDeepLink.Message(payload.entityId, payload.messageId)
        NotificationKind.BROADCAST -> NotificationDeepLink.Broadcast(payload.entityId)
        // P1: carry the alert's deep-link (parsed from the FCM `deep_link`/`action_url` key).
        NotificationKind.ALERT -> NotificationDeepLink.Alert(payload.entityId, payload.deepLink)
        NotificationKind.UNKNOWN -> NotificationDeepLink.Generic(payload.entityId)
    }

    fun typeString(link: NotificationDeepLink): String = when (link) {
        is NotificationDeepLink.Message -> TYPE_MESSAGE
        is NotificationDeepLink.Broadcast -> TYPE_BROADCAST
        is NotificationDeepLink.Alert -> TYPE_ALERT
        is NotificationDeepLink.Generic -> TYPE_GENERIC
    }

    fun idOf(link: NotificationDeepLink): String = when (link) {
        is NotificationDeepLink.Message -> link.threadId
        is NotificationDeepLink.Broadcast -> link.broadcastId
        is NotificationDeepLink.Alert -> link.alertId
        is NotificationDeepLink.Generic -> link.entityId
    }

    /** Reconstructs a [NotificationDeepLink] from a (type, id) pair, or null if unmappable. */
    fun fromTypeAndId(
        type: String?,
        id: String?,
        messageId: String? = null,
        actionUrl: String? = null,
    ): NotificationDeepLink? {
        val nonBlankId = id?.takeIf { it.isNotBlank() } ?: return null
        return when (type) {
            TYPE_MESSAGE -> NotificationDeepLink.Message(nonBlankId, messageId?.takeIf { it.isNotBlank() })
            TYPE_BROADCAST -> NotificationDeepLink.Broadcast(nonBlankId)
            // P1: carry the alert deep-link so the tap can resolve to the sale detail.
            TYPE_ALERT -> NotificationDeepLink.Alert(nonBlankId, actionUrl?.takeIf { it.isNotBlank() })
            TYPE_GENERIC -> NotificationDeepLink.Generic(nonBlankId)
            else -> null
        }
    }
}
