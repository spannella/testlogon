package com.testlogon.android.navigation.deeplink

import com.testlogon.android.notifications.NotificationKind
import com.testlogon.android.notifications.PushPayload

/**
 * AND-108 — typed deep-link target carried on a notification's PendingIntent and parsed back on tap.
 *
 * Pure/framework-free model (no android.* deps) so the mapping + parser logic is JVM-unit-testable.
 */
sealed interface NotificationDeepLink {
    data class Message(val threadId: String) : NotificationDeepLink
    data class Broadcast(val broadcastId: String) : NotificationDeepLink
    data class Alert(val alertId: String) : NotificationDeepLink

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

    const val TYPE_MESSAGE = "message"
    const val TYPE_BROADCAST = "broadcast"
    const val TYPE_ALERT = "alert"
    const val TYPE_GENERIC = "generic"

    /** Maps a parsed AND-107 [PushPayload] to the canonical deep-link target. Total over the kind. */
    fun fromPayload(payload: PushPayload): NotificationDeepLink = when (payload.kind) {
        NotificationKind.MESSAGE -> NotificationDeepLink.Message(payload.entityId)
        NotificationKind.BROADCAST -> NotificationDeepLink.Broadcast(payload.entityId)
        NotificationKind.ALERT -> NotificationDeepLink.Alert(payload.entityId)
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
    fun fromTypeAndId(type: String?, id: String?): NotificationDeepLink? {
        val nonBlankId = id?.takeIf { it.isNotBlank() } ?: return null
        return when (type) {
            TYPE_MESSAGE -> NotificationDeepLink.Message(nonBlankId)
            TYPE_BROADCAST -> NotificationDeepLink.Broadcast(nonBlankId)
            TYPE_ALERT -> NotificationDeepLink.Alert(nonBlankId)
            TYPE_GENERIC -> NotificationDeepLink.Generic(nonBlankId)
            else -> null
        }
    }
}
