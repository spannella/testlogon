package com.testlogon.android.push

import com.google.firebase.messaging.RemoteMessage

/**
 * AND-105 — stable internal model decoupled from FCM's [RemoteMessage].
 *
 * Downstream code (channel display in AND-107, deep-link routing in AND-108) consumes this rather
 * than the Firebase type so the routing/display logic stays JVM-unit-testable without a live
 * Firebase (a [RemoteMessage] cannot be constructed off-device in plain JVM tests).
 *
 * `data` is the arbitrary FCM data map; reserved keys are defined by AND-107/AND-108
 * (see PushPayloadParser). Title/body come from the optional FCM notification block.
 */
data class PushMessage(
    val messageId: String?,
    val title: String?,
    val body: String?,
    val data: Map<String, String>,
    val sentTime: Long,
    val priority: Int,
) {
    companion object {
        fun from(rm: RemoteMessage): PushMessage = PushMessage(
            messageId = rm.messageId,
            title = rm.notification?.title,
            body = rm.notification?.body,
            data = rm.data,
            sentTime = rm.sentTime,
            priority = rm.priority,
        )
    }
}

/**
 * AND-105 — sink for FCM registration-token rotations.
 *
 * AND-106/AND-109 bind the real registrar that persists + uploads the token. The default
 * [LoggingPushTokenSink] logs a redacted prefix only.
 */
fun interface PushTokenSink {
    fun onTokenRefreshed(token: String)
}

/**
 * AND-105 — sink for inbound FCM messages.
 *
 * AND-107 binds the channel-aware notification display sink. The default [LoggingPushMessageSink]
 * logs the messageId + data key set (never values) and otherwise no-ops.
 */
fun interface PushMessageSink {
    fun onMessage(message: PushMessage)
}
