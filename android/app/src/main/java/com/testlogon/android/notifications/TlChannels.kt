package com.testlogon.android.notifications

/**
 * AND-107 — the fixed set of typed notification channels and the kind → channel mapping.
 *
 * Pure constants + a total mapping function; framework-free so it is JVM-unit-testable. Channel
 * objects themselves are created by DefaultNotificationChannelInitializer.
 */
enum class NotificationKind { MESSAGE, BROADCAST, ALERT, UNKNOWN }

object TlChannels {
    const val GROUP_ID = "tl_general"
    const val MESSAGES = "tl_messages"
    const val BROADCASTS = "tl_broadcasts"
    const val ALERTS = "tl_alerts"

    /** AND-297 — high-importance incoming-call channel (CallStyle + full-screen intent + ringtone). */
    const val CALLS = "tl_calls"

    /** Total mapping; unknown/broadcast route to the lowest-disruption visible channel (FR-4). */
    fun channelIdFor(kind: NotificationKind): String = when (kind) {
        NotificationKind.MESSAGE -> MESSAGES
        NotificationKind.ALERT -> ALERTS
        NotificationKind.BROADCAST, NotificationKind.UNKNOWN -> BROADCASTS
    }
}
