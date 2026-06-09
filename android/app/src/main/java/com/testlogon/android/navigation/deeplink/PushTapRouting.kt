package com.testlogon.android.navigation.deeplink

import com.testlogon.android.data.notifications.NotificationType
import com.testlogon.android.feature.notifications.NotificationTarget
import com.testlogon.android.feature.notifications.NotificationTargetResolver

/**
 * AND-108 — bridges a tapped FCM push deep link to the EXISTING in-app notification routing.
 *
 * Rather than duplicate routing logic, push taps reuse the notification feature's
 * [NotificationTargetResolver] + [NotificationTarget] (AND-085), so a push notification and an
 * in-app notification of the same kind open the same destination. The push deep link only carries a
 * `type` + entity `id`, so we map the push kind to the resolver's [NotificationType] and feed the id
 * through the resolver's data map under its conventional key.
 *
 * Pure/framework-free (no android.*) so it is JVM-unit-testable.
 */
object PushTapRouting {

    fun targetFor(link: NotificationDeepLink): NotificationTarget = when (link) {
        // A "message" push has no first-party detail route yet -> resolver fails safe to Unknown,
        // which navigateToNotificationTarget lands on the Notification Center (never a dead end).
        is NotificationDeepLink.Message ->
            NotificationTargetResolver.resolve(NotificationType.MESSAGE, emptyMap())
        // Broadcast / alert have no dedicated NotificationType; route via SYSTEM -> Settings is wrong,
        // so resolve as UNKNOWN -> Notification Center until per-entity routes land (AND-108 §13 R1).
        is NotificationDeepLink.Broadcast ->
            NotificationTargetResolver.resolve(NotificationType.UNKNOWN, emptyMap())
        is NotificationDeepLink.Alert ->
            NotificationTargetResolver.resolve(NotificationType.UNKNOWN, emptyMap())
        is NotificationDeepLink.Generic ->
            NotificationTargetResolver.resolve(NotificationType.UNKNOWN, emptyMap())
    }
}
