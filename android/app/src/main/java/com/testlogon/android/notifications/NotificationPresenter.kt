package com.testlogon.android.notifications

import android.annotation.SuppressLint
import android.content.Context
import androidx.compose.ui.graphics.toArgb
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.testlogon.android.R
import com.testlogon.android.core.ui.theme.BrandPrimary
import com.testlogon.android.navigation.deeplink.DeepLinkContract
import com.testlogon.android.navigation.deeplink.DeepLinkIntentFactory
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-107 — turns a parsed [PushPayload] into a channel-bound system notification.
 *
 * Routing: [NotificationKind] -> channel id ([TlChannels.channelIdFor]); unknown -> broadcasts.
 * Dedupe: the notification id is `entityId.hashCode()` so a re-pushed update replaces rather than
 * stacks (FR-9). Tap: a PendingIntent built via [DeepLinkIntentFactory] (FLAG_IMMUTABLE, single-top)
 * carrying the AND-108 deep-link extras. Degrades gracefully (FR-7): returns false (no post) when the
 * runtime permission is ungranted; never throws.
 */
@Singleton
class NotificationPresenter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val permission: NotificationPermissionState,
    private val initializer: NotificationChannelInitializer,
) {

    /** @return true if a notification was posted; false if dropped (no permission / error). */
    @SuppressLint("MissingPermission") // gated by NotificationPermissionState.isGranted()
    fun show(payload: PushPayload): Boolean {
        if (!permission.isGranted()) {
            com.testlogon.android.push.PushLog.d("notif dropped reason=no_permission")
            return false
        }
        return runCatching {
            initializer.ensureChannels()
            val channelId = TlChannels.channelIdFor(payload.kind)
            val notifId = payload.entityId.hashCode()
            val link = DeepLinkContract.fromPayload(payload)
            val pending = DeepLinkIntentFactory.pendingIntent(context, link, notifId)

            val priority = when (payload.kind) {
                NotificationKind.MESSAGE, NotificationKind.ALERT -> NotificationCompat.PRIORITY_HIGH
                else -> NotificationCompat.PRIORITY_DEFAULT
            }

            val notification = NotificationCompat.Builder(context, channelId)
                .setSmallIcon(R.drawable.ic_stat_notification)
                .setColor(BrandPrimary.toArgb())
                .setContentTitle(payload.title)
                .setContentText(payload.body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(payload.body))
                .setPriority(priority)
                .setGroup(channelId)
                .setAutoCancel(true)
                .setContentIntent(pending)
                .build()

            NotificationManagerCompat.from(context).notify(notifId, notification)
            com.testlogon.android.push.PushLog.d(
                "notif posted kind=${payload.kind} channel=$channelId entityId=${payload.entityId}",
            )
            true
        }.getOrElse {
            com.testlogon.android.push.PushLog.d("notif dropped reason=channel_error")
            false
        }
    }
}

/**
 * AND-105/107 — the real [com.testlogon.android.push.PushMessageSink] binding (replaces AND-105's
 * logging default): parses the inbound data message and posts it via [NotificationPresenter].
 *
 * AND-297: a `call.*` data message is intercepted FIRST by [com.testlogon.android.feature.call.incoming
 * .CallPushHandler] (ring + full-screen via the CallStyle path) and skips the generic display. Everything
 * else falls through to the channel-bound notification. The call interception is inert without FCM — the
 * flagged push seam never delivers a `call.invite` without google-services.json.
 */
@Singleton
class NotificationDisplaySink @Inject constructor(
    private val parser: PushPayloadParser,
    private val presenter: NotificationPresenter,
    private val callPushHandler: com.testlogon.android.feature.call.incoming.CallPushHandler,
) : com.testlogon.android.push.PushMessageSink {

    override fun onMessage(message: com.testlogon.android.push.PushMessage) {
        // AND-297: route incoming/terminal call data messages to the call orchestrators first.
        if (callPushHandler.tryHandle(message.data)) return

        val payload = parser.parse(message.data)
        if (payload == null) {
            com.testlogon.android.push.PushLog.d("notif dropped reason=invalid_payload")
            return
        }
        presenter.show(payload)
    }
}
