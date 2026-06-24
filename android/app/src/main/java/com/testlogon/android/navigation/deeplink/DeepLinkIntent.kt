package com.testlogon.android.navigation.deeplink

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.testlogon.android.MainActivity

/**
 * AND-107/108 — builds and parses the notification tap [Intent] / [PendingIntent].
 *
 * The notification presenter (AND-107) MUST construct its tap PendingIntent via [pendingIntent] so
 * the producer and the [DeepLinkParser] consumer always agree on the extras contract
 * ([DeepLinkContract]). FLAG_IMMUTABLE is mandatory (target 35) so other apps cannot mutate the
 * target; FLAG_ACTIVITY_SINGLE_TOP routes a warm tap through MainActivity.onNewIntent.
 */
object DeepLinkIntentFactory {

    fun intent(context: Context, link: NotificationDeepLink): Intent =
        Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(DeepLinkContract.EXTRA_TYPE, DeepLinkContract.typeString(link))
            putExtra(DeepLinkContract.EXTRA_ID, DeepLinkContract.idOf(link))
            if (link is NotificationDeepLink.Message) {
                link.messageId?.let { putExtra(DeepLinkContract.EXTRA_MESSAGE_ID, it) }
            }
        }

    fun pendingIntent(context: Context, link: NotificationDeepLink, requestCode: Int): PendingIntent =
        PendingIntent.getActivity(
            context,
            requestCode,
            intent(context, link),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
}

/**
 * AND-108 — parses the tap Intent back into a [NotificationDeepLink], with intent-layer idempotency.
 *
 * Returns null when the intent carries no (valid) deep link or it was already consumed, so rotation
 * re-reading getIntent() does not re-navigate.
 */
object DeepLinkParser {

    fun parse(intent: Intent?): NotificationDeepLink? {
        intent ?: return null
        if (intent.getBooleanExtra(DeepLinkContract.EXTRA_CONSUMED, false)) return null
        // Foreground / app-built notification: the PendingIntent carries our typed extras.
        val type = intent.getStringExtra(DeepLinkContract.EXTRA_TYPE)
        if (type != null) {
            val id = intent.getStringExtra(DeepLinkContract.EXTRA_ID)
            val messageId = intent.getStringExtra(DeepLinkContract.EXTRA_MESSAGE_ID)
            return DeepLinkContract.fromTypeAndId(type, id, messageId)
        }
        // Background system-tray tap: FCM delivers the message `data` map as raw string extras.
        val fcmKind = intent.getStringExtra("kind") ?: intent.getStringExtra("type")
        if (fcmKind != null) {
            val convId = intent.getStringExtra("entity_id") ?: intent.getStringExtra("conversation_id")
            val messageId = intent.getStringExtra("message_id")
            return DeepLinkContract.fromTypeAndId(fcmKind, convId, messageId)
        }
        return null
    }

    fun markConsumed(intent: Intent?) {
        intent?.putExtra(DeepLinkContract.EXTRA_CONSUMED, true)
    }
}
