package com.testlogon.android.notifications

import android.content.Context
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationChannelGroupCompat
import androidx.core.app.NotificationManagerCompat
import com.testlogon.android.R
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/** AND-107 — creates the typed notification channels. No-op on API < 26 (handled by *Compat). */
interface NotificationChannelInitializer {
    fun ensureChannels()
}

/**
 * AND-107 — builds the channel group + three channels via [NotificationManagerCompat].
 *
 * Idempotent: re-creating an existing channel only updates the mutable name; Android pins importance
 * after first creation, so the importances in FR-1 are fixed for the life of the install. Called once
 * from [com.testlogon.android.TestLogonApp.onCreate]. Wrapped in runCatching so an OEM quirk can't
 * crash startup; the presenter still falls back to NotificationCompat.setPriority.
 */
@Singleton
class DefaultNotificationChannelInitializer @Inject constructor(
    @ApplicationContext private val context: Context,
) : NotificationChannelInitializer {

    override fun ensureChannels() {
        runCatching {
            val manager = NotificationManagerCompat.from(context)
            val group = NotificationChannelGroupCompat.Builder(TlChannels.GROUP_ID)
                .setName(context.getString(R.string.notif_channel_group_name))
                .build()
            manager.createNotificationChannelGroup(group)

            val messages = NotificationChannelCompat.Builder(
                TlChannels.MESSAGES,
                NotificationManagerCompat.IMPORTANCE_HIGH,
            )
                .setName(context.getString(R.string.notif_channel_messages_name))
                .setGroup(TlChannels.GROUP_ID)
                .setVibrationEnabled(true)
                .build()

            val broadcasts = NotificationChannelCompat.Builder(
                TlChannels.BROADCASTS,
                NotificationManagerCompat.IMPORTANCE_DEFAULT,
            )
                .setName(context.getString(R.string.notif_channel_broadcasts_name))
                .setGroup(TlChannels.GROUP_ID)
                .setVibrationEnabled(false)
                .build()

            val alerts = NotificationChannelCompat.Builder(
                TlChannels.ALERTS,
                NotificationManagerCompat.IMPORTANCE_HIGH,
            )
                .setName(context.getString(R.string.notif_channel_alerts_name))
                .setGroup(TlChannels.GROUP_ID)
                .setVibrationEnabled(true)
                .build()

            manager.createNotificationChannelsCompat(listOf(messages, broadcasts, alerts))
        }
    }
}
