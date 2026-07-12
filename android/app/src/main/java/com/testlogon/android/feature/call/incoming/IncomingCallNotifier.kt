package com.testlogon.android.feature.call.incoming

import android.annotation.SuppressLint
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.Person
import com.testlogon.android.R
import com.testlogon.android.data.call.CallEvent
import com.testlogon.android.notifications.NotificationPermissionState
import com.testlogon.android.notifications.TlChannels
import com.testlogon.android.push.PushLog
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-297 — builds + posts the high-priority, full-screen-intent incoming-call notification (the
 * "CallNotificationPresenter").
 *
 * Uses [NotificationCompat.CallStyle.forIncomingCall] on the high-importance `calls` channel (AND-107)
 * with [setFullScreenIntent] so the device rings + shows the full-screen UI from a locked/asleep state.
 * Degrades gracefully: when POST_NOTIFICATIONS is revoked or canUseFullScreenIntent() is false (API 34
 * policy) it still posts a heads-up CallStyle notification with action buttons (the ringer is independent).
 * Never throws — the push path must never crash.
 *
 * FLAG: this presenter is only reached once a real FCM `call.invite` is delivered; the FCM transport stays
 * behind the existing flagged push seam and is inert without google-services.json.
 *
 * Interface seam so [IncomingCallController] stays JVM-unit-testable with a fake notifier (no Context).
 */
interface IncomingCallNotifier {
    /** Posts (or refreshes) the ringing notification. @return true if posted. */
    fun showRinging(invite: CallEvent.Invite): Boolean

    /** Cancels the ringing notification for [callId]. Idempotent. */
    fun cancel(callId: String)
}

@Singleton
class SystemIncomingCallNotifier @Inject constructor(
    @ApplicationContext private val context: Context,
    private val permission: NotificationPermissionState,
) : IncomingCallNotifier {

    /** @return true if a notification was posted; false if dropped (no permission / error). */
    @SuppressLint("MissingPermission") // gated by NotificationPermissionState.isGranted()
    override fun showRinging(invite: CallEvent.Invite): Boolean {
        if (!permission.isGranted()) {
            PushLog.d("call notif dropped reason=no_permission")
            return false
        }
        return runCatching {
            val person = Person.Builder()
                .setName(invite.callerName ?: context.getString(R.string.call_unknown_caller))
                .setKey(invite.callerUserId)
                .build()
            val notification = NotificationCompat.Builder(context, TlChannels.CALLS)
                .setSmallIcon(R.drawable.ic_stat_notification)
                .setCategory(NotificationCompat.CATEGORY_CALL)
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setOngoing(true)
                .setAutoCancel(false)
                .setFullScreenIntent(fullScreenIntent(invite), true)
                .setStyle(
                    NotificationCompat.CallStyle.forIncomingCall(
                        person,
                        actionIntent(invite, IncomingCallActivity.ACTION_DECLINE),
                        actionIntent(invite, IncomingCallActivity.ACTION_ACCEPT),
                    ),
                )
                .build()
            NotificationManagerCompat.from(context).notify(notifId(invite.callId), notification)
            // A full-screen intent only auto-launches the activity when the device is locked/screen-off;
            // when the app is foreground (the hub delivers the invite in-app) start it directly too.
            runCatching {
                context.startActivity(
                    IncomingCallActivity.intent(context, invite.callId, IncomingCallActivity.ACTION_SHOW)
                        .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            }
            PushLog.d("call notif posted fullScreen=${canUseFullScreenIntent()}")
            true
        }.getOrElse {
            PushLog.d("call notif dropped reason=error")
            false
        }
    }

    /** Cancels the ringing notification for [callId]. Idempotent. */
    override fun cancel(callId: String) {
        runCatching { NotificationManagerCompat.from(context).cancel(notifId(callId)) }
    }

    private fun canUseFullScreenIntent(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            (context.getSystemService(NotificationManager::class.java))?.canUseFullScreenIntent() ?: true
        } else {
            true
        }

    private fun fullScreenIntent(invite: CallEvent.Invite): PendingIntent =
        actionIntent(invite, IncomingCallActivity.ACTION_SHOW)

    private fun actionIntent(invite: CallEvent.Invite, action: String): PendingIntent {
        val intent = IncomingCallActivity.intent(context, invite.callId, action)
        return PendingIntent.getActivity(
            context,
            (invite.callId + action).hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private fun notifId(callId: String): Int = NOTIF_ID_BASE + (callId.hashCode() and 0xFFFF)

    private companion object {
        const val NOTIF_ID_BASE = 0x0CA1_0000
    }
}
