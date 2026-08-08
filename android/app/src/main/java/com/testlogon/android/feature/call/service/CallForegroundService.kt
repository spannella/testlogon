package com.testlogon.android.feature.call.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.testlogon.android.MainActivity
import com.testlogon.android.R
import com.testlogon.android.notifications.TlChannels
import com.testlogon.android.push.PushLog

/**
 * CALL-PIP FIX — the ongoing-call foreground service.
 *
 * A 1:1 call's media (native WebRTC capture + peer connection) and its control-plane heartbeat run on an
 * app-scoped [com.testlogon.android.feature.call.domain.CallManager] coroutine scope, NOT tied to any
 * Activity. Before this service existed, pressing Home backgrounded the whole process with no foreground
 * component: Android then throttled the process's network (observed on-device as
 * `UnknownHostException: Unable to resolve host` on the heartbeat poll), the heartbeat failed its 3
 * consecutive attempts, and CallManager ended the call with reason "network" — tearing down the peer and
 * powering the camera down ("Releasing pipeline"). That is exactly what broke Picture-in-Picture: the call
 * was dead before/at the moment the float would have shown live video.
 *
 * This service is started for the FULL duration of an active call (see [CallForegroundController]) so the
 * OS keeps the process foreground-privileged — network stays alive, the call scope survives, and the
 * camera keeps feeding, which is precisely what the PiP float renders. It declares
 * `camera|microphone` foreground types for a video call (microphone-only for audio) to match the media it
 * holds. The notification lets the user jump back into the call; it is NOT the incoming-call ring
 * (that is [com.testlogon.android.feature.call.incoming.IncomingCallNotifier]).
 */
class CallForegroundService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val video = intent?.getBooleanExtra(EXTRA_VIDEO, true) ?: true
        val peer = intent?.getStringExtra(EXTRA_PEER_NAME)
        runCatching { startForegroundCompat(video, peer) }
            .onFailure { PushLog.d("call FGS startForeground failed: ${it.javaClass.simpleName}") }
        // Sticky so a transient kill re-delivers; the controller stops it explicitly on call end.
        return START_STICKY
    }

    private fun startForegroundCompat(video: Boolean, peerName: String?) {
        val notification = buildNotification(peerName)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // camera type only for a video call (needs FOREGROUND_SERVICE_CAMERA + granted CAMERA);
            // microphone always (the call carries audio).
            var type = ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            if (video) type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA
            startForeground(NOTIF_ID, notification, type)
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    private fun buildNotification(peerName: String?): Notification {
        val content = peerName?.takeIf { it.isNotBlank() }
            ?.let { getString(R.string.call_ongoing_with, it) }
            ?: getString(R.string.call_ongoing)
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, TlChannels.CALLS)
            .setSmallIcon(R.drawable.ic_stat_notification)
            .setContentTitle(getString(R.string.call_ongoing_title))
            .setContentText(content)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setOngoing(true)
            .setAutoCancel(false)
            .setContentIntent(open)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    companion object {
        const val NOTIF_ID = 0x0CA1 // ongoing-call FGS (distinct from the incoming-ring notif ids)
        private const val EXTRA_VIDEO = "extra_video"
        private const val EXTRA_PEER_NAME = "extra_peer_name"

        fun start(context: Context, video: Boolean, peerName: String?) {
            val intent = Intent(context, CallForegroundService::class.java)
                .putExtra(EXTRA_VIDEO, video)
                .putExtra(EXTRA_PEER_NAME, peerName)
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            }.onFailure { PushLog.d("call FGS start failed: ${it.javaClass.simpleName}") }
        }

        fun stop(context: Context) {
            runCatching { context.stopService(Intent(context, CallForegroundService::class.java)) }
        }
    }
}
