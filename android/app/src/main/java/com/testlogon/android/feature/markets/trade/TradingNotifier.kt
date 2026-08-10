package com.testlogon.android.feature.markets.trade

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import androidx.compose.ui.graphics.toArgb
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.testlogon.android.R
import com.testlogon.android.core.ui.theme.BrandPrimary
import com.testlogon.android.notifications.NotificationChannelInitializer
import com.testlogon.android.notifications.NotificationPermissionState
import com.testlogon.android.notifications.TlChannels
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/** Distinct haptic patterns for trading feedback. */
enum class TradeHaptic { TICK, SUCCESS, WARN, ERROR }

/**
 * Trading feedback: haptics (via [Vibrator]) + system notifications for notable events (fills, algo/OTO
 * triggers, liquidation distress). Notifications route to the existing [TlChannels.ALERTS] channel and
 * are permission-gated + failure-safe (never throw). Haptics degrade to a no-op when the device has no
 * vibrator. Notable events buzz AND notify so a fill is felt even when you're on another tab.
 */
@Singleton
class TradingNotifier @Inject constructor(
    @ApplicationContext private val context: Context,
    private val permission: NotificationPermissionState,
    private val initializer: NotificationChannelInitializer,
) {
    private val vibrator: Vibrator? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            (context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager)?.defaultVibrator
        } else {
            @Suppress("DEPRECATION") context.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
        }
    }.getOrNull()

    // ---- haptics ----
    fun tick() = haptic(TradeHaptic.TICK)
    fun success() = haptic(TradeHaptic.SUCCESS)
    fun warn() = haptic(TradeHaptic.WARN)
    fun error() = haptic(TradeHaptic.ERROR)

    @Suppress("DEPRECATION")
    fun haptic(kind: TradeHaptic) {
        val v = vibrator ?: return
        if (!v.hasVibrator()) return
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val effect = when (kind) {
                    TradeHaptic.TICK -> VibrationEffect.createOneShot(12, VibrationEffect.DEFAULT_AMPLITUDE)
                    TradeHaptic.WARN -> VibrationEffect.createOneShot(35, VibrationEffect.DEFAULT_AMPLITUDE)
                    TradeHaptic.SUCCESS -> VibrationEffect.createWaveform(longArrayOf(0, 25, 60, 25), -1)
                    TradeHaptic.ERROR -> VibrationEffect.createWaveform(longArrayOf(0, 45, 55, 45, 55, 45), -1)
                }
                v.vibrate(effect)
            } else {
                val ms = when (kind) {
                    TradeHaptic.TICK -> 12L
                    TradeHaptic.WARN -> 35L
                    TradeHaptic.SUCCESS -> 60L
                    TradeHaptic.ERROR -> 120L
                }
                v.vibrate(ms)
            }
        }
    }

    // ---- notifications ----
    fun notifyFill(title: String, body: String) {
        success()
        post(title, body)
    }

    fun notifyTrigger(title: String, body: String) {
        success()
        post(title, body)
    }

    fun notifyDistress(title: String, body: String) {
        warn()
        post(title, body)
    }

    @SuppressLint("MissingPermission") // gated by NotificationPermissionState.isGranted()
    private fun post(title: String, body: String) {
        if (!permission.isGranted()) return
        runCatching {
            initializer.ensureChannels()
            val notifId = ("trade:" + title + body).hashCode()
            val launch = context.packageManager.getLaunchIntentForPackage(context.packageName)
            val pending = launch?.let {
                PendingIntent.getActivity(
                    context,
                    notifId,
                    it,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
            }
            val builder = NotificationCompat.Builder(context, TlChannels.ALERTS)
                .setSmallIcon(R.drawable.ic_stat_notification)
                .setColor(BrandPrimary.toArgb())
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setGroup(TlChannels.ALERTS)
                .setAutoCancel(true)
            if (pending != null) builder.setContentIntent(pending)
            NotificationManagerCompat.from(context).notify(notifId, builder.build())
        }
    }
}
