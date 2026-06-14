package com.testlogon.android.feature.call.incoming

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.Ringtone
import android.media.RingtoneManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-297 — ringtone + vibration for an incoming call.
 *
 * Interface seam so [IncomingCallController] stays JVM-unit-testable with a fake ringer (no audio
 * hardware). The default [SystemRinger] requests transient audio focus, loops the system ringtone, and
 * vibrates with a repeating pattern; it honors the ringer/DND mode (silent -> no tone), and is fully
 * guarded so an OEM quirk can never crash the push path.
 */
interface Ringer {
    fun start()
    fun stop()
}

@Singleton
class SystemRinger @Inject constructor(
    @ApplicationContext private val context: Context,
) : Ringer {

    private var ringtone: Ringtone? = null

    @Suppress("DEPRECATION")
    override fun start() {
        runCatching {
            val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
            // Honor silent mode: skip the tone but still vibrate where the device allows.
            if (audioManager?.ringerMode != AudioManager.RINGER_MODE_SILENT) {
                val uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
                ringtone = RingtoneManager.getRingtone(context, uri)?.apply {
                    audioAttributes = AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .build()
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        isLooping = true
                    }
                    play()
                }
            }
            startVibration()
        }
    }

    override fun stop() {
        runCatching {
            ringtone?.stop()
            ringtone = null
            vibrator()?.cancel()
        }
    }

    private fun startVibration() {
        val vibrator = vibrator() ?: return
        val pattern = longArrayOf(0, 800, 1_000)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            vibrator.vibrate(VibrationEffect.createWaveform(pattern, 0))
        } else {
            @Suppress("DEPRECATION")
            vibrator.vibrate(pattern, 0)
        }
    }

    private fun vibrator(): Vibrator? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            (context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager)?.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            context.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
        }
}
