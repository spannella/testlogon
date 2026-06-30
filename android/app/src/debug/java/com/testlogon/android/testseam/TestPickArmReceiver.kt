package com.testlogon.android.testseam

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * DEBUG-ONLY BroadcastReceiver (declared exported in app/src/debug/AndroidManifest.xml) that arms
 * the media-picker seam from the host:
 *
 *   adb shell am broadcast -a com.testlogon.test.PICK --es kind image  -p com.testlogon.android
 *   adb shell am broadcast -a com.testlogon.test.PICK --es kind video  -p com.testlogon.android
 *   adb shell am broadcast -a com.testlogon.test.PICK --es kind pdf     -p com.testlogon.android
 *   adb shell am broadcast -a com.testlogon.test.PICK --es kind png     -p com.testlogon.android
 *   adb shell am broadcast -a com.testlogon.test.PICK --es kind multi_image --ei count 3 -p com.testlogon.android
 *   adb shell am broadcast -a com.testlogon.test.PICK --es kind camera  -p com.testlogon.android
 *   adb shell am broadcast -a com.testlogon.test.PICK --es kind clear   -p com.testlogon.android   (disarm)
 *
 * Arming only takes EFFECT if the gate is on (debug.testlogon.testhooks==1); otherwise the next
 * pick still goes to the real system picker. The arm is one-shot (consumed by the next pick).
 */
class TestPickArmReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        val kindStr = intent.getStringExtra("kind")?.lowercase()
        val count = intent.getIntExtra("count", 2).coerceAtLeast(1)
        if (kindStr == "clear" || kindStr == "disarm") {
            ArmState.clear()
            Log.i(TAG, "disarmed")
            return
        }
        val kind = when (kindStr) {
            "image" -> PickKind.IMAGE
            "video" -> PickKind.VIDEO
            "pdf" -> PickKind.PDF
            "png" -> PickKind.PNG
            "multi_image", "multi", "multiimage" -> PickKind.MULTI_IMAGE
            "multi_av", "av", "image_video" -> PickKind.MULTI_AV
            "camera" -> PickKind.CAMERA
            else -> {
                Log.w(TAG, "unknown kind=" + kindStr + " (expected image|video|pdf|png|multi_image|camera|clear)")
                return
            }
        }
        ArmState.arm(Arm(kind, count))
        Log.i(TAG, "armed kind=" + kind + " count=" + count + " gateEnabled=" + TestSeamGate.enabled())
    }

    companion object {
        const val ACTION = "com.testlogon.test.PICK"
        private const val TAG = "TestPickArmReceiver"
    }
}
