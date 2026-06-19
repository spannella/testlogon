package com.testlogon.android.feature.call.incoming

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import com.testlogon.android.core.ui.theme.TestLogonTheme
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

/**
 * AND-297 — the lock-screen-capable, full-screen incoming-call Activity, launched by the notification's
 * fullScreenIntent (or directly when the app process is alive). Renders over the lock screen and turns the
 * screen on so the call rings + shows from a locked/asleep state.
 *
 * Declared in the manifest with showWhenLocked / turnScreenOn / excludeFromRecents. The notification action
 * buttons route here too (ACTION_ACCEPT / ACTION_DECLINE), funneling into the process-singleton
 * [IncomingCallController] so accept/decline work whether or not the UI is foreground.
 *
 * FLAG: inert without FCM — nothing launches it until a real `call.invite` is delivered.
 */
@AndroidEntryPoint
class IncomingCallActivity : ComponentActivity() {

    @Inject lateinit var controller: IncomingCallController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showWhenLockedAndTurnScreenOn()
        handleAction(intent)
        setContent {
            TestLogonTheme {
                @OptIn(ExperimentalComposeUiApi::class)
                Box(modifier = Modifier.fillMaxSize().semantics { testTagsAsResourceId = true }) {
                    IncomingCallScreen(
                        controller = controller,
                        onAccept = controller::accept,
                        onDecline = { controller.decline() },
                        onFinished = { finish() },
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleAction(intent)
    }

    /** Notification action buttons route ACCEPT/DECLINE here; SHOW just presents the UI. */
    private fun handleAction(intent: Intent?) {
        when (intent?.getStringExtra(EXTRA_ACTION)) {
            ACTION_ACCEPT -> controller.accept()
            ACTION_DECLINE -> controller.decline()
            else -> Unit
        }
    }

    private fun showWhenLockedAndTurnScreenOn() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
            (getSystemService(KeyguardManager::class.java))?.requestDismissKeyguard(this, null)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                android.view.WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                    android.view.WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
                    android.view.WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD,
            )
        }
    }

    companion object {
        const val EXTRA_CALL_ID = "extra_call_id"
        const val EXTRA_ACTION = "extra_action"
        const val ACTION_SHOW = "show"
        const val ACTION_ACCEPT = "accept"
        const val ACTION_DECLINE = "decline"

        fun intent(context: Context, callId: String, action: String): Intent =
            Intent(context, IncomingCallActivity::class.java).apply {
                putExtra(EXTRA_CALL_ID, callId)
                putExtra(EXTRA_ACTION, action)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
    }
}
