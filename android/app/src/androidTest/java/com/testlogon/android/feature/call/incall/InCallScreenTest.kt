package com.testlogon.android.feature.call.incall

import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-298 — Compose UI tests for the stateless [InCallScreen]. Renders with a hand-built [InCallUiState]
 * (no Hilt) and drives a tiny in-test reducer for the toggles under test.
 */
@RunWith(AndroidJUnit4::class)
class InCallScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun baseState(
        isVideoCall: Boolean = true,
        micEnabled: Boolean = true,
        cameraEnabled: Boolean = true,
        hasMultipleCameras: Boolean = true,
        quality: ConnectionQuality = ConnectionQuality.GOOD,
        lifecycle: InCallLifecycle = InCallLifecycle.Connected,
    ) = InCallUiState(
        callId = "c1",
        peerName = "Alex",
        lifecycle = lifecycle,
        isVideoCall = isVideoCall,
        hasRemoteVideo = false,
        micEnabled = micEnabled,
        cameraEnabled = cameraEnabled,
        hasMultipleCameras = hasMultipleCameras,
        quality = quality,
        showWeakBanner = quality == ConnectionQuality.POOR,
        durationLabel = "00:05",
        controlsVisible = true,
    )

    /** Renders the screen with a no-op action handler (for static assertions). */
    private fun launchStatic(initial: InCallUiState) {
        rule.setContent {
            TestLogonTheme {
                InCallScreen(state = initial, onAction = {})
            }
        }
    }

    // The mute control's content description reflects mic state. The toggle ACTION (onAction(ToggleMic)
    // flipping micEnabled) is covered by InCallViewModelTest; here we only assert the stateless screen
    // renders the right accessibility label per state (the cd node lives in the unmerged tree).
    @Test
    fun muteControl_showsMute_whenMicEnabled() {
        launchStatic(baseState(micEnabled = true))
        rule.onNodeWithContentDescription("Mute microphone", useUnmergedTree = true).assertIsEnabled()
    }

    @Test
    fun muteControl_showsUnmute_whenMicDisabled() {
        launchStatic(baseState(micEnabled = false))
        rule.onNodeWithContentDescription("Unmute microphone", useUnmergedTree = true).assertIsEnabled()
    }

    @Test
    fun camera_disabled_whenAudioOnly() {
        launchStatic(baseState(isVideoCall = false))
        rule.onNodeWithTag("incall_camera").assertIsNotEnabled()
    }

    @Test
    fun flip_disabled_whenSingleCamera() {
        launchStatic(baseState(hasMultipleCameras = false))
        rule.onNodeWithTag("incall_flip").assertIsNotEnabled()
    }

    @Test
    fun end_exposesEndCallContentDescription() {
        launchStatic(baseState())
        rule.onNodeWithContentDescription("End call").assertIsEnabled()
    }

    @Test
    fun weakBanner_present_whenQualityPoor() {
        launchStatic(baseState(quality = ConnectionQuality.POOR))
        rule.onNodeWithTag("incall_weak_banner", useUnmergedTree = true).assertExists()
    }

    @Test
    fun reconnectingSpinner_present_whenReconnecting() {
        launchStatic(baseState(lifecycle = InCallLifecycle.Reconnecting))
        rule.onNodeWithTag("incall_reconnecting", useUnmergedTree = true).assertExists()
    }

    @Test
    fun localPip_hidden_whenCameraOff() {
        launchStatic(baseState(cameraEnabled = false))
        rule.onNodeWithTag("incall_local_pip", useUnmergedTree = true).assertDoesNotExist()
    }
}
