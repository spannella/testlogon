package com.testlogon.android.feature.call.incall

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
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

    /** Renders the screen with an in-test reducer that applies mic/camera toggles locally. */
    private fun launchReducing(initial: InCallUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by mutableStateOf(initial)
                InCallScreen(
                    state = state,
                    onAction = { action ->
                        state = when (action) {
                            InCallAction.ToggleMic -> state.copy(micEnabled = !state.micEnabled)
                            InCallAction.ToggleCamera ->
                                if (state.isVideoCall) state.copy(cameraEnabled = !state.cameraEnabled) else state
                            else -> state
                        }
                    },
                )
            }
        }
    }

    /** Renders the screen with a no-op action handler (for static assertions). */
    private fun launchStatic(initial: InCallUiState) {
        rule.setContent {
            TestLogonTheme {
                InCallScreen(state = initial, onAction = {})
            }
        }
    }

    @Test
    fun mute_showsMute_thenFlipsToUnmute() {
        launchReducing(baseState(micEnabled = true))
        rule.onNodeWithContentDescription("Mute microphone").assertIsEnabled()
        rule.onNodeWithTag("incall_mute").performClick()
        rule.onNodeWithContentDescription("Unmute microphone").assertIsEnabled()
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
        rule.onNodeWithTag("incall_weak_banner").assertExists()
    }

    @Test
    fun reconnectingSpinner_present_whenReconnecting() {
        launchStatic(baseState(lifecycle = InCallLifecycle.Reconnecting))
        rule.onNodeWithTag("incall_reconnecting").assertExists()
    }

    @Test
    fun localPip_hidden_whenCameraOff() {
        launchStatic(baseState(cameraEnabled = false))
        rule.onNodeWithTag("incall_local_pip").assertDoesNotExist()
    }
}
