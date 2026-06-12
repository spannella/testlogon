package com.testlogon.android.feature.call.recording

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-302 — Compose UI tests for the recording consent dialog + upload status + record control. Hand-built
 * state wrapped in [TestLogonTheme]; useUnmergedTree for nested nodes; remember{mutableStateOf} for the
 * in-test reducer wiring.
 */
@RunWith(AndroidJUnit4::class)
class RecordingConsentDialogTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun consentDialog_showsRequesterName_andButtons() {
        rule.setContent {
            TestLogonTheme {
                RecordingConsentDialog(requesterName = "Alex", onAccept = {}, onDecline = {})
            }
        }
        rule.onNodeWithText("Alex wants to record this call").assertExists()
        rule.onNodeWithTag("recording_consent", useUnmergedTree = true).assertExists()
        rule.onNodeWithTag("recording_consent_accept", useUnmergedTree = true).assertExists()
        rule.onNodeWithTag("recording_consent_decline", useUnmergedTree = true).assertExists()
    }

    @Test
    fun consentDialog_accept_invokesCallback() {
        var accepted = false
        rule.setContent {
            TestLogonTheme {
                RecordingConsentDialog(requesterName = "Alex", onAccept = { accepted = true }, onDecline = {})
            }
        }
        rule.onNodeWithTag("recording_consent_accept", useUnmergedTree = true).performClick()
        assertTrue(accepted)
    }

    @Test
    fun consentDialog_decline_invokesCallback() {
        var declined = false
        rule.setContent {
            TestLogonTheme {
                RecordingConsentDialog(requesterName = "Alex", onAccept = {}, onDecline = { declined = true })
            }
        }
        rule.onNodeWithTag("recording_consent_decline", useUnmergedTree = true).performClick()
        assertTrue(declined)
    }

    @Test
    fun uploadStatus_showsProgress_andCancel() {
        var cancelled = false
        rule.setContent {
            TestLogonTheme {
                RecordingUploadStatus(
                    state = RecordingUiState(phase = RecordingPhase.Uploading, uploadProgress = 40),
                    onCancel = { cancelled = true },
                    onRetry = {},
                )
            }
        }
        rule.onNodeWithTag("recording_upload", useUnmergedTree = true).assertExists()
        rule.onNodeWithTag("recording_upload_progress", useUnmergedTree = true).assertExists()
        rule.onNodeWithTag("recording_upload_cancel", useUnmergedTree = true).performClick()
        assertTrue(cancelled)
    }

    @Test
    fun uploadStatus_failed_showsRetry() {
        var retried = false
        rule.setContent {
            TestLogonTheme {
                RecordingUploadStatus(
                    state = RecordingUiState(phase = RecordingPhase.Failed, error = "x"),
                    onCancel = {},
                    onRetry = { retried = true },
                )
            }
        }
        rule.onNodeWithTag("recording_upload_retry", useUnmergedTree = true).performClick()
        assertTrue(retried)
    }

    @Test
    fun uploadStatus_mediaUnavailable_showsNotice() {
        rule.setContent {
            TestLogonTheme {
                RecordingUploadStatus(
                    state = RecordingUiState(phase = RecordingPhase.Idle, mediaUnavailable = true),
                    onCancel = {},
                    onRetry = {},
                )
            }
        }
        rule.onNodeWithTag("recording_unavailable", useUnmergedTree = true).assertExists()
    }

    @Test
    fun recordControl_disabledWhileRequestPending() {
        rule.setContent {
            TestLogonTheme {
                RecordingControl(phase = RecordingPhase.RequestPending, onRecord = {})
            }
        }
        rule.onNodeWithTag("recording_button").assertIsNotEnabled()
    }

    @Test
    fun recordControl_enabledWhenIdle_invokesOnRecord() {
        var recorded = false
        rule.setContent {
            TestLogonTheme {
                RecordingControl(phase = RecordingPhase.Idle, onRecord = { recorded = true })
            }
        }
        rule.onNodeWithTag("recording_button").assertIsEnabled()
        rule.onNodeWithTag("recording_button").performClick()
        assertTrue(recorded)
    }

    @Test
    fun consentDialog_inTestReducer_acceptDismisses() {
        rule.setContent {
            TestLogonTheme {
                var state by remember {
                    mutableStateOf(
                        RecordingStateMachine.onRemoteRequest(RecordingUiState(), "Alex"),
                    )
                }
                if (state.phase == RecordingPhase.ConsentPrompt) {
                    RecordingConsentDialog(
                        requesterName = state.requesterName,
                        onAccept = { state = RecordingStateMachine.onConsentGranted(state, "rec_1") },
                        onDecline = { state = RecordingStateMachine.onDeclined(state) },
                    )
                }
            }
        }
        rule.onNodeWithTag("recording_consent_accept", useUnmergedTree = true).performClick()
        // After granting, the dialog is gone (phase left ConsentPrompt).
        rule.onNodeWithTag("recording_consent", useUnmergedTree = true).assertDoesNotExist()
    }
}
