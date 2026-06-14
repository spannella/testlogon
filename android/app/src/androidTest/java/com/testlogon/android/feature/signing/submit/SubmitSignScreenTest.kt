package com.testlogon.android.feature.signing.submit

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.signing.model.PacketLegalNotice
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-343 - Compose UI smoke tests for the stateless [SubmitSignScreen] driven by fixed UI states (no
 * VM / Hilt). useUnmergedTree for non-merging surfaces; assertDoesNotExist is a MEMBER. An in-test
 * reducer (a mutableStateOf swap) verifies the acknowledge affordance flips the legal-notice gate.
 */
@RunWith(AndroidJUnit4::class)
class SubmitSignScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun notice(accepted: Boolean) =
        PacketLegalNotice(required = true, accepted = accepted, version = "v1", text = "the legal notice")

    private fun launch(
        state: SubmitUiState,
        role: PacketRole = PacketRole.SIGNER,
        onAcknowledge: () -> Unit = {},
        onMarkDone: () -> Unit = {},
        onDownloadPdf: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                SubmitSignScreen(
                    state = state,
                    role = role,
                    onAcknowledge = onAcknowledge,
                    onMarkDone = onMarkDone,
                    onDownloadPdf = onDownloadPdf,
                    onRetry = {},
                    onDismiss = {},
                )
            }
        }
    }

    @Test
    fun ready_showsLegalNotice_andAcknowledge_whenNotAccepted() {
        launch(
            SubmitUiState.Ready(
                legalNotice = notice(accepted = false),
                canMarkDone = false,
                submitting = false,
            ),
        )
        rule.onNodeWithTag(SubmitSignTestTags.LEGAL_TEXT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SubmitSignTestTags.LEGAL_VERSION, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SubmitSignTestTags.ACKNOWLEDGE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun acknowledge_hidden_onceAccepted() {
        launch(
            SubmitUiState.Ready(
                legalNotice = notice(accepted = true),
                canMarkDone = true,
                submitting = false,
            ),
        )
        rule.onNodeWithTag(SubmitSignTestTags.ACKNOWLEDGE, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun markDone_disabledUntilCanMarkDone() {
        launch(
            SubmitUiState.Ready(
                legalNotice = notice(accepted = false),
                canMarkDone = false,
                submitting = false,
            ),
        )
        rule.onNodeWithTag(SubmitSignTestTags.MARK_DONE, useUnmergedTree = true).assertIsNotEnabled()
    }

    @Test
    fun markDone_enabled_whenCanMarkDone() {
        launch(
            SubmitUiState.Ready(legalNotice = null, canMarkDone = true, submitting = false),
        )
        rule.onNodeWithTag(SubmitSignTestTags.MARK_DONE, useUnmergedTree = true).assertIsEnabled()
    }

    @Test
    fun confirmation_showsCompletedAndDownload() {
        launch(
            SubmitUiState.Confirmed(
                status = PacketStatus.COMPLETED,
                completedAt = Instant.ofEpochSecond(1_780_000_000L),
                canDownloadPdf = true,
            ),
        )
        rule.onNodeWithTag(SubmitSignTestTags.CONFIRMATION, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SubmitSignTestTags.COMPLETED_AT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SubmitSignTestTags.DOWNLOAD_PDF, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun downloadButton_firesCallback() {
        var clicks = 0
        launch(
            SubmitUiState.Confirmed(
                status = PacketStatus.COMPLETED,
                completedAt = null,
                canDownloadPdf = true,
            ),
            onDownloadPdf = { clicks++ },
        )
        rule.onNodeWithTag(SubmitSignTestTags.DOWNLOAD_PDF, useUnmergedTree = true).performClick()
        assertEquals(1, clicks)
    }

    @Test
    fun acknowledge_reducerFlipsGate() {
        var notice by mutableStateOf(notice(accepted = false))
        rule.setContent {
            TestLogonTheme {
                SubmitSignScreen(
                    state = SubmitUiState.Ready(
                        legalNotice = notice,
                        canMarkDone = notice.accepted,
                        submitting = false,
                    ),
                    role = PacketRole.SIGNER,
                    onAcknowledge = { notice = notice.copy(accepted = true) },
                    onMarkDone = {},
                    onDownloadPdf = {},
                    onRetry = {},
                    onDismiss = {},
                )
            }
        }
        rule.onNodeWithTag(SubmitSignTestTags.MARK_DONE, useUnmergedTree = true).assertIsNotEnabled()
        rule.onNodeWithTag(SubmitSignTestTags.ACKNOWLEDGE, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(SubmitSignTestTags.ACKNOWLEDGE, useUnmergedTree = true).assertDoesNotExist()
        rule.onNodeWithTag(SubmitSignTestTags.MARK_DONE, useUnmergedTree = true).assertIsEnabled()
    }
}
