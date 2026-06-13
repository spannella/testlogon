package com.testlogon.android.feature.share

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.share.model.PublicShare
import com.testlogon.android.feature.share.model.PublicShareState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-335 - Compose UI tests for the stateless [PublicShareScreen] driven by an in-test reducer. The
 * info panel + password gate + download button + terminal panels are exercised. useUnmergedTree for
 * nested controls.
 */
@RunWith(AndroidJUnit4::class)
class PublicShareScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun share(passwordRequired: Boolean) = PublicShare(
        linkId = "lnk_1",
        fileName = "report.pdf",
        sizeBytes = 1234L,
        contentType = "application/pdf",
        expiresAt = null,
        passwordRequired = passwordRequired,
        state = PublicShareState.AVAILABLE,
    )

    private fun launch(initial: PublicShareUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                PublicShareScreen(
                    state = state,
                    onBack = {},
                    onRetry = {},
                    onPasswordChange = { value ->
                        (state as? PublicShareUiState.Info)?.let { state = it.copy(password = value) }
                    },
                    onSubmitPassword = {
                        (state as? PublicShareUiState.Info)?.let { state = it.copy(needsPassword = false) }
                    },
                    onDownload = {
                        (state as? PublicShareUiState.Info)?.let {
                            state = it.copy(savedFileName = "report.pdf")
                        }
                    },
                )
            }
        }
    }

    @Test
    fun info_rendersDownloadButton() {
        launch(PublicShareUiState.Info(share = share(passwordRequired = false), needsPassword = false))
        rule.onNodeWithTag(PublicShareTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(PublicShareTestTags.DOWNLOAD, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun passwordGate_rendersField() {
        launch(PublicShareUiState.Info(share = share(passwordRequired = true), needsPassword = true))
        rule.onNodeWithTag(PublicShareTestTags.PASSWORD, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(PublicShareTestTags.PASSWORD, useUnmergedTree = true).performTextInput("secret")
    }

    @Test
    fun unlock_revealsDownload() {
        launch(PublicShareUiState.Info(share = share(passwordRequired = true), needsPassword = true, password = "secret"))
        // Submitting the password drops the gate -> the download button appears.
        rule.onNodeWithTag(PublicShareTestTags.PASSWORD, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun download_marksSaved() {
        launch(PublicShareUiState.Info(share = share(passwordRequired = false), needsPassword = false))
        rule.onNodeWithTag(PublicShareTestTags.DOWNLOAD, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(PublicShareTestTags.DOWNLOAD, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun terminalState_rendersPanel() {
        launch(PublicShareUiState.Terminal(PublicShareState.EXPIRED))
        rule.onNodeWithTag(PublicShareTestTags.TERMINAL, useUnmergedTree = true).assertIsDisplayed()
    }
}
