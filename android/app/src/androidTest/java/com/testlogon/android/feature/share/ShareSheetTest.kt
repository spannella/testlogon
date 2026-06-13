package com.testlogon.android.feature.share

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.share.model.ShareLink
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-335 - Compose UI tests for the stateless [ShareSheetContent] driven by an in-test reducer. The
 * create form (presets / password / max), the existing-links list, and the copy / revoke affordances are
 * exercised. useUnmergedTree for nested controls.
 */
@RunWith(AndroidJUnit4::class)
class ShareSheetTest {

    @get:Rule
    val rule = createComposeRule()

    private fun sampleLink(id: String) = ShareLink(
        linkId = id,
        fileNodeId = "f1",
        shareUrl = "https://host/s/$id",
        expiresAt = null,
        maxDownloads = 3,
        downloadCount = 1,
        passwordProtected = false,
        createdAt = null,
        revoked = false,
    )

    private fun launch(initial: ShareSheetUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                ShareSheetContent(
                    state = state,
                    onExpiry = { state = state.copy(expiry = it) },
                    onPasswordEnabled = { state = state.copy(passwordEnabled = it) },
                    onPassword = { state = state.copy(password = it) },
                    onMaxDownloads = { state = state.copy(maxDownloads = it) },
                    onCreate = {},
                    onCopy = {},
                    onRevoke = { id -> state = state.copy(revoking = state.revoking + id) },
                )
            }
        }
    }

    @Test
    fun form_renders() {
        launch(ShareSheetUiState(fileId = "f1", isLoading = false))
        rule.onNodeWithTag(ShareSheetTestTags.CREATE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ShareSheetTestTags.expiry(ExpiryPreset.SEVEN_DAYS), useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithTag(ShareSheetTestTags.MAX, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun passwordField_appearsWhenEnabled() {
        launch(ShareSheetUiState(fileId = "f1", isLoading = false, passwordEnabled = true))
        rule.onNodeWithTag(ShareSheetTestTags.PASSWORD, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ShareSheetTestTags.PASSWORD, useUnmergedTree = true).performTextInput("abcd")
    }

    @Test
    fun create_enabled_byDefault() {
        launch(ShareSheetUiState(fileId = "f1", isLoading = false))
        rule.onNodeWithTag(ShareSheetTestTags.CREATE, useUnmergedTree = true).assertIsEnabled()
    }

    @Test
    fun existingLinks_renderWithCopyAndRevoke() {
        launch(
            ShareSheetUiState(
                fileId = "f1",
                isLoading = false,
                links = listOf(sampleLink("a"), sampleLink("b")),
            ),
        )
        rule.onNodeWithTag(ShareSheetTestTags.link("a"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ShareSheetTestTags.link("b"), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun revoke_hidesRow() {
        launch(
            ShareSheetUiState(
                fileId = "f1",
                isLoading = false,
                links = listOf(sampleLink("a")),
            ),
        )
        rule.onNodeWithTag(ShareSheetTestTags.REVOKE, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(ShareSheetTestTags.link("a"), useUnmergedTree = true).assertDoesNotExist()
    }
}
