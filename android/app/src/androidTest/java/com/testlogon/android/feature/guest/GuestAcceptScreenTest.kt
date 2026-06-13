package com.testlogon.android.feature.guest

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-312 — Compose UI tests for the stateless [GuestAcceptScreen]. A non-blank display name is required to
 * enable Accept; the joined confirmation renders on success. useUnmergedTree for nested controls.
 */
@RunWith(AndroidJUnit4::class)
class GuestAcceptScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: GuestAcceptUiState = GuestAcceptUiState()) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                GuestAcceptScreen(
                    state = state,
                    onDisplayNameChange = { state = state.copy(displayName = it, error = null) },
                    onAccept = {},
                    onDecline = {},
                )
            }
        }
    }

    @Test
    fun screen_renders() {
        launch()
        rule.onNodeWithTag(GuestAcceptTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(GuestAcceptTestTags.NAME, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun accept_disabledUntilNameEntered() {
        launch()
        rule.onNodeWithTag(GuestAcceptTestTags.SUBMIT, useUnmergedTree = true).assertIsNotEnabled()
        rule.onNodeWithTag(GuestAcceptTestTags.NAME, useUnmergedTree = true).performTextInput("Ada")
        rule.onNodeWithTag(GuestAcceptTestTags.SUBMIT, useUnmergedTree = true).assertIsEnabled()
    }

    @Test
    fun decline_isPresent() {
        launch()
        rule.onNodeWithTag(GuestAcceptTestTags.DECLINE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun accepted_showsJoinedConfirmation() {
        launch(
            GuestAcceptUiState(
                displayName = "Ada",
                accepted = GuestAcceptResult("inv_1", "in_9", "rtmp", "bcs_1", "rtmps://ingest/app"),
            ),
        )
        rule.onNodeWithTag(GuestAcceptTestTags.JOINED, useUnmergedTree = true).assertIsDisplayed()
    }
}
