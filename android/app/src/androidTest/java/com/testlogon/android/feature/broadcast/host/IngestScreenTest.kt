package com.testlogon.android.feature.broadcast.host

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-308 — Compose UI tests for the stateless [IngestScreen]. */
@RunWith(AndroidJUnit4::class)
class IngestScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: IngestUiState = IngestUiState()) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                IngestScreen(
                    state = state,
                    onStart = { state = state.copy(phase = IngestPhase.Unavailable, mediaUnavailable = true) },
                    onStop = { state = state.copy(phase = IngestPhase.PreviewReady, mediaUnavailable = false) },
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun rendersPreviewAndStartButton() {
        launch()
        rule.onNodeWithTag(IngestTestTags.SCREEN).assertIsDisplayed()
        // The preview placeholder is a nested semantics node.
        rule.onNodeWithTag(IngestTestTags.PREVIEW, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(IngestTestTags.START).assertIsDisplayed()
    }

    @Test
    fun showsUnavailableBanner_whenMediaUnavailable() {
        launch(IngestUiState(phase = IngestPhase.Unavailable, mediaUnavailable = true))
        rule.onNodeWithTag(IngestTestTags.UNAVAILABLE).assertIsDisplayed()
    }

    @Test
    fun noUnavailableBanner_whenPreviewReady() {
        launch()
        rule.onNodeWithTag(IngestTestTags.UNAVAILABLE).assertDoesNotExist()
    }
}
