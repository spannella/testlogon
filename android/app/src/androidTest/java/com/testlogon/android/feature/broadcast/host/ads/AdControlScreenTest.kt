package com.testlogon.android.feature.broadcast.host.ads

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-316 — Compose UI tests for the stateless [AdControlScreen]. Drives an in-test reducer over
 * [AdControlUiState]: Save is disabled when invalid / not dirty; the Trigger button shows when inactive; the
 * countdown chip + End button show when active; the pre-roll toggle renders. useUnmergedTree for nested
 * controls; assertDoesNotExist is used as a member (not imported).
 */
@RunWith(AndroidJUnit4::class)
class AdControlScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: AdControlUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                AdControlScreen(
                    state = state,
                    onPreRollToggled = { enabled ->
                        state = state.copy(config = state.config.copy(preRollEnabled = enabled))
                    },
                    onDurationChanged = { seconds ->
                        state = state.copy(
                            config = state.config.copy(
                                midRollDurationSeconds = seconds,
                                durationValid = AdConfigBounds.durationValid(seconds),
                                dirty = true,
                            ),
                        )
                    },
                    onSkipAfterChanged = { seconds ->
                        state = state.copy(
                            config = state.config.copy(
                                skipAfterSeconds = seconds,
                                skipValid = AdConfigBounds.skipValid(seconds),
                                dirty = true,
                            ),
                        )
                    },
                    onSave = {},
                    onTrigger = {},
                    onEnd = {},
                    onRetry = {},
                    onBack = {},
                )
            }
        }
    }

    private fun loaded(
        dirty: Boolean = true,
        durationValid: Boolean = true,
        skipValid: Boolean = true,
        active: Boolean = false,
        remaining: Int = 0,
    ) = AdControlUiState(
        loading = false,
        hasConfig = true,
        config = AdConfigForm(
            preRollEnabled = false,
            midRollDurationSeconds = 30,
            skipAfterSeconds = 5,
            durationValid = durationValid,
            skipValid = skipValid,
            dirty = dirty,
        ),
        adBreakActive = active,
        adBreakDurationSeconds = 30,
        skipAfterSeconds = 5,
        remainingSeconds = remaining,
        totalAdBreaks = 2,
    )

    @Test
    fun editor_renders_whenInactive() {
        launch(loaded())
        rule.onNodeWithTag(AdControlTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(AdControlTestTags.PRE_ROLL, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdControlTestTags.DURATION, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdControlTestTags.SKIP_AFTER, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdControlTestTags.TOTAL_BREAKS, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun save_disabledWhenInvalid() {
        launch(loaded(durationValid = false))
        rule.onNodeWithTag(AdControlTestTags.SAVE).assertIsNotEnabled()
    }

    @Test
    fun save_disabledWhenNotDirty() {
        launch(loaded(dirty = false))
        rule.onNodeWithTag(AdControlTestTags.SAVE).assertIsNotEnabled()
    }

    @Test
    fun save_enabledWhenValidAndDirty() {
        launch(loaded(dirty = true, durationValid = true, skipValid = true))
        rule.onNodeWithTag(AdControlTestTags.SAVE).assertIsEnabled()
    }

    @Test
    fun triggerShown_whenInactive_countdownAbsent() {
        launch(loaded(active = false))
        rule.onNodeWithTag(AdControlTestTags.TRIGGER).assertIsDisplayed()
        rule.onNodeWithTag(AdControlTestTags.COUNTDOWN).assertDoesNotExist()
        rule.onNodeWithTag(AdControlTestTags.END).assertDoesNotExist()
    }

    @Test
    fun countdownAndEndShown_whenActive_triggerAbsent() {
        launch(loaded(active = true, remaining = 25))
        rule.onNodeWithTag(AdControlTestTags.COUNTDOWN, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdControlTestTags.END).assertIsDisplayed()
        rule.onNodeWithTag(AdControlTestTags.TRIGGER).assertDoesNotExist()
    }
}
