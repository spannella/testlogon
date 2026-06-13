package com.testlogon.android.feature.broadcast.tipsconfig

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
 * AND-315 — Compose UI tests for the stateless [TipsConfigScreen]. Drives an in-test reducer over the small
 * Editing state (dollar text + enabled switch). Asserts: the editor renders, Save is disabled when invalid
 * (min > max) and enabled when valid + dirty. useUnmergedTree where controls are nested.
 */
@RunWith(AndroidJUnit4::class)
class TipsConfigScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun editing(
        enabled: Boolean = true,
        min: String = "1.00",
        max: String = "50.00",
        dirty: Boolean = true,
        fieldErrors: Map<TipField, TipFieldError> = emptyMap(),
    ) = TipsConfigUiState.Editing(
        enabled = enabled,
        minDollars = min,
        maxDollars = max,
        dirty = dirty,
        fieldErrors = fieldErrors,
        saveError = null,
    )

    private fun launch(initial: TipsConfigUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                TipsConfigScreen(
                    state = state,
                    onEnabledChange = { enabled ->
                        (state as? TipsConfigUiState.Editing)?.let { state = it.copy(enabled = enabled) }
                    },
                    onMinChange = { v ->
                        (state as? TipsConfigUiState.Editing)?.let { state = it.copy(minDollars = v) }
                    },
                    onMaxChange = { v ->
                        (state as? TipsConfigUiState.Editing)?.let { state = it.copy(maxDollars = v) }
                    },
                    onSave = {},
                    onRetry = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun editor_renders() {
        launch(editing())
        rule.onNodeWithTag(TipsConfigTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(TipsConfigTestTags.ENABLED, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(TipsConfigTestTags.MIN, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(TipsConfigTestTags.MAX, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun save_disabledWhenInvalid() {
        launch(
            editing(
                min = "100.00",
                max = "5.00",
                fieldErrors = mapOf(TipField.MAX to TipFieldError.MIN_GREATER_THAN_MAX),
            ),
        )
        rule.onNodeWithTag(TipsConfigTestTags.SAVE).assertIsNotEnabled()
    }

    @Test
    fun save_enabledWhenValidAndDirty() {
        launch(editing(dirty = true, fieldErrors = emptyMap()))
        rule.onNodeWithTag(TipsConfigTestTags.SAVE).assertIsEnabled()
    }

    @Test
    fun save_disabledWhenNotDirty() {
        launch(editing(dirty = false))
        rule.onNodeWithTag(TipsConfigTestTags.SAVE).assertIsNotEnabled()
    }
}
