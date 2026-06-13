package com.testlogon.android.feature.signing.capture

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-342 - Compose UI tests for the full-screen [SignaturePadScreen], driven by fixed callbacks (no VM /
 * Hilt / real rasterizer). useUnmergedTree for non-merging surfaces; assertDoesNotExist is a MEMBER.
 * Draw / clear / undo / confirm affordances + the Type-mode font chips + Use-saved are exercised.
 */
@RunWith(AndroidJUnit4::class)
class SignaturePadTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(
        hasSaved: Boolean = false,
        onStrokesConfirmed: (List<List<androidx.compose.ui.geometry.Offset>>) -> Unit = {},
        onTypedConfirmed: (String, Int) -> Unit = { _, _ -> },
        onUseSaved: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                SignaturePadScreen(
                    hasSaved = hasSaved,
                    onBack = {},
                    onStrokesConfirmed = onStrokesConfirmed,
                    onTypedConfirmed = onTypedConfirmed,
                    onUseSaved = onUseSaved,
                )
            }
        }
    }

    @Test
    fun drawMode_showsCanvasAndControls() {
        launch()
        rule.onNodeWithTag(SignaturePadTestTags.SCREEN, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SignaturePadTestTags.CANVAS, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SignaturePadTestTags.CLEAR, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SignaturePadTestTags.UNDO, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun confirm_disabledUntilStrokes_inDrawMode() {
        launch()
        // No strokes yet -> Confirm is disabled.
        rule.onNodeWithTag(SignaturePadTestTags.CONFIRM, useUnmergedTree = true).assertIsNotEnabled()
    }

    @Test
    fun useSaved_shownOnlyWhenSavedExists() {
        launch(hasSaved = false)
        rule.onNodeWithTag(SignaturePadTestTags.USE_SAVED, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun useSaved_firesCallback() {
        var used = 0
        launch(hasSaved = true, onUseSaved = { used++ })
        rule.onNodeWithTag(SignaturePadTestTags.USE_SAVED, useUnmergedTree = true).performClick()
        rule.runOnIdle { assertEquals(1, used) }
    }

    @Test
    fun typeMode_showsFontChips_afterSwitchingToType() {
        launch()
        // Font chips are hidden in the default draw mode.
        rule.onNodeWithTag(SignaturePadTestTags.font(0), useUnmergedTree = true).assertDoesNotExist()
        // Switch to Type mode by clicking the "Type" chip label, then the font chips appear.
        rule.onNodeWithText("Type").performClick()
        rule.onNodeWithTag(SignaturePadTestTags.font(0), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SignaturePadTestTags.font(1), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SignaturePadTestTags.font(2), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun typeMode_typingEnablesConfirm_andConfirmEmits() {
        var confirmedText: String? = null
        var confirmedFont = -1
        launch(onTypedConfirmed = { t, f -> confirmedText = t; confirmedFont = f })
        rule.onNodeWithText("Type").performClick()
        // Empty text -> Confirm disabled.
        rule.onNodeWithTag(SignaturePadTestTags.CONFIRM, useUnmergedTree = true).assertIsNotEnabled()
        rule.onNodeWithTag(SignaturePadTestTags.TYPED_TEXT, useUnmergedTree = true)
            .performTextInput("Sean Pannella")
        rule.onNodeWithTag(SignaturePadTestTags.font(2), useUnmergedTree = true).performClick()
        rule.onNodeWithTag(SignaturePadTestTags.CONFIRM, useUnmergedTree = true).assertIsEnabled()
        rule.onNodeWithTag(SignaturePadTestTags.CONFIRM, useUnmergedTree = true).performClick()
        rule.runOnIdle {
            assertEquals("Sean Pannella", confirmedText)
            assertEquals(2, confirmedFont)
        }
    }
}
