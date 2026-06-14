package com.testlogon.android.feature.signing.capture

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.FieldType
import com.testlogon.android.feature.signing.capture.model.NormalizedRect
import com.testlogon.android.feature.signing.capture.model.SignatureField
import com.testlogon.android.feature.signing.document.model.PageOnScreen
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-342 - Compose UI tests for the [SigningPlacementOverlay], driven by a FIXED AND-341 page geometry
 * + an in-test reducer over the placements map (no VM / Hilt / real PDF). useUnmergedTree for
 * non-merging surfaces; assertDoesNotExist is a MEMBER. Verifies field boxes render, progress reflects
 * completion, Continue gates on isComplete, and tapping toggles a placement.
 */
@RunWith(AndroidJUnit4::class)
class SigningPlacementOverlayTest {

    @get:Rule
    val rule = createComposeRule()

    private val pages = listOf(
        PageOnScreen(index = 0, contentRect = Rect(0f, 0f, 600f, 800f)),
    )

    private fun field(id: String, type: FieldType = FieldType.DATE) = SignatureField(
        id = id,
        page = 1,
        type = type,
        rect = NormalizedRect.fromXywh(0.1f, 0.1f, 0.3f, 0.05f),
        required = true,
        isAssignedToViewer = true,
    )

    @Test
    fun overlay_rendersFieldBoxes_andProgress() {
        rule.setContent {
            TestLogonTheme {
                SigningPlacementOverlay(
                    pages = pages,
                    fields = listOf(field("a"), field("b")),
                    placements = emptyMap(),
                    requiredDone = 0,
                    requiredTotal = 2,
                    isComplete = false,
                    onFieldTap = {},
                    onClearField = {},
                    onContinue = {},
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
        rule.onNodeWithTag(SigningOverlayTestTags.OVERLAY, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SigningOverlayTestTags.field("a"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SigningOverlayTestTags.field("b"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SigningOverlayTestTags.PROGRESS, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun continue_disabledUntilComplete() {
        rule.setContent {
            TestLogonTheme {
                SigningPlacementOverlay(
                    pages = pages,
                    fields = listOf(field("a")),
                    placements = emptyMap(),
                    requiredDone = 0,
                    requiredTotal = 1,
                    isComplete = false,
                    onFieldTap = {},
                    onClearField = {},
                    onContinue = {},
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
        rule.onNodeWithTag(SigningOverlayTestTags.CONTINUE, useUnmergedTree = true).assertIsNotEnabled()
    }

    @Test
    fun tappingDateField_satisfiesIt_andEnablesContinue_viaReducer() {
        var continues = 0
        rule.setContent {
            TestLogonTheme {
                val fields = listOf(field("a"))
                val placements = remember { mutableStateMapOf<String, FieldPlacement>() }
                val isComplete = placements["a"]?.satisfied == true
                SigningPlacementOverlay(
                    pages = pages,
                    fields = fields,
                    placements = placements,
                    requiredDone = if (isComplete) 1 else 0,
                    requiredTotal = 1,
                    isComplete = isComplete,
                    onFieldTap = { id ->
                        // The in-test reducer plays the VM's date auto-fill.
                        placements[id] = FieldPlacement(
                            fieldId = id,
                            page = 1,
                            rect = field("a").rect,
                            textValue = "2026-06-09",
                            satisfied = true,
                        )
                    },
                    onClearField = { id -> placements.remove(id) },
                    onContinue = { continues++ },
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
        // Initially incomplete -> Continue disabled.
        rule.onNodeWithTag(SigningOverlayTestTags.CONTINUE, useUnmergedTree = true).assertIsNotEnabled()
        // Tap the field -> the reducer satisfies it.
        rule.onNodeWithTag(SigningOverlayTestTags.field("a"), useUnmergedTree = true).performClick()
        rule.onNodeWithTag(SigningOverlayTestTags.CONTINUE, useUnmergedTree = true).assertIsEnabled()
        rule.onNodeWithTag(SigningOverlayTestTags.CONTINUE, useUnmergedTree = true).performClick()
        rule.runOnIdle { assertEquals(1, continues) }
    }
}
