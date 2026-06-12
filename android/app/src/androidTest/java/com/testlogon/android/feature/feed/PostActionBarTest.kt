package com.testlogon.android.feature.feed

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.click
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-173 / AND-175 — Compose tests for [LikeButton] + the overflow menu. */
@RunWith(AndroidJUnit4::class)
class PostActionBarTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun likeButton_click_invokesToggle_andFlipsIcon() {
        var toggles = 0
        rule.setContent {
            TestLogonTheme {
                var liked by remember { mutableStateOf(false) }
                LikeButton(
                    liked = liked,
                    likeCount = if (liked) 43 else 42,
                    onToggle = {
                        toggles++
                        liked = !liked
                    },
                )
            }
        }
        rule.onNodeWithTag(PostActionTestTags.LIKE).assertIsDisplayed()
        // The like Row uses clearAndSetSemantics, so the tagged node spans the icon AND the count
        // text; the clickable IconButton only occupies the left 48dp. A default performClick taps the
        // Row's center, which (with a count chip present) lands past the button and never toggles.
        // Click the left (icon) region explicitly so the gesture hits the IconButton.
        rule.onNodeWithTag(PostActionTestTags.LIKE).performTouchInput {
            click(percentOffset(0.08f, 0.5f))
        }
        rule.waitForIdle()
        rule.runOnIdle { assertEquals(1, toggles) }
    }

    @Test
    fun overflowMenu_hideAndNotInterested_invokeCallbacks() {
        var hidden = false
        var notInterested = false
        rule.setContent {
            TestLogonTheme {
                PostActionBar(
                    liked = false,
                    likeCount = 0,
                    commentCount = 0,
                    onLikeToggle = {},
                    onCommentClick = {},
                    onHide = { hidden = true },
                    onNotInterested = { notInterested = true },
                )
            }
        }
        rule.onNodeWithTag(PostActionTestTags.OVERFLOW).performClick()
        rule.onNodeWithTag(PostActionTestTags.MENU_HIDE).performClick()
        rule.runOnIdle { assertTrue(hidden) }

        rule.onNodeWithTag(PostActionTestTags.OVERFLOW).performClick()
        rule.onNodeWithTag(PostActionTestTags.MENU_NOT_INTERESTED).performClick()
        rule.runOnIdle { assertTrue(notInterested) }
    }
}
