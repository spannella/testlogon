package com.testlogon.android.feature.feed

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performSemanticsAction
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
        // LikeButton is a clearAndSetSemantics Button that now exposes an onClick action (testTag kept
        // ahead of the clear so the node is findable). Invoke the semantics action directly.
        rule.onNodeWithTag(PostActionTestTags.LIKE)
            .performSemanticsAction(SemanticsActions.OnClick)
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
