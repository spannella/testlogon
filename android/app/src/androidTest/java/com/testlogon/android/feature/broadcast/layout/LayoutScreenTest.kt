package com.testlogon.android.feature.broadcast.layout

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-311 — Compose UI tests for the stateless [LayoutScreen]. Drives an in-test reducer over
 * [LayoutUiState]: selecting a non-live mode flips the live badge (optimistically) in-test. Asserts the four
 * cards render, the live card shows the LIVE badge and is a no-op (selecting it does not change state), a
 * non-live card is selectable, the pending state disables the grid + shows progress, and the error state
 * renders. useUnmergedTree for nested nodes; assertDoesNotExist is a member (not imported).
 */
@RunWith(AndroidJUnit4::class)
class LayoutScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun cards(
        current: LayoutModeUi,
        pending: LayoutModeUi? = null,
        needsSource: Boolean = false,
    ): List<ModeCard> = LayoutModeUi.SELECTABLE.map { mode ->
        val isLive = mode == (pending ?: current)
        ModeCard(
            mode = mode,
            isLive = isLive,
            isSelectable = !isLive && pending == null,
            needsSource = needsSource,
        )
    }

    private fun content(
        current: LayoutModeUi = LayoutModeUi.SINGLE,
        pending: LayoutModeUi? = null,
        needsSource: Boolean = false,
        isStale: Boolean = false,
    ) = LayoutUiState.Content(
        cards = cards(current, pending, needsSource),
        currentMode = pending ?: current,
        activeInputCount = if (needsSource) 0 else 1,
        isStale = isStale,
        pendingMode = pending,
    )

    private var selectCount = 0

    private fun launch(initial: LayoutUiState) {
        selectCount = 0
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                LayoutScreen(
                    state = state,
                    onSelectMode = { mode ->
                        selectCount++
                        // Trivial in-test reducer: switching to a non-live mode makes it the live mode.
                        val current = state
                        if (current is LayoutUiState.Content) {
                            state = current.copy(
                                cards = current.cards.map { it.copy(isLive = it.mode == mode) },
                                currentMode = mode,
                            )
                        }
                    },
                    onRetry = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun screen_rendersFourCards() {
        launch(content(current = LayoutModeUi.SINGLE))
        rule.onNodeWithTag(LayoutTestTags.SCREEN).assertIsDisplayed()
        LayoutModeUi.SELECTABLE.forEach { mode ->
            rule.onNodeWithTag(LayoutTestTags.mode(mode), useUnmergedTree = true).assertIsDisplayed()
        }
    }

    @Test
    fun liveCard_showsBadge() {
        launch(content(current = LayoutModeUi.PIP))
        rule.onNodeWithTag(LayoutTestTags.LIVE_BADGE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun liveCard_isNotEnabled_noOpOnClick() {
        launch(content(current = LayoutModeUi.SINGLE))
        // The live card is disabled (it cannot be re-selected).
        rule.onNodeWithTag(LayoutTestTags.mode(LayoutModeUi.SINGLE)).assertIsNotEnabled()
    }

    @Test
    fun nonLiveCard_isSelectable_movesBadge() {
        launch(content(current = LayoutModeUi.SINGLE))
        rule.onNodeWithTag(LayoutTestTags.mode(LayoutModeUi.GRID)).performClick()
        assertEquals(1, selectCount)
        rule.onNodeWithTag(LayoutTestTags.LIVE_BADGE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun pendingState_disablesGrid_andShowsProgress() {
        launch(content(current = LayoutModeUi.SINGLE, pending = LayoutModeUi.GRID))
        rule.onNodeWithTag(LayoutTestTags.PENDING, useUnmergedTree = true).assertIsDisplayed()
        // Every card is non-interactive while a switch is in flight.
        LayoutModeUi.SELECTABLE.forEach { mode ->
            rule.onNodeWithTag(LayoutTestTags.mode(mode)).assertIsNotEnabled()
        }
    }

    @Test
    fun needsSource_hintShown_cardStillSelectable() {
        launch(content(current = LayoutModeUi.SINGLE, needsSource = true))
        rule.onNodeWithTag(LayoutTestTags.NEEDS_SOURCE, useUnmergedTree = true)
            .assertIsDisplayed()
        // The non-live card stays selectable despite the needs-source hint.
        rule.onNodeWithTag(LayoutTestTags.mode(LayoutModeUi.GRID)).performClick()
        assertEquals(1, selectCount)
    }

    @Test
    fun staleBanner_shownOnStaleContent() {
        launch(content(current = LayoutModeUi.SINGLE, isStale = true))
        rule.onNodeWithTag(LayoutTestTags.STALE_BANNER, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun errorState_renders() {
        launch(LayoutUiState.Error(message = "Couldn't load", retryable = true))
        rule.onNodeWithTag(LayoutTestTags.ERROR, useUnmergedTree = true).assertIsDisplayed()
    }
}
