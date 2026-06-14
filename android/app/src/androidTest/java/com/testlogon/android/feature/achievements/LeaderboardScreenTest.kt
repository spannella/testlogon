package com.testlogon.android.feature.achievements

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.achievements.LeaderboardEntry
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-096 — Compose UI smoke tests for the stateless [LeaderboardScreen]. */
@RunWith(AndroidJUnit4::class)
class LeaderboardScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun entry(rank: Int, sub: String, isMe: Boolean = false) = LeaderboardEntry(
        rank = rank, userSub = sub, name = "Player $sub", points = 100 - rank,
        achievementCount = 1, badges = emptyList(), isMe = isMe,
    )

    private fun launch(state: LeaderboardUiState) {
        rule.setContent {
            TestLogonTheme {
                LeaderboardScreen(state = state, onRefresh = {}, onRetry = {}, onBack = {})
            }
        }
    }

    @Test
    fun rendersEntries_andPinnedOwnRankBar_whenMeAbsentFromList() {
        launch(
            LeaderboardUiState.Content(
                entries = listOf(entry(1, "u_a"), entry(2, "u_b")),
                me = entry(57, "u_self", isMe = true),
            ),
        )
        rule.onNodeWithTag(LeaderboardTestTags.LIST).assertIsDisplayed()
        rule.onNodeWithTag(LeaderboardTestTags.MY_RANK_BAR).assertIsDisplayed()
    }

    @Test
    fun emptyState_renders() {
        launch(LeaderboardUiState.Empty(me = null))
        rule.onNodeWithText("No rankings yet").assertIsDisplayed()
    }

    @Test
    fun errorState_renders() {
        launch(LeaderboardUiState.Error("offline"))
        rule.onNodeWithTag(LeaderboardTestTags.ERROR).assertIsDisplayed()
    }
}
