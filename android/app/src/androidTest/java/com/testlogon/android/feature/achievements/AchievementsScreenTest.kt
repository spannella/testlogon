package com.testlogon.android.feature.achievements

import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.remember
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.achievements.Achievement
import com.testlogon.android.data.achievements.AchievementCatalog
import com.testlogon.android.data.achievements.AchievementProgress
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-096 — Compose UI smoke tests for the stateless [AchievementsScreen]. */
@RunWith(AndroidJUnit4::class)
class AchievementsScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val earned = Achievement(
        id = "first", title = "First", description = "Sign in", iconUrl = null, rarity = "common",
        points = 10, earned = true, earnedAtEpochSeconds = 1L, progress = null,
    )
    private val lockedInProgress = Achievement(
        id = "streak", title = "On a Roll", description = "Streak", iconUrl = null, rarity = "rare",
        points = 25, earned = false, earnedAtEpochSeconds = null, progress = AchievementProgress(7, 10),
    )
    private val lockedNoProgress = Achievement(
        id = "mystery", title = "Mystery", description = null, iconUrl = null, rarity = null,
        points = 0, earned = false, earnedAtEpochSeconds = null, progress = null,
    )

    private fun launch(state: AchievementsUiState) {
        rule.setContent {
            TestLogonTheme {
                AchievementsScreen(
                    state = state,
                    snackbarHostState = remember { SnackbarHostState() },
                    onRefresh = {},
                    onRetry = {},
                    onOpenLeaderboard = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun rendersEarnedAndLockedSections_withProgress() {
        launch(
            AchievementsUiState.Content(
                AchievementCatalog(
                    earned = listOf(earned),
                    locked = listOf(lockedInProgress, lockedNoProgress),
                    earnedCount = 1, totalPoints = 10, total = 3,
                ),
            ),
        )
        rule.onNodeWithText("Earned").assertIsDisplayed()
        rule.onNodeWithText("Locked").assertIsDisplayed()
        // The progress node lives inside a merged row, so query the unmerged tree for its tag.
        rule.onNodeWithTag(AchievementsTestTags.progress("streak"), useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithText("7 / 10", useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun emptyState_renders() {
        launch(AchievementsUiState.Empty)
        rule.onNodeWithText("No achievements yet").assertIsDisplayed()
    }

    @Test
    fun errorState_renders() {
        launch(AchievementsUiState.Error("offline"))
        rule.onNodeWithTag(AchievementsTestTags.ERROR).assertIsDisplayed()
    }
}
