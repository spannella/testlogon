package com.testlogon.android.feature.broadcast.moderation

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-313 — Compose UI tests for the stateless [ModerationLogScreen]. Asserts: the screen renders; log rows
 * render for Content; the empty state renders; the error state renders + retries; a ban row's Unban invokes
 * the callback. useUnmergedTree for nested nodes; assertDoesNotExist is a member (not imported).
 */
@RunWith(AndroidJUnit4::class)
class ModerationLogScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun entry(id: String, action: ModerationActionType = ModerationActionType.DELETE) =
        ModerationLogEntry(
            id = id,
            action = action,
            moderatorId = "mod_1",
            moderatorName = "Mod One",
            target = ModerationTarget(messageId = "cm_1"),
            targetLabel = "cm_1",
            reason = null,
            createdAt = Instant.EPOCH,
        )

    private fun ban(userId: String = "usr_9") = ModerationBan(
        userId = userId,
        displayName = "Ada",
        reason = "spam",
        moderatorId = "mod_1",
        createdAt = Instant.EPOCH,
    )

    private fun launch(
        state: ModerationLogUiState,
        onUnban: (String) -> Unit = {},
        onRetry: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                ModerationLogScreen(
                    state = state,
                    onRefresh = {},
                    onUnban = onUnban,
                    onRetry = onRetry,
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun screen_renders() {
        launch(ModerationLogUiState.Content(entries = listOf(entry("ev_1")), bans = emptyList()))
        rule.onNodeWithTag(ModerationTestTags.LOG_SCREEN).assertIsDisplayed()
    }

    @Test
    fun content_rendersLogRows() {
        launch(
            ModerationLogUiState.Content(
                entries = listOf(entry("ev_1"), entry("ev_2", ModerationActionType.MUTE)),
                bans = emptyList(),
            ),
        )
        assertEquals(2, rule.onAllNodesWithTag(ModerationTestTags.LOG_ROW).fetchSemanticsNodes().size)
    }

    @Test
    fun empty_rendersEmptyState() {
        launch(ModerationLogUiState.Empty)
        rule.onNodeWithTag(ModerationTestTags.LOG_SCREEN).assertIsDisplayed()
        // No log rows render in the empty state.
        assertEquals(0, rule.onAllNodesWithTag(ModerationTestTags.LOG_ROW).fetchSemanticsNodes().size)
    }

    @Test
    fun error_rendersAndRetries() {
        var retried = false
        launch(ModerationLogUiState.Error("boom"), onRetry = { retried = true })
        rule.onNode(hasText(RETRY_LABEL)).performClick()
        assert(retried)
    }

    @Test
    fun banRow_unban_invokesCallback() {
        var unbanned: String? = null
        launch(
            ModerationLogUiState.Content(entries = emptyList(), bans = listOf(ban("usr_9"))),
            onUnban = { unbanned = it },
        )
        rule.onNodeWithTag(ModerationTestTags.UNBAN, useUnmergedTree = true).performClick()
        assertEquals("usr_9", unbanned)
    }

    private companion object {
        // Matches core-ui R.string.action_retry ("Retry").
        const val RETRY_LABEL = "Retry"
    }
}
