package com.testlogon.android.feature.notifications

import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.remember
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.paging.LoadState
import androidx.paging.LoadStates
import androidx.paging.PagingData
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.notifications.NotificationType
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-090 — Compose UI tests for the stateless [NotificationCenterScreen]. */
@RunWith(AndroidJUnit4::class)
class NotificationCenterScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun ui(id: String, read: Boolean, target: NotificationTarget = NotificationTarget.Unknown) =
        NotificationUi(
            id = id, type = NotificationType.SYSTEM, title = "Title $id", body = "Body $id",
            isRead = read, createdAtEpochSeconds = 1_749_124_800L, batchCount = 1, target = target,
        )

    private fun launch(
        items: List<NotificationUi>,
        badge: UnreadBadgeUiState = UnreadBadgeUiState(count = 1, isLoading = false),
        onItemClick: (NotificationUi) -> Unit = {},
        onMarkAllRead: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                val paging = remember {
                    flowOf(
                        PagingData.from(
                            items,
                            sourceLoadStates = LoadStates(
                                refresh = LoadState.NotLoading(endOfPaginationReached = items.isEmpty()),
                                prepend = LoadState.NotLoading(endOfPaginationReached = true),
                                append = LoadState.NotLoading(endOfPaginationReached = true),
                            ),
                        ),
                    )
                }
                val lazyItems = paging.collectAsLazyPagingItems()
                NotificationCenterScreen(
                    badge = badge,
                    items = lazyItems,
                    snackbarHostState = remember { SnackbarHostState() },
                    onItemClick = onItemClick,
                    onMarkAllRead = onMarkAllRead,
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun renders_rows() {
        launch(listOf(ui("n1", read = false), ui("n2", read = true)))
        rule.onNodeWithTag(NotifTestTags.SCREEN).assertIsDisplayed()
        rule.onAllNodesWithTag(NotifTestTags.ROW).assertCountEquals(2)
    }

    @Test
    fun unreadRow_showsDot_readRowDoesNot() {
        launch(listOf(ui("n1", read = false), ui("n2", read = true)))
        // Paging loads asynchronously; wait for both rows to render before counting dots.
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithTag(NotifTestTags.ROW).fetchSemanticsNodes().size == 2
        }
        // exactly one unread dot for the single unread row (the dot lives in the unmerged tree).
        rule.onAllNodesWithTag(NotifTestTags.UNREAD_DOT, useUnmergedTree = true).assertCountEquals(1)
    }

    @Test
    fun tappingRow_invokesClickCallback_withItem() {
        var clicked: NotificationUi? = null
        launch(listOf(ui("n1", read = false, target = NotificationTarget.Settings)), onItemClick = { clicked = it })
        rule.onAllNodesWithTag(NotifTestTags.ROW).onFirst().performClick()
        rule.runOnIdle { assertEquals("n1", clicked?.id) }
    }

    @Test
    fun markAllRead_action_invokesCallback() {
        var called = false
        launch(listOf(ui("n1", read = false)), onMarkAllRead = { called = true })
        rule.onNodeWithTag(NotifTestTags.MARK_ALL_READ).performClick()
        rule.runOnIdle { assertEquals(true, called) }
    }

    @Test
    fun emptyState_rendersWhenNoItems() {
        launch(emptyList(), badge = UnreadBadgeUiState(count = 0, isLoading = false))
        // The empty state renders only after the paging flow's first (empty) load completes.
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithText("No notifications yet").fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithText("No notifications yet").assertIsDisplayed()
    }
}
