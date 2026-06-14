package com.testlogon.android.feature.collaborations

import androidx.compose.runtime.remember
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.paging.LoadState
import androidx.paging.LoadStates
import androidx.paging.PagingData
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.collaborations.CollabStatus
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.collaborations.ui.CollaborationsListScreen
import com.testlogon.android.feature.collaborations.ui.CollaborationsListTestTags
import kotlinx.coroutines.flow.flowOf
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-358 - Compose UI tests for the stateless [CollaborationsListScreen]. Paging flows use PagingData.from
 * with terminal NotLoading LoadStates so the content / empty state renders in tests. assertDoesNotExist is
 * chained (a member), not imported.
 */
@RunWith(AndroidJUnit4::class)
class CollaborationsListScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun collab(id: String, title: String, split: Map<String, Int> = mapOf("usr_a" to 60)) =
        Collaboration(
            id = id, title = title, status = "active", statusEnum = CollabStatus.ACTIVE,
            initiatorId = "usr_a", recipientId = "usr_b", split = split,
        )

    private fun terminalLoadStates(empty: Boolean) = LoadStates(
        refresh = LoadState.NotLoading(endOfPaginationReached = empty),
        prepend = LoadState.NotLoading(endOfPaginationReached = true),
        append = LoadState.NotLoading(endOfPaginationReached = true),
    )

    private fun items(vararg items: Collaboration) = flowOf(
        PagingData.from(items.toList(), sourceLoadStates = terminalLoadStates(items.isEmpty())),
    )

    private fun launch(
        flow: kotlinx.coroutines.flow.Flow<PagingData<Collaboration>>,
        viewerId: String? = "usr_a",
    ) {
        rule.setContent {
            TestLogonTheme {
                val paged = remember { flow }.collectAsLazyPagingItems()
                CollaborationsListScreen(
                    items = paged,
                    viewerId = viewerId,
                    onBack = {},
                    onOpenCollaboration = {},
                )
            }
        }
    }

    @Test
    fun rendersRows_withViewerShare() {
        launch(
            items(
                collab("c1", "Track", mapOf("usr_a" to 60, "usr_b" to 40)),
                collab("c2", "Photo", mapOf("usr_a" to 50, "usr_b" to 50)),
            ),
        )
        rule.onNodeWithTag(CollaborationsListTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(CollaborationsListTestTags.row("c1")).assertIsDisplayed()
        rule.onNodeWithTag(CollaborationsListTestTags.row("c2")).assertIsDisplayed()
        rule.onNodeWithText("Track").assertIsDisplayed()
    }

    @Test
    fun emptyList_showsEmptyState() {
        launch(items())
        rule.onNodeWithText("No collaborations yet").assertIsDisplayed()
        rule.onNodeWithTag(CollaborationsListTestTags.row("c1")).assertDoesNotExist()
    }
}
