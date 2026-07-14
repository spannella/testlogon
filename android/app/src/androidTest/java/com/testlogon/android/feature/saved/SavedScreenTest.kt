package com.testlogon.android.feature.saved

import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.remember
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.paging.LoadState
import androidx.paging.LoadStates
import androidx.paging.PagingData
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.bookmarks.Bookmark
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-096 — Compose UI smoke tests for the stateless [SavedScreen]. */
@RunWith(AndroidJUnit4::class)
class SavedScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun bookmark(id: String) = Bookmark(
        contentType = "post",
        contentId = id,
        collectionId = "default",
        title = "Title $id",
        subtitle = "Snippet $id",
        thumbnailUrl = null,
        savedAtIso = null,
    )

    private fun launch(
        items: List<Bookmark>,
        state: SavedUiState = SavedUiState(),
        onUnsave: (Bookmark) -> Unit = {},
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
                SavedScreen(
                    items = paging.collectAsLazyPagingItems(),
                    state = state,
                    snackbarHostState = remember { SnackbarHostState() },
                    onUnsave = onUnsave,
                    onOpen = { _, _ -> },
                    onSelectCollection = {},
                    onCreateCollection = {},
                    onRenameCollection = { _, _ -> },
                    onDeleteCollection = {},
                    onRequestMove = {},
                    onDismissMove = {},
                    onMoveTo = {},
                    onRefresh = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun rendersRows() {
        launch(listOf(bookmark("post_1"), bookmark("post_2")))
        rule.onAllNodesWithTag(SavedTestTags.ROW).assertCountEquals(2)
    }

    @Test
    fun unsave_invokesCallback() {
        var unsaved: Bookmark? = null
        launch(listOf(bookmark("post_1")), onUnsave = { unsaved = it })
        rule.onAllNodesWithTag(SavedTestTags.UNSAVE).onFirst().performClick()
        rule.runOnIdle { assertEquals("post_1", unsaved?.contentId) }
    }

    @Test
    fun emptyState_rendersWhenNoItems() {
        launch(emptyList())
        // The empty state renders only after the paging flow's first (empty) load completes.
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithText("Nothing saved yet").fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithText("Nothing saved yet").assertIsDisplayed()
    }
}
