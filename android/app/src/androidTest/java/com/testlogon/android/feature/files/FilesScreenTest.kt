package com.testlogon.android.feature.files

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.paging.LoadState
import androidx.paging.LoadStates
import androidx.paging.PagingData
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.files.presentation.FilesUiState
import com.testlogon.android.feature.files.ui.FilesScreen
import com.testlogon.android.feature.files.ui.FilesTestTags
import kotlinx.coroutines.flow.flowOf
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-332 - Compose UI smoke tests for the stateless [FilesScreen]. Populated + empty browse use a
 * TERMINAL LoadStates(NotLoading, endOfPaginationReached) via PagingData.from so the empty-state and
 * row rendering settle deterministically; search uses the non-paging [FilesUiState] path.
 */
@RunWith(AndroidJUnit4::class)
class FilesScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun folder(name: String, path: String = "/$name") =
        FileNode(path = path, name = name, type = FileNodeType.FOLDER)

    private fun file(name: String, path: String = "/$name") =
        FileNode(path = path, name = name, type = FileNodeType.FILE, sizeBytes = 100L)

    private fun terminalStates(empty: Boolean) = LoadStates(
        refresh = LoadState.NotLoading(endOfPaginationReached = empty),
        prepend = LoadState.NotLoading(endOfPaginationReached = true),
        append = LoadState.NotLoading(endOfPaginationReached = true),
    )

    private fun launchBrowse(items: List<FileNode>, state: FilesUiState = FilesUiState(rootLabel = "Home")) {
        rule.setContent {
            TestLogonTheme {
                val paging = remember {
                    flowOf(PagingData.from(items, sourceLoadStates = terminalStates(items.isEmpty())))
                }
                FilesScreen(
                    state = state,
                    items = paging.collectAsLazyPagingItems(),
                    onUp = {},
                    onBreadcrumb = {},
                    onOpenFolder = {},
                    onOpenFile = {},
                    onSearchChanged = {},
                    onToggleSearchMode = {},
                    onSortChanged = { _, _, _ -> },
                    onRefresh = {},
                )
            }
        }
    }

    private fun launchSearch(state: FilesUiState) {
        rule.setContent {
            TestLogonTheme {
                val paging = remember { flowOf(PagingData.from(emptyList<FileNode>(), sourceLoadStates = terminalStates(true))) }
                FilesScreen(
                    state = state,
                    items = paging.collectAsLazyPagingItems(),
                    onUp = {},
                    onBreadcrumb = {},
                    onOpenFolder = {},
                    onOpenFile = {},
                    onSearchChanged = {},
                    onToggleSearchMode = {},
                    onSortChanged = { _, _, _ -> },
                    onRefresh = {},
                )
            }
        }
    }

    @Test
    fun rendersRows_andSortAffordance() {
        launchBrowse(listOf(folder("docs"), file("a.txt")))
        rule.onNodeWithTag(FilesTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(FilesTestTags.SORT).assertIsDisplayed()
        rule.onAllNodesWithTag(FilesTestTags.LIST).assertCountEquals(1)
        rule.onNodeWithTag("file_row_/docs", useUnmergedTree = true).assertExists()
        rule.onNodeWithTag("file_row_/a.txt", useUnmergedTree = true).assertExists()
    }

    @Test
    fun rendersBreadcrumb_forNestedPath() {
        launchBrowse(
            items = listOf(file("a.txt")),
            state = FilesUiState(currentPath = "/docs", rootLabel = "Home"),
        )
        // root crumb (index 0) + "docs" crumb (index 1).
        rule.onNodeWithTag(FilesTestTags.breadcrumb(0), useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(FilesTestTags.breadcrumb(1), useUnmergedTree = true).assertExists()
    }

    @Test
    fun emptyFolder_showsEmptyCopy() {
        launchBrowse(emptyList())
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithTag(FilesTestTags.EMPTY).fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithText("This folder is empty").assertIsDisplayed()
    }

    @Test
    fun emptySearch_showsNoMatchesCopy() {
        launchSearch(
            FilesUiState(
                rootLabel = "Home",
                searchQuery = "zz",
                isSearching = true,
                searchLoading = false,
                searchResults = emptyList(),
            ),
        )
        rule.onNodeWithTag(FilesTestTags.EMPTY).assertExists()
        rule.onNodeWithText("No matches").assertIsDisplayed()
    }

    @Test
    fun searchResults_renderRows() {
        launchSearch(
            FilesUiState(
                rootLabel = "Home",
                searchQuery = "re",
                isSearching = true,
                searchLoading = false,
                searchResults = listOf(file("readme.md", "/readme.md")),
            ),
        )
        rule.onNodeWithTag("file_row_/readme.md", useUnmergedTree = true).assertExists()
    }
}
