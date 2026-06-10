package com.testlogon.android.feature.discover

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.discover.RecentSearch
import com.testlogon.android.data.discover.SearchEntityType
import com.testlogon.android.data.discover.SearchFilters
import com.testlogon.android.data.discover.SearchResult
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-186 / AND-188 — Compose UI smoke tests for the AND-186 surfaces added to the stateless
 * [MultiSearchScreen]: recent searches (Idle), the no-results state with/without filter affordances,
 * and the active-filter chips. Renders hand-built [MultiSearchUiState] so it is decoupled from the VM.
 */
@RunWith(AndroidJUnit4::class)
class MultiSearchScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(
        state: MultiSearchUiState,
        filters: SearchFilters = SearchFilters.DEFAULT,
        recent: List<RecentSearch> = emptyList(),
        onRunRecent: (String) -> Unit = {},
        onRemoveRecent: (String) -> Unit = {},
        onClearRecent: () -> Unit = {},
        onClearFilters: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                MultiSearchScreen(
                    query = if (state is MultiSearchUiState.Idle) "" else "jane",
                    state = state,
                    selectedTab = MultiSearchTab.All,
                    filters = filters,
                    recent = recent,
                    onQueryChange = {},
                    onClearQuery = {},
                    onTabSelected = {},
                    onApplyFilters = {},
                    onClearFilters = onClearFilters,
                    onRunRecent = onRunRecent,
                    onRemoveRecent = onRemoveRecent,
                    onClearRecent = onClearRecent,
                    onRetry = {},
                    onOpenResult = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun idle_showsRecentSearches_andRunsOnTap() {
        var ran: String? = null
        launch(
            state = MultiSearchUiState.Idle,
            recent = listOf(RecentSearch("r1", "kotlin"), RecentSearch("r2", "compose")),
            onRunRecent = { ran = it },
        )
        rule.onNodeWithTag(GlobalSearchTestTags.RECENTS).assertIsDisplayed()
        rule.onAllNodesWithTag(GlobalSearchTestTags.RECENT_ROW).assertCountEquals(2)
        rule.onAllNodesWithTag(GlobalSearchTestTags.RECENT_ROW)[0].performClick()
        assertEquals("kotlin", ran)
    }

    @Test
    fun idle_removeAndClearAll_invokeCallbacks() {
        var removed: String? = null
        var clearedAll = false
        launch(
            state = MultiSearchUiState.Idle,
            recent = listOf(RecentSearch("r1", "kotlin")),
            onRemoveRecent = { removed = it },
            onClearRecent = { clearedAll = true },
        )
        rule.onAllNodesWithTag(GlobalSearchTestTags.RECENT_REMOVE)[0].performClick()
        assertEquals("r1", removed)
        rule.onNodeWithTag(GlobalSearchTestTags.RECENT_CLEAR_ALL).performClick()
        assertEquals(true, clearedAll)
    }

    @Test
    fun noResults_withFilters_showsClearAndSearchAll() {
        launch(state = MultiSearchUiState.Empty("jane", filtersActive = true), filters = SearchFilters(SearchEntityType.USER))
        rule.onNodeWithTag(GlobalSearchTestTags.NO_RESULTS).assertIsDisplayed()
        rule.onNodeWithTag(GlobalSearchTestTags.NO_RESULTS_CLEAR_FILTERS).assertIsDisplayed()
        rule.onNodeWithTag(GlobalSearchTestTags.NO_RESULTS_SEARCH_ALL).assertIsDisplayed()
    }

    @Test
    fun noResults_noFilters_hidesClearFilters() {
        launch(state = MultiSearchUiState.Empty("jane", filtersActive = false))
        rule.onNodeWithTag(GlobalSearchTestTags.NO_RESULTS).assertIsDisplayed()
        rule.onAllNodesWithTag(GlobalSearchTestTags.NO_RESULTS_CLEAR_FILTERS).assertCountEquals(0)
    }

    @Test
    fun activeFilter_showsChips_andClearInvokesCallback() {
        var cleared = false
        launch(
            state = sampleSuccess(),
            filters = SearchFilters(SearchEntityType.USER),
            onClearFilters = { cleared = true },
        )
        rule.onNodeWithTag(GlobalSearchTestTags.FILTER_CHIPS).assertIsDisplayed()
        rule.onNodeWithTag(GlobalSearchTestTags.FILTER_CLEAR).performClick()
        assertEquals(true, cleared)
    }

    private fun sampleSuccess(): MultiSearchUiState.Success =
        MultiSearchUiState.Success(
            com.testlogon.android.data.discover.SearchResults(
                query = "jane",
                categories = listOf(
                    com.testlogon.android.data.discover.SearchCategory(
                        type = SearchEntityType.USER,
                        items = listOf(SearchResult("u1", SearchEntityType.USER, "Jane", "@jane", null, "/users/u1")),
                        totalEstimate = 1,
                        hasMore = false,
                    ),
                ),
            ),
        )
}
