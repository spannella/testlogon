package com.testlogon.android.feature.discover

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.RecentSearch
import com.testlogon.android.data.discover.SearchCategory
import com.testlogon.android.data.discover.SearchEntityType
import com.testlogon.android.data.discover.SearchFilters
import com.testlogon.android.data.discover.SearchResult
import com.testlogon.android.data.discover.SearchResults
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class GlobalSearchViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeSearchRepository()
    private val history = FakeSearchHistoryRepository()

    private fun vm(saved: SavedStateHandle = SavedStateHandle()) =
        GlobalSearchViewModel(repo, history, saved)

    private fun results(query: String = "jane") = SearchResults(
        query = query,
        categories = listOf(
            SearchCategory(
                type = SearchEntityType.USER,
                items = listOf(SearchResult("u1", SearchEntityType.USER, "Jane", "@jane", null, "/users/u1")),
                totalEstimate = 8,
                hasMore = true,
            ),
            SearchCategory(
                type = SearchEntityType.POST,
                items = listOf(SearchResult("c1", SearchEntityType.POST, "Post", null, null, "/posts/c1")),
                totalEstimate = 1,
                hasMore = false,
            ),
        ),
    )

    @Test
    fun idle_onStart() = runTest {
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        advanceUntilIdle()
        assertEquals(MultiSearchUiState.Idle, vm.uiState.value)
    }

    @Test
    fun happyPath_categorizedResults() = runTest {
        repo.result = ApiResult.Success(results())
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("jane")
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is MultiSearchUiState.Success)
        assertEquals(2, (state as MultiSearchUiState.Success).results.categories.size)
        assertEquals(2, state.results.totalCount)
    }

    @Test
    fun rapidTyping_coalescesToSingleSearch_latestWins() = runTest {
        repo.result = ApiResult.Success(results())
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("ja")
        advanceTimeBy(100)
        vm.onQueryChange("jan")
        advanceTimeBy(100)
        vm.onQueryChange("jane")
        advanceUntilIdle()
        assertEquals(listOf("jane"), repo.queries)
    }

    @Test
    fun shortQuery_staysIdle_noCall() = runTest {
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("j")
        advanceUntilIdle()
        assertEquals(MultiSearchUiState.Idle, vm.uiState.value)
        assertTrue(repo.queries.isEmpty())
    }

    @Test
    fun emptyResults_emitsEmpty() = runTest {
        repo.result = ApiResult.Success(SearchResults("zzzz", emptyList()))
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("zzzz")
        advanceUntilIdle()
        assertTrue(vm.uiState.value is MultiSearchUiState.Empty)
    }

    @Test
    fun failure_emitsError() = runTest {
        repo.result = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("jane")
        advanceUntilIdle()
        assertTrue(vm.uiState.value is MultiSearchUiState.Error)
    }

    @Test
    fun networkError_withCache_emitsStaleSuccess() = runTest {
        repo.result = ApiResult.NetworkError(IOException("x"))
        repo.cachedByQuery["jane"] = results()
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("jane")
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is MultiSearchUiState.Success)
        assertTrue((state as MultiSearchUiState.Success).stale)
    }

    @Test
    fun selectedTab_roundTripsThroughSavedState() = runTest {
        val saved = SavedStateHandle()
        val vm = vm(saved)
        vm.onTabSelected(MultiSearchTab.Category(SearchEntityType.POST))
        assertEquals(MultiSearchTab.Category(SearchEntityType.POST), vm.selectedTab.value)
        // A fresh VM restores the selection from saved state.
        val restored = vm(saved)
        assertEquals(MultiSearchTab.Category(SearchEntityType.POST), restored.selectedTab.value)
    }

    @Test
    fun query_roundTripsThroughSavedState() = runTest {
        val saved = SavedStateHandle()
        val vm = vm(saved)
        vm.onQueryChange("jane")
        assertEquals("jane", saved.get<String>("global_search_query"))
    }

    // ---- AND-186 / AND-188: filters ----

    @Test
    fun applyFilter_sendsTypesParam_andReissuesQuery() = runTest {
        repo.result = ApiResult.Success(results())
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("jane")
        advanceUntilIdle()
        // First call is un-scoped (ALL -> null types).
        assertEquals(listOf<String?>(null), repo.filterTypes)

        vm.applyFilters(SearchFilters(SearchEntityType.USER))
        advanceUntilIdle()
        // Re-issued under the USER scope; "users" is the plural section key.
        assertEquals(listOf<String?>(null, "users"), repo.filterTypes)
        // Query text preserved across the filter change.
        assertEquals(listOf("jane", "jane"), repo.queries)
    }

    @Test
    fun applyFilter_alsoSelectsMatchingTab() = runTest {
        repo.result = ApiResult.Success(results())
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("jane")
        vm.applyFilters(SearchFilters(SearchEntityType.POST))
        advanceUntilIdle()
        assertEquals(MultiSearchTab.Category(SearchEntityType.POST), vm.selectedTab.value)
        assertEquals(SearchEntityType.POST, vm.filters.value.entityType)
    }

    @Test
    fun clearFilters_resetsToAll_andReissues() = runTest {
        repo.result = ApiResult.Success(results())
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("jane")
        advanceUntilIdle() // let the initial (ALL) search settle before changing filters
        vm.applyFilters(SearchFilters(SearchEntityType.USER))
        advanceUntilIdle()
        vm.clearFilters()
        advanceUntilIdle()
        assertTrue(vm.filters.value.isDefault)
        assertEquals(MultiSearchTab.All, vm.selectedTab.value)
        // null (ALL) -> users -> null (cleared back to ALL).
        assertEquals(listOf<String?>(null, "users", null), repo.filterTypes)
    }

    @Test
    fun filter_roundTripsThroughSavedState() = runTest {
        val saved = SavedStateHandle()
        val vm = vm(saved)
        vm.applyFilters(SearchFilters(SearchEntityType.VIDEO))
        val restored = vm(saved)
        assertEquals(SearchEntityType.VIDEO, restored.filters.value.entityType)
    }

    @Test
    fun emptyResults_withFilter_marksFiltersActive() = runTest {
        repo.result = ApiResult.Success(SearchResults("zzzz", emptyList()))
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("zzzz")
        vm.applyFilters(SearchFilters(SearchEntityType.USER))
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is MultiSearchUiState.Empty)
        assertTrue((state as MultiSearchUiState.Empty).filtersActive)
    }

    @Test
    fun emptyResults_noFilter_filtersInactive() = runTest {
        repo.result = ApiResult.Success(SearchResults("zzzz", emptyList()))
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("zzzz")
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is MultiSearchUiState.Empty)
        assertFalse((state as MultiSearchUiState.Empty).filtersActive)
    }

    // ---- AND-186 / AND-188: recent searches (server-backed) ----

    @Test
    fun init_loadsRecentSearches() = runTest {
        history.items = mutableListOf(RecentSearch("r1", "kotlin"), RecentSearch("r2", "compose"))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(listOf("kotlin", "compose"), vm.recent.value.map { it.query })
    }

    @Test
    fun successfulSearch_recordsQueryToHistory() = runTest {
        repo.result = ApiResult.Success(results())
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("jane")
        advanceUntilIdle()
        assertEquals(listOf("jane" to 2), history.recorded)
        assertTrue(vm.recent.value.any { it.query == "jane" })
    }

    @Test
    fun emptySearch_doesNotRecordHistory() = runTest {
        repo.result = ApiResult.Success(SearchResults("zzzz", emptyList()))
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.onQueryChange("zzzz")
        advanceUntilIdle()
        assertTrue(history.recorded.isEmpty())
    }

    @Test
    fun runRecent_setsQuery_andRunsSearch() = runTest {
        repo.result = ApiResult.Success(results("kotlin"))
        val vm = vm()
        backgroundScope.launch { vm.uiState.collect {} }
        vm.runRecent("kotlin")
        advanceUntilIdle()
        assertEquals("kotlin", vm.query.value)
        assertEquals(listOf("kotlin"), repo.queries)
    }

    @Test
    fun removeRecent_deletesByIdAndRefreshes() = runTest {
        history.items = mutableListOf(RecentSearch("r1", "kotlin"), RecentSearch("r2", "compose"))
        val vm = vm()
        advanceUntilIdle()
        vm.removeRecent("r1")
        advanceUntilIdle()
        assertEquals(listOf("r1"), history.removed)
        assertEquals(listOf("compose"), vm.recent.value.map { it.query })
    }

    @Test
    fun clearRecent_clearsAll() = runTest {
        history.items = mutableListOf(RecentSearch("r1", "kotlin"))
        val vm = vm()
        advanceUntilIdle()
        vm.clearRecent()
        advanceUntilIdle()
        assertEquals(1, history.cleared)
        assertTrue(vm.recent.value.isEmpty())
    }
}
