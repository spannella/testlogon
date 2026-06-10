package com.testlogon.android.feature.discover

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.SearchCategory
import com.testlogon.android.data.discover.SearchEntityType
import com.testlogon.android.data.discover.SearchResult
import com.testlogon.android.data.discover.SearchResults
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class GlobalSearchViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeSearchRepository()

    private fun vm(saved: SavedStateHandle = SavedStateHandle()) = GlobalSearchViewModel(repo, saved)

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
}
