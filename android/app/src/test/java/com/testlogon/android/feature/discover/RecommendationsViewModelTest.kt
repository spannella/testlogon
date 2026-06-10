package com.testlogon.android.feature.discover

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.RecommendationItem
import com.testlogon.android.data.discover.Recommendations
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class RecommendationsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeRecommendationsRepository()
    private val actions = FakePostActionsRepository()

    private fun recs(vararg ids: String, source: String = "for_you") =
        Recommendations(ids.map { RecommendationItem(it, "T-$it", null, null) }, source)

    @Test
    fun loadsContent_onInit() = runTest {
        repo.result = ApiResult.Success(recs("v1", "v2"))
        val vm = RecommendationsViewModel(repo, actions)
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is RecommendationsUiState.Content)
        assertEquals(2, (state as RecommendationsUiState.Content).items.size)
    }

    @Test
    fun emptyFeed_collapses() = runTest {
        repo.result = ApiResult.Success(recs())
        val vm = RecommendationsViewModel(repo, actions)
        advanceUntilIdle()
        assertEquals(RecommendationsUiState.Empty, vm.state.value)
    }

    @Test
    fun trendingFallback_flagged() = runTest {
        repo.result = ApiResult.Success(recs("v1", source = "trending_fallback"))
        val vm = RecommendationsViewModel(repo, actions)
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is RecommendationsUiState.Content)
        assertTrue((state as RecommendationsUiState.Content).isTrendingFallback)
    }

    @Test
    fun failure_noCache_emitsError() = runTest {
        repo.result = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = RecommendationsViewModel(repo, actions)
        advanceUntilIdle()
        assertTrue(vm.state.value is RecommendationsUiState.Error)
    }

    @Test
    fun failure_withCache_emitsStaleContent() = runTest {
        repo.result = ApiResult.NetworkError(IOException("x"))
        repo.cachedValue = recs("v1")
        val vm = RecommendationsViewModel(repo, actions)
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is RecommendationsUiState.Content)
        assertTrue((state as RecommendationsUiState.Content).isStale)
    }

    @Test
    fun notInterested_removesItem_andSendsSignal_reusingAND175() = runTest {
        repo.result = ApiResult.Success(recs("v1", "v2"))
        val vm = RecommendationsViewModel(repo, actions)
        advanceUntilIdle()
        vm.onNotInterested("v1")
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is RecommendationsUiState.Content)
        assertEquals(listOf("v2"), (state as RecommendationsUiState.Content).items.map { it.id })
        assertEquals(listOf("v1"), actions.notInterestedIds)
    }

    @Test
    fun notInterested_lastItem_collapsesToEmpty() = runTest {
        repo.result = ApiResult.Success(recs("v1"))
        val vm = RecommendationsViewModel(repo, actions)
        advanceUntilIdle()
        vm.onNotInterested("v1")
        advanceUntilIdle()
        assertEquals(RecommendationsUiState.Empty, vm.state.value)
    }

    @Test
    fun retry_reloads() = runTest {
        repo.result = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = RecommendationsViewModel(repo, actions)
        advanceUntilIdle()
        assertTrue(vm.state.value is RecommendationsUiState.Error)
        repo.result = ApiResult.Success(recs("v1"))
        vm.retry()
        advanceUntilIdle()
        assertTrue(vm.state.value is RecommendationsUiState.Content)
        assertEquals(2, repo.calls)
    }
}
