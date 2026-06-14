package com.testlogon.android.feature.achievements

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-096 — [AchievementsViewModel] state-machine unit tests. */
class AchievementsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    @Test
    fun load_success_partitionsEarnedLocked() = runTest {
        val repo = FakeAchievementsRepository().apply {
            catalogResults.add(
                ApiResult.Success(
                    FakeAchievementsRepository.catalog(
                        earned = listOf(FakeAchievementsRepository.earned("a")),
                        locked = listOf(FakeAchievementsRepository.locked("b", 7, 10)),
                    ),
                ),
            )
        }
        val vm = AchievementsViewModel(repo)
        advanceUntilIdle()

        val state = vm.uiState.value
        assertTrue(state is AchievementsUiState.Content)
        val content = state as AchievementsUiState.Content
        assertEquals(1, content.catalog.earned.size)
        assertEquals(1, content.catalog.locked.size)
        assertEquals(0.7f, content.catalog.locked.first().progress?.fraction)
    }

    @Test
    fun load_empty_mapsToEmpty() = runTest {
        val repo = FakeAchievementsRepository().apply {
            catalogResults.add(ApiResult.Success(FakeAchievementsRepository.emptyCatalog()))
        }
        val vm = AchievementsViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is AchievementsUiState.Empty)
    }

    @Test
    fun load_failure_noCache_mapsToError_andRetryRecovers() = runTest {
        val repo = FakeAchievementsRepository().apply {
            catalogResults.add(FakeAchievementsRepository.failure(500))
            catalogResults.add(
                ApiResult.Success(
                    FakeAchievementsRepository.catalog(listOf(FakeAchievementsRepository.earned("a")), emptyList()),
                ),
            )
        }
        val vm = AchievementsViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is AchievementsUiState.Error)

        vm.retry()
        advanceUntilIdle()
        assertTrue(vm.uiState.value is AchievementsUiState.Content)
    }

    @Test
    fun refresh_overContent_transientFailure_keepsContent() = runTest {
        val good = ApiResult.Success(
            FakeAchievementsRepository.catalog(listOf(FakeAchievementsRepository.earned("a")), emptyList()),
        )
        val repo = FakeAchievementsRepository().apply {
            catalogResults.add(good)
            catalogResults.add(FakeAchievementsRepository.failure(500))
        }
        val vm = AchievementsViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is AchievementsUiState.Content)

        vm.refresh()
        advanceUntilIdle()
        // Content retained on a transient refresh failure (not blown away).
        val state = vm.uiState.value
        assertTrue(state is AchievementsUiState.Content)
        assertEquals(false, (state as AchievementsUiState.Content).isRefreshing)
    }
}
