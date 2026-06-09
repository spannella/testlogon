package com.testlogon.android.feature.achievements

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.achievements.Leaderboard
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-096 — [LeaderboardViewModel] state-machine unit tests. */
class LeaderboardViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    @Test
    fun load_success_rendersEntries_andMe() = runTest {
        val repo = FakeAchievementsRepository().apply {
            leaderboardResult = ApiResult.Success(
                Leaderboard(
                    entries = listOf(
                        FakeAchievementsRepository.entry(1, "u_a"),
                        FakeAchievementsRepository.entry(2, "u_me", isMe = true),
                    ),
                    me = FakeAchievementsRepository.entry(2, "u_me", isMe = true),
                    nextCursor = null,
                    period = "alltime",
                ),
            )
        }
        val vm = LeaderboardViewModel(repo)
        advanceUntilIdle()

        val state = vm.uiState.value
        assertTrue(state is LeaderboardUiState.Content)
        val content = state as LeaderboardUiState.Content
        assertEquals(2, content.entries.size)
        assertEquals("u_me", content.me?.userSub)
    }

    @Test
    fun load_emptyEntries_mapsToEmpty_keepsMe() = runTest {
        val repo = FakeAchievementsRepository().apply {
            leaderboardResult = ApiResult.Success(
                Leaderboard(emptyList(), FakeAchievementsRepository.entry(99, "u_me", isMe = true), null, "alltime"),
            )
        }
        val vm = LeaderboardViewModel(repo)
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is LeaderboardUiState.Empty)
        assertEquals(99, (state as LeaderboardUiState.Empty).me?.rank)
    }

    @Test
    fun load_failure_mapsToError() = runTest {
        val repo = FakeAchievementsRepository().apply {
            leaderboardResult = FakeAchievementsRepository.failure(500)
        }
        val vm = LeaderboardViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is LeaderboardUiState.Error)
    }
}
