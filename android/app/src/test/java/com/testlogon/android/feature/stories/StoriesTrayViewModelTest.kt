package com.testlogon.android.feature.stories

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.stories.StoriesRepository
import com.testlogon.android.data.stories.StoryBarItem
import com.testlogon.android.data.stories.StorySegment
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-203 — fills the missing JVM coverage for [StoriesTrayViewModel] (AND-199/AND-202): it surfaces the
 * repository tray flow as state, refreshes on init, and refresh() re-issues the network tray fetch.
 * Ordering follows server order (web parity — asserted preserved, NOT client-sorted).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class StoriesTrayViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun bar(userId: String, unseen: Boolean) =
        StoryBarItem(userId, "s_$userId", null, 1, hasUnseen = unseen, isOwn = false)

    @Test
    fun init_refreshes_andSurfacesTray_inServerOrder() = runTest {
        val repo = TrayFakeRepository(
            tray = listOf(bar("seen", unseen = false), bar("unseen", unseen = true)),
        )
        val model = StoriesTrayViewModel(repo)
        val job = launch { model.tray.collect {} } // activate the WhileSubscribed upstream
        advanceUntilIdle()
        val state = model.tray.value
        job.cancel()
        assertTrue(state is ApiResult.Success)
        // Server order preserved (web parity: no client unseen-first sort that would desync the viewer).
        assertEquals(listOf("seen", "unseen"), (state as ApiResult.Success).data.map { it.userId })
        assertEquals(1, repo.refreshCount)
    }

    @Test
    fun refresh_reissuesTrayFetch() = runTest {
        val repo = TrayFakeRepository(tray = listOf(bar("a", unseen = true)))
        val model = StoriesTrayViewModel(repo)
        advanceUntilIdle()
        model.refresh()
        advanceUntilIdle()
        assertEquals(2, repo.refreshCount) // init + explicit refresh
    }

    @Test
    fun emptyTray_isSuccessEmpty_notError() = runTest {
        val repo = TrayFakeRepository(tray = emptyList())
        val model = StoriesTrayViewModel(repo)
        advanceUntilIdle()
        val state = model.tray.value
        assertTrue(state is ApiResult.Success)
        assertTrue((state as ApiResult.Success).data.isEmpty())
    }

    @Test
    fun failedTray_surfacesFailure() = runTest {
        val repo = TrayFakeRepository(
            tray = emptyList(),
            trayState = ApiResult.Failure(ApiError(status = 503, message = "down")),
        )
        val model = StoriesTrayViewModel(repo)
        val job = launch { model.tray.collect {} } // activate the WhileSubscribed upstream
        advanceUntilIdle()
        val failure = model.tray.value
        job.cancel()
        assertTrue(failure is ApiResult.Failure)
    }
}

/** Tray-focused [StoriesRepository] fake exposing a controllable trayFlow + refresh counter. */
private class TrayFakeRepository(
    tray: List<StoryBarItem>,
    trayState: ApiResult<List<StoryBarItem>> = ApiResult.Success(tray),
) : StoriesRepository {
    private val flow = MutableStateFlow(trayState)
    private val refreshResult: ApiResult<List<StoryBarItem>> = trayState
    var refreshCount = 0
        private set

    override fun trayFlow(): Flow<ApiResult<List<StoryBarItem>>> = flow
    override suspend fun refreshTray(): ApiResult<List<StoryBarItem>> {
        refreshCount++
        return refreshResult
    }
    override suspend fun loadAuthorStories(userId: String): ApiResult<List<StorySegment>> =
        ApiResult.Success(emptyList())
    override suspend fun recordView(storyId: String): ApiResult<Unit> = ApiResult.Success(Unit)
    override fun isViewed(storyId: String): Boolean = false
    override fun markAuthorSeen(userId: String) {}
}
