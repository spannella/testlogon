package com.testlogon.android.feature.discover

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.DiscoverContent
import com.testlogon.android.data.discover.DiscoverCreator
import com.testlogon.android.data.discover.DiscoverTag
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class DiscoverViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeDiscoverRepository()

    private fun content() = DiscoverContent(
        suggested = listOf(DiscoverCreator("u1", "Ava", null, null, 10, false)),
        trendingCreators = emptyList(),
        trendingTags = listOf(DiscoverTag("art", 5)),
    )

    @Test
    fun loads_content_onInit() = runTest {
        repo.result = ApiResult.Success(content())
        val vm = DiscoverViewModel(repo)
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is DiscoverUiState.Content)
        assertEquals("u1", (state as DiscoverUiState.Content).content.suggested.single().userId)
    }

    @Test
    fun emptyContent_emitsEmpty() = runTest {
        repo.result = ApiResult.Success(DiscoverContent(emptyList(), emptyList(), emptyList()))
        val vm = DiscoverViewModel(repo)
        advanceUntilIdle()
        assertEquals(DiscoverUiState.Empty, vm.uiState.value)
    }

    @Test
    fun failure_noCache_emitsError() = runTest {
        repo.result = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = DiscoverViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is DiscoverUiState.Error)
    }

    @Test
    fun networkError_noCache_emitsOffline() = runTest {
        repo.result = ApiResult.NetworkError(IOException("x"))
        val vm = DiscoverViewModel(repo)
        advanceUntilIdle()
        assertEquals(DiscoverUiState.Offline, vm.uiState.value)
    }

    @Test
    fun failure_withCache_emitsStaleContent() = runTest {
        repo.result = ApiResult.NetworkError(IOException("x"))
        repo.cachedValue = content()
        val vm = DiscoverViewModel(repo)
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is DiscoverUiState.Content)
        assertTrue((state as DiscoverUiState.Content).isStale)
    }

    @Test
    fun refresh_setsRefreshing_thenContent() = runTest {
        repo.result = ApiResult.Success(content())
        val vm = DiscoverViewModel(repo)
        advanceUntilIdle()
        vm.refresh()
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is DiscoverUiState.Content)
        assertEquals(false, (state as DiscoverUiState.Content).isRefreshing) // cleared after success
        assertEquals(2, repo.calls)
    }

    @Test
    fun onCreatorClick_emitsOpenProfile_once() = runTest {
        repo.result = ApiResult.Success(content())
        val vm = DiscoverViewModel(repo)
        advanceUntilIdle()
        val events = mutableListOf<DiscoverNavEvent>()
        val job = launch { vm.navEvents.collect { events += it } }
        vm.onCreatorClick("u1")
        advanceUntilIdle()
        job.cancel()
        assertEquals(listOf(DiscoverNavEvent.OpenProfile("u1")), events)
    }

    @Test
    fun onTagClick_emitsOpenTag() = runTest {
        repo.result = ApiResult.Success(content())
        val vm = DiscoverViewModel(repo)
        advanceUntilIdle()
        val events = mutableListOf<DiscoverNavEvent>()
        val job = launch { vm.navEvents.collect { events += it } }
        vm.onTagClick("art")
        advanceUntilIdle()
        job.cancel()
        assertEquals(listOf(DiscoverNavEvent.OpenTag("art")), events)
    }
}
