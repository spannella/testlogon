package com.testlogon.android.feature.settings.media

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.MediaPreferences
import com.testlogon.android.core.model.VideoResolution
import com.testlogon.android.data.preferences.MediaPreferencesRepository
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class MediaPreferencesViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeRepo(
        var refreshResult: ApiResult<MediaPreferences> = ApiResult.Success(MediaPreferences()),
        var updateResult: ApiResult<MediaPreferences> = ApiResult.Success(MediaPreferences()),
        var cachedValue: MediaPreferences? = null,
    ) : MediaPreferencesRepository {
        var updateCalls = 0
        override suspend fun refresh() = refreshResult
        override suspend fun update(prefs: MediaPreferences): ApiResult<MediaPreferences> {
            updateCalls++
            return updateResult
        }
        override fun cached() = cachedValue
    }

    @Test
    fun load_success_rendersReady() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(refreshResult = ApiResult.Success(MediaPreferences(defaultAudioMuted = true)))
        val vm = MediaPreferencesViewModel(repo)
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is MediaPrefsUiState.Ready)
        assertTrue((state as MediaPrefsUiState.Ready).prefs.defaultAudioMuted)
        assertFalse(state.isDirty)
    }

    @Test
    fun load_failureWithMirror_rendersStaleReady() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(
            refreshResult = ApiResult.Failure(ApiError(500, "boom")),
            cachedValue = MediaPreferences(defaultVideoOff = true),
        )
        val vm = MediaPreferencesViewModel(repo)
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is MediaPrefsUiState.Ready)
        assertTrue((state as MediaPrefsUiState.Ready).isStale)
        assertTrue(state.prefs.defaultVideoOff)
    }

    @Test
    fun load_failureNoMirror_rendersError() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(refreshResult = ApiResult.Failure(ApiError(500, "boom")))
        val vm = MediaPreferencesViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.state.value is MediaPrefsUiState.Error)
    }

    @Test
    fun edit_marksDirty_noNetworkUntilSave() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        val vm = MediaPreferencesViewModel(repo)
        advanceUntilIdle()
        vm.onDefaultVideoOffChanged(true)
        val state = vm.state.value as MediaPrefsUiState.Ready
        assertTrue(state.prefs.defaultVideoOff)
        assertTrue(state.isDirty)
        assertEquals(0, repo.updateCalls)
    }

    @Test
    fun save_success_clearsDirty_andCommits() = runTest(mainRule.dispatcher) {
        val saved = MediaPreferences(videoResolution = VideoResolution.P1080)
        val repo = FakeRepo(updateResult = ApiResult.Success(saved))
        val vm = MediaPreferencesViewModel(repo)
        advanceUntilIdle()
        vm.onResolutionSelected(VideoResolution.P1080)
        vm.save()
        advanceUntilIdle()
        val state = vm.state.value as MediaPrefsUiState.Ready
        assertEquals(1, repo.updateCalls)
        assertEquals(VideoResolution.P1080, state.saved.videoResolution)
        assertFalse(state.isDirty)
    }

    @Test
    fun save_failure_keepsEditedForm() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(updateResult = ApiResult.Failure(ApiError(500, "boom")))
        val vm = MediaPreferencesViewModel(repo)
        advanceUntilIdle()
        vm.onDefaultMutedChanged(true)
        vm.save()
        advanceUntilIdle()
        val state = vm.state.value as MediaPrefsUiState.Ready
        assertTrue(state.prefs.defaultAudioMuted) // edited form preserved
        assertTrue(state.isDirty)
        assertFalse(state.isSaving)
    }
}
