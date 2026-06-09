package com.testlogon.android.feature.profile.own

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.profile.MediaUploadResult
import com.testlogon.android.core.model.profile.Profile
import com.testlogon.android.core.model.profile.ProfilePatch
import com.testlogon.android.data.profile.MediaKind
import com.testlogon.android.data.profile.ProfileMediaUploader
import com.testlogon.android.data.profile.ProfileRepository
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class OwnProfileViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun profile(name: String = "Sean") = Profile.EMPTY.copy(displayName = name, description = "Bio")

    class FakeRepo : ProfileRepository {
        var ownResult: ApiResult<Profile> = ApiResult.Success(Profile.EMPTY.copy(displayName = "Sean"))
        var cached: Profile? = null
        var ownCalls = 0
        override suspend fun getOwnProfile(forceRefresh: Boolean): ApiResult<Profile> {
            ownCalls++
            return ownResult
        }
        override fun cachedOwnProfile(): Profile? = cached
        override suspend fun getPublicProfile(identifier: String) =
            com.testlogon.android.data.profile.ProfileResult.NotFound
        override suspend fun updateProfile(patch: ProfilePatch): ApiResult<Profile> = ownResult
        override suspend fun uploadPhoto(
            kind: MediaKind,
            upload: ProfileMediaUploader.PreparedUpload,
        ): ApiResult<MediaUploadResult> = ApiResult.Success(MediaUploadResult(null, null))
    }

    @Test
    fun init_loadingThenContent() = runTest(mainRule.dispatcher) {
        val vm = OwnProfileViewModel(FakeRepo().apply { ownResult = ApiResult.Success(profile()) })
        assertEquals(OwnProfileUiState.Phase.Loading, vm.uiState.value.phase)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(OwnProfileUiState.Phase.Content, s.phase)
        assertEquals("Sean", s.profile?.displayName)
        assertFalse(s.isStale)
    }

    @Test
    fun init_errorNoCache_toError() = runTest(mainRule.dispatcher) {
        val vm = OwnProfileViewModel(FakeRepo().apply { ownResult = ApiResult.Failure(ApiError(500, "boom")) })
        advanceUntilIdle()
        assertEquals(OwnProfileUiState.Phase.Error, vm.uiState.value.phase)
        assertEquals("boom", vm.uiState.value.errorMessage)
    }

    @Test
    fun init_failureWithCache_toStaleContent_andEffect() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply {
            ownResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cached = profile()
        }
        val effects = mutableListOf<OwnProfileEffect>()
        val vm = OwnProfileViewModel(repo)
        val job = launch { vm.effects.collect { effects += it } }
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(OwnProfileUiState.Phase.Content, s.phase)
        assertTrue(s.isStale)
        assertTrue(effects.any { it is OwnProfileEffect.ShowMessage })
        job.cancel()
    }

    @Test
    fun retry_fromError_reloadsToContent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { ownResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = OwnProfileViewModel(repo)
        advanceUntilIdle()
        assertEquals(OwnProfileUiState.Phase.Error, vm.uiState.value.phase)
        repo.ownResult = ApiResult.Success(profile())
        vm.onRetry()
        advanceUntilIdle()
        assertEquals(OwnProfileUiState.Phase.Content, vm.uiState.value.phase)
        assertNull(vm.uiState.value.errorMessage)
    }

    @Test
    fun editClicked_emitsNavigateToEdit() = runTest(mainRule.dispatcher) {
        val vm = OwnProfileViewModel(FakeRepo())
        advanceUntilIdle()
        val effects = mutableListOf<OwnProfileEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        vm.onEditClicked()
        advanceUntilIdle()
        assertTrue(effects.any { it is OwnProfileEffect.NavigateToEdit })
        job.cancel()
    }
}
