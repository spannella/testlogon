package com.testlogon.android.feature.profile.publicprofile

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.profile.MediaUploadResult
import com.testlogon.android.core.model.profile.Profile
import com.testlogon.android.core.model.profile.ProfilePatch
import com.testlogon.android.core.model.profile.PublicProfile
import com.testlogon.android.data.profile.MediaKind
import com.testlogon.android.data.profile.ProfileMediaUploader
import com.testlogon.android.data.profile.ProfileRepository
import com.testlogon.android.data.profile.ProfileResult
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class PublicProfileViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun publicProfile() = PublicProfile(
        userId = "u", identifier = "ada", canonicalIdentifier = "ada", displayName = "Ada",
        title = null, description = "First programmer.", location = null,
        profilePhotoUrl = null, coverPhotoUrl = null,
        followerCount = 10, followingCount = 2, postCount = 5,
        isFollowing = false, isFollowedBy = false, isMutual = false,
        hasSubscriptionPlans = false, createdAtEpochSeconds = null, discoverability = "public",
    )

    class FakeRepo(var result: ProfileResult) : ProfileRepository {
        var calls = 0
        override suspend fun getOwnProfile(forceRefresh: Boolean): ApiResult<Profile> =
            ApiResult.Failure(ApiError(500, "n/a"))
        override fun cachedOwnProfile(): Profile? = null
        override suspend fun getPublicProfile(identifier: String): ProfileResult {
            calls++
            return result
        }
        override suspend fun updateProfile(patch: ProfilePatch): ApiResult<Profile> =
            ApiResult.Failure(ApiError(500, "n/a"))
        override suspend fun uploadPhoto(
            kind: MediaKind,
            upload: ProfileMediaUploader.PreparedUpload,
        ): ApiResult<MediaUploadResult> = ApiResult.Success(MediaUploadResult(null, null))
    }

    private fun vm(repo: ProfileRepository, identifier: String = "ada") =
        PublicProfileViewModel(repo, SavedStateHandle(mapOf("identifier" to identifier)))

    @Test
    fun found_emitsContent() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(ProfileResult.Found(publicProfile())))
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is PublicProfileUiState.Content)
        assertEquals("Ada", (s as PublicProfileUiState.Content).profile.displayName)
    }

    @Test
    fun notFound_emitsNotFound() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(ProfileResult.NotFound))
        advanceUntilIdle()
        assertTrue(vm.uiState.value is PublicProfileUiState.NotFound)
    }

    @Test
    fun rateLimited_emitsRateLimited() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(ProfileResult.RateLimited(30)))
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is PublicProfileUiState.RateLimited)
        assertEquals(30L, (s as PublicProfileUiState.RateLimited).retryAfterSeconds)
    }

    @Test
    fun offline_emitsRetryableError() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(ProfileResult.Offline))
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is PublicProfileUiState.Error)
        assertTrue((s as PublicProfileUiState.Error).retryable)
    }

    @Test
    fun blankIdentifier_notFound_noNetworkCall() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(ProfileResult.Found(publicProfile()))
        val vm = vm(repo, identifier = "   ")
        advanceUntilIdle()
        assertTrue(vm.uiState.value is PublicProfileUiState.NotFound)
        assertEquals(0, repo.calls)
    }

    @Test
    fun retry_fromError_reloadsToContent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(ProfileResult.Offline)
        val vm = vm(repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is PublicProfileUiState.Error)
        repo.result = ProfileResult.Found(publicProfile())
        vm.onRetry()
        advanceUntilIdle()
        assertTrue(vm.uiState.value is PublicProfileUiState.Content)
    }
}
