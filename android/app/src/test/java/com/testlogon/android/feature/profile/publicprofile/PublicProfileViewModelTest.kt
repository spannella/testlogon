package com.testlogon.android.feature.profile.publicprofile

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.model.profile.MediaUploadResult
import com.testlogon.android.core.model.profile.Profile
import com.testlogon.android.core.model.profile.ProfilePatch
import com.testlogon.android.core.model.profile.PublicProfile
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.profile.MediaKind
import com.testlogon.android.data.profile.ProfileMediaUploader
import com.testlogon.android.data.profile.ProfileRepository
import com.testlogon.android.data.profile.ProfileResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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

    // AND-390 — a minimal AuthStateStore double whose isAuthenticated is settable per test (FR-7).
    private class FakeAuth(authenticated: Boolean) : AuthStateStore {
        override val isAuthenticated = MutableStateFlow(authenticated)
        override val userSub: StateFlow<String?> = MutableStateFlow(if (authenticated) "usr_me" else null)
        override suspend fun setAuthenticated(userSub: String) { isAuthenticated.value = true }
        override suspend fun clear(reason: LogoutReason) { isAuthenticated.value = false }
        override suspend fun lastLogoutReason(): LogoutReason? = null
        override suspend fun clearLogoutReason() = Unit
    }

    // AND-390 — fixed published App Link host so shareUrl never depends on the dev base URL (TC-04).
    private val shareHost = ProfileShareHostProvider { "app.testlogon.example.com" }

    private fun vm(
        repo: ProfileRepository,
        identifier: String = "ada",
        authenticated: Boolean = false,
    ) = PublicProfileViewModel(
        repo,
        FakeAuth(authenticated),
        shareHost,
        SavedStateHandle(mapOf("identifier" to identifier)),
    )

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

    // ── AND-390 polish ──────────────────────────────────────────────────────────────────────────

    @Test
    fun signedOut_isAuthenticatedFalse() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(ProfileResult.Found(publicProfile())), authenticated = false)
        advanceUntilIdle()
        assertFalse(vm.isAuthenticated.value)
    }

    @Test
    fun signedIn_isAuthenticatedTrue() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(ProfileResult.Found(publicProfile())), authenticated = true)
        advanceUntilIdle()
        assertTrue(vm.isAuthenticated.value)
    }

    @Test
    fun shareUrl_isProductionHost_notDevHost() = runTest(mainRule.dispatcher) {
        // TC-AND-390-04: even though the dev base URL is the plaintext dev host, the share URL is the
        // canonical production https /u/<id> on the published App Link host.
        val vm = vm(FakeRepo(ProfileResult.Found(publicProfile())), identifier = "ada")
        advanceUntilIdle()
        assertEquals("https://app.testlogon.example.com/u/ada", vm.shareUrl)
    }

    @Test
    fun shareUrl_blankIdentifier_isNull() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(ProfileResult.Found(publicProfile())), identifier = "   ")
        advanceUntilIdle()
        assertNull(vm.shareUrl)
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
