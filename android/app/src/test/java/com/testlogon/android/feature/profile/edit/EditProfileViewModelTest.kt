package com.testlogon.android.feature.profile.edit

import com.squareup.moshi.Moshi
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.profile.MediaUploadResult
import com.testlogon.android.core.model.profile.Profile
import com.testlogon.android.core.model.profile.ProfilePatch
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.profile.MediaKind
import com.testlogon.android.data.profile.ProfileMediaUploader
import com.testlogon.android.data.profile.ProfileRepository
import com.testlogon.android.data.profile.ProfileResult
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class EditProfileViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    private fun baseProfile() = Profile.EMPTY.copy(displayName = "Sean", description = "Old bio", location = "PGH")

    class FakeRepo(initial: Profile?) : ProfileRepository {
        var cached: Profile? = initial
        var updateResult: ApiResult<Profile> = ApiResult.Success(Profile.EMPTY.copy(displayName = "Sean"))
        var lastPatch: ProfilePatch? = null
        var updateCalls = 0
        override suspend fun getOwnProfile(forceRefresh: Boolean): ApiResult<Profile> =
            cached?.let { ApiResult.Success(it) } ?: ApiResult.Failure(ApiError(500, "no profile"))
        override fun cachedOwnProfile(): Profile? = cached
        override suspend fun getPublicProfile(identifier: String): ProfileResult = ProfileResult.NotFound
        override suspend fun updateProfile(patch: ProfilePatch): ApiResult<Profile> {
            updateCalls++
            lastPatch = patch
            return updateResult
        }
        override suspend fun uploadPhoto(
            kind: MediaKind,
            upload: ProfileMediaUploader.PreparedUpload,
        ): ApiResult<MediaUploadResult> = ApiResult.Success(MediaUploadResult(null, null))
    }

    private fun vm(repo: ProfileRepository) = EditProfileViewModel(repo, ProfileValidator(), errorParser)

    @Test
    fun load_seedsFormFromCache_notDirty() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(baseProfile()))
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(EditProfileUiState.Phase.Editing, s.phase)
        assertEquals("Sean", s.form.displayName)
        assertFalse(s.isDirty)
        assertFalse(s.canSave)
    }

    @Test
    fun fieldChange_makesDirty_andCanSave() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(baseProfile()))
        advanceUntilIdle()
        vm.onDisplayNameChange("New Name")
        val s = vm.uiState.value
        assertTrue(s.isDirty)
        assertTrue(s.canSave)
    }

    @Test
    fun invalidField_blocksSave() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(baseProfile()))
        advanceUntilIdle()
        vm.onDisplayNameChange("")
        val s = vm.uiState.value
        assertNotNull(s.errors.displayName)
        assertFalse(s.canSave)
    }

    @Test
    fun save_sendsOnlyChangedFields_andNavigatesBack() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(baseProfile())
        val vm = vm(repo)
        advanceUntilIdle()
        val effects = mutableListOf<EditProfileEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        vm.onDescriptionChange("New bio")
        vm.onSave()
        advanceUntilIdle()
        // Only description changed.
        assertEquals("New bio", repo.lastPatch?.description)
        assertEquals(null, repo.lastPatch?.displayName)
        assertTrue(effects.any { it is EditProfileEffect.NavigateBack })
        job.cancel()
    }

    @Test
    fun save_422_mapsFieldError_staysEditing_noNav() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(baseProfile()).apply {
            updateResult = ApiResult.Failure(
                ApiError(
                    status = 422,
                    message = "Validation error",
                    raw = """{"detail":[{"loc":["body","display_name"],"msg":"too long","type":"value_error"}]}""",
                ),
            )
        }
        val vm = vm(repo)
        advanceUntilIdle()
        vm.onDisplayNameChange("New Name")
        vm.onSave()
        advanceUntilIdle()
        val s = vm.uiState.value
        assertNotNull(s.errors.displayName)
        assertEquals(EditProfileUiState.Phase.Editing, s.phase)
        assertFalse(s.isSaving)
    }

    @Test
    fun save_otherFailure_setsSaveError() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(baseProfile()).apply {
            updateResult = ApiResult.Failure(ApiError(500, "server boom"))
        }
        val vm = vm(repo)
        advanceUntilIdle()
        vm.onTitleChange("Builder")
        vm.onSave()
        advanceUntilIdle()
        assertEquals("server boom", vm.uiState.value.saveError)
        assertEquals(1, repo.updateCalls) // never auto-retried
    }

    @Test
    fun back_withChanges_emitsConfirmDiscard_else_navigateBack() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeRepo(baseProfile()))
        advanceUntilIdle()
        val effects = mutableListOf<EditProfileEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        vm.onBackPressed()
        advanceUntilIdle()
        assertTrue(effects.any { it is EditProfileEffect.NavigateBack })
        effects.clear()
        vm.onDisplayNameChange("Changed")
        vm.onBackPressed()
        advanceUntilIdle()
        assertTrue(effects.any { it is EditProfileEffect.ConfirmDiscard })
        job.cancel()
    }

    @Test
    fun buildPatch_onlyChanged() {
        val baseline = EditProfileForm(displayName = "A", description = "B", title = "C", location = "D")
        val current = baseline.copy(description = "B2")
        val patch = buildPatch(baseline, current)
        assertEquals("B2", patch.description)
        assertEquals(null, patch.displayName)
        assertEquals(null, patch.title)
    }
}
