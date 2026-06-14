package com.testlogon.android.feature.syndicates

import androidx.lifecycle.SavedStateHandle
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.LicensingContentType
import com.testlogon.android.core.model.syndicates.OpenLicensingContent
import com.testlogon.android.core.model.syndicates.RegistrationResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.syndicates.testing.FakeSyndicateRepo
import com.testlogon.android.feature.syndicates.ui.OpenLicensingUiState
import com.testlogon.android.feature.syndicates.ui.OpenLicensingViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-357 - tests for [OpenLicensingViewModel]: load -> Content / Empty; isFormValid gating; submit success
 * -> lastResult set + form closed + list REFETCHED (assert the list re-fetch ran, never an optimistic
 * prepend); submit 422 -> per-field inline errors by loc tail (form stays open); submit other failure ->
 * retryable submitError (form stays open). Uses runCurrent (NOT advanceUntilIdle).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OpenLicensingViewModelTest {

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private val parser = ApiErrorParser(Moshi.Builder().build())

    private fun makeVm(repo: FakeSyndicateRepo, syndicateId: String = "syn_1") = OpenLicensingViewModel(
        repository = repo,
        errorParser = parser,
        savedState = SavedStateHandle(mapOf(OpenLicensingViewModel.ARG_SYNDICATE_ID to syndicateId)),
    )

    private fun sampleRow(id: String) = OpenLicensingContent(
        contentId = id, contentType = LicensingContentType.VIDEO, creatorId = "usr_a",
        exempt = false, registeredAt = 1L,
    )

    @Test
    fun load_withItems_isContent() = runTest {
        val repo = FakeSyndicateRepo(
            licensingResult = { ApiResult.Success(listOf(sampleRow("vid_1"))) },
        )
        val vm = makeVm(repo)
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is OpenLicensingUiState.Content)
        assertEquals(listOf("vid_1"), (state as OpenLicensingUiState.Content).items.map { it.contentId })
    }

    @Test
    fun load_emptyList_isEmpty() = runTest {
        val repo = FakeSyndicateRepo(licensingResult = { ApiResult.Success(emptyList()) })
        val vm = makeVm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is OpenLicensingUiState.Empty)
    }

    @Test
    fun load_failure_isError() = runTest {
        val repo = FakeSyndicateRepo(licensingResult = { FakeSyndicateRepo.failure(status = 500) })
        val vm = makeVm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is OpenLicensingUiState.Error)
    }

    @Test
    fun isFormValid_requiresContentId_andContentType() = runTest {
        val repo = FakeSyndicateRepo(licensingResult = { ApiResult.Success(emptyList()) })
        val vm = makeVm(repo)
        runCurrent()

        vm.openForm()
        assertFalse(vm.uiState.value.form.isValid)

        vm.onContentIdChange("vid_1")
        assertFalse(vm.uiState.value.form.isValid)

        vm.onContentTypeChange(LicensingContentType.VIDEO)
        assertTrue(vm.uiState.value.form.isValid)

        // a blank (whitespace) id is NOT valid
        vm.onContentIdChange("   ")
        assertFalse(vm.uiState.value.form.isValid)
    }

    @Test
    fun submit_success_setsLastResult_closesForm_andRefetchesList() = runTest {
        // The list is empty on the initial load, then re-fetched (with the new row) AFTER the register.
        var afterRegister = false
        val repo = FakeSyndicateRepo(
            licensingResult = {
                if (afterRegister) ApiResult.Success(listOf(sampleRow("vid_1")))
                else ApiResult.Success(emptyList())
            },
            registerResult = ApiResult.Success(RegistrationResult(contentId = "vid_1", licensesCreated = 3)),
        )
        val vm = makeVm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is OpenLicensingUiState.Empty)
        val loadsBeforeSubmit = repo.licensingContentCallCount

        vm.openForm()
        vm.onContentIdChange("vid_1")
        vm.onContentTypeChange(LicensingContentType.VIDEO)
        afterRegister = true
        vm.submit()
        runCurrent()

        // form closed + success feedback
        val form = vm.uiState.value.form
        assertFalse(form.visible)
        assertEquals(3, form.lastResult)
        assertNull(form.submitError)
        // the list was REFETCHED (one extra getOpenLicensingContent call), NOT optimistically prepended
        assertEquals(loadsBeforeSubmit + 1, repo.licensingContentCallCount)
        assertEquals(1, repo.registerCallCount)
        val state = vm.uiState.value
        assertTrue(state is OpenLicensingUiState.Content)
        assertEquals(listOf("vid_1"), (state as OpenLicensingUiState.Content).items.map { it.contentId })
    }

    @Test
    fun submit_422_mapsPerFieldErrors_byLocTail_andKeepsFormOpen() = runTest {
        val repo = FakeSyndicateRepo(
            licensingResult = { ApiResult.Success(emptyList()) },
            registerResult = FakeSyndicateRepo.failure422(
                "content_id" to "must not be blank",
                "content_type" to "invalid type",
            ),
        )
        val vm = makeVm(repo)
        runCurrent()

        vm.openForm()
        vm.onContentIdChange("vid_1")
        vm.onContentTypeChange(LicensingContentType.VIDEO)
        vm.submit()
        runCurrent()

        val form = vm.uiState.value.form
        assertTrue(form.visible)
        assertEquals("must not be blank", form.contentIdError)
        assertEquals("invalid type", form.contentTypeError)
        assertNull(form.submitError)
        assertFalse(form.submitting)
        // no refetch on a failed submit
        assertEquals(1, repo.licensingContentCallCount)
    }

    @Test
    fun submit_otherFailure_setsRetryableError_andKeepsFormOpen() = runTest {
        val repo = FakeSyndicateRepo(
            licensingResult = { ApiResult.Success(emptyList()) },
            registerResult = FakeSyndicateRepo.failure(status = 500),
        )
        val vm = makeVm(repo)
        runCurrent()

        vm.openForm()
        vm.onContentIdChange("vid_1")
        vm.onContentTypeChange(LicensingContentType.VIDEO)
        vm.submit()
        runCurrent()

        val form = vm.uiState.value.form
        assertTrue(form.visible)
        assertNull(form.contentIdError)
        assertNull(form.contentTypeError)
        assertEquals("boom", form.submitError)
    }
}
