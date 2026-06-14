package com.testlogon.android.feature.dmca

import androidx.lifecycle.SavedStateHandle
import com.squareup.moshi.Moshi
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.dmca.DmcaClaimCreateResponse
import com.testlogon.android.data.dmca.DmcaClaimRequest
import com.testlogon.android.data.dmca.DmcaContentType
import com.testlogon.android.data.dmca.DmcaDraft
import com.testlogon.android.data.dmca.DmcaRepository
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-384 - DmcaViewModel unit tests (TC-AND-384-07..08, plus 422-field mapping and error-kind mapping).
 * Uses a fake [DmcaRepository]; no nested runTest. State is read off the StateFlow value; the single
 * in-flight coroutine is driven with runCurrent / advanceUntilIdle on the StandardTestDispatcher.
 */
class DmcaViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeDmcaRepository()
    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    private fun vm(savedState: SavedStateHandle = SavedStateHandle()) =
        DmcaViewModel(repo, errorParser, savedState)

    private fun DmcaViewModel.fillValid() {
        onFieldChanged(DmcaField.OriginalWorkDescription, "Original photograph Sunset number four, registered")
        onFieldChanged(DmcaField.ContentUrl, "https://testlogon.app/p/abc123")
        onFieldChanged(DmcaField.ClaimantName, "Jane Doe")
        onFieldChanged(DmcaField.ClaimantEmail, "jane@example.com")
        onFieldChanged(DmcaField.ClaimantAddress, "123 Main St, Springfield IL")
        onFieldChanged(DmcaField.Signature, "Jane Doe")
        onToggle(DmcaField.SwornStatement, true)
        onToggle(DmcaField.GoodFaithBelief, true)
    }

    private fun form(state: DmcaUiState): DmcaFormState = when (state) {
        is DmcaUiState.Editing -> state.form
        is DmcaUiState.Error -> state.form
        is DmcaUiState.Submitted -> error("submitted has no form")
    }

    // TC-AND-384-07
    @Test
    fun isSubmittable_requiresAllHardRules() {
        val viewModel = vm()
        assertFalse(form(viewModel.uiState.value).isSubmittable)

        viewModel.fillValid()
        assertTrue(form(viewModel.uiState.value).isSubmittable)

        // Missing one attestation -> not submittable.
        viewModel.onToggle(DmcaField.GoodFaithBelief, false)
        assertFalse(form(viewModel.uiState.value).isSubmittable)
        viewModel.onToggle(DmcaField.GoodFaithBelief, true)

        // Description too short (< 20).
        viewModel.onFieldChanged(DmcaField.OriginalWorkDescription, "too short")
        assertFalse(form(viewModel.uiState.value).isSubmittable)
        viewModel.onFieldChanged(
            DmcaField.OriginalWorkDescription,
            "Original photograph Sunset number four, registered",
        )

        // Malformed email.
        viewModel.onFieldChanged(DmcaField.ClaimantEmail, "not-an-email")
        assertFalse(form(viewModel.uiState.value).isSubmittable)
        viewModel.onFieldChanged(DmcaField.ClaimantEmail, "jane@example.com")

        // Empty content URL.
        viewModel.onFieldChanged(DmcaField.ContentUrl, "")
        assertFalse(form(viewModel.uiState.value).isSubmittable)
        viewModel.onFieldChanged(DmcaField.ContentUrl, "https://testlogon.app/p/abc123")

        // Empty signature.
        viewModel.onFieldChanged(DmcaField.Signature, "")
        assertFalse(form(viewModel.uiState.value).isSubmittable)
    }

    // TC-AND-384-08 - success path + single repo call + draft cleared.
    @Test
    fun submit_success_emitsSubmitted_clearsDraft() = runTest {
        repo.deferred = null
        repo.result = ApiResult.Success(
            DmcaClaimCreateResponse(
                ok = true, claimId = "dmca_x", status = "received",
                contentRemoved = false, strikeNumber = 1, createdAt = 1749132069L,
            ),
        )
        val viewModel = vm()
        viewModel.fillValid()
        viewModel.submit()

        // Editing(submitting=true) is the immediate intermediate state.
        val mid = viewModel.uiState.value
        assertTrue(mid is DmcaUiState.Editing && mid.submitting)

        advanceUntilIdle()
        val end = viewModel.uiState.value
        assertTrue(end is DmcaUiState.Submitted)
        assertEquals("dmca_x", (end as DmcaUiState.Submitted).claimId)
        assertEquals(1, repo.submitCalls)
        assertTrue(repo.clearedDraftKeys.isNotEmpty()) // draft cleared on success (FR-7 / AC-6)
    }

    // TC-AND-384-08 - double-tap while submitting issues a single network call.
    @Test
    fun submit_doubleTapWhileSubmitting_isSingleCall() = runTest {
        repo.deferred = CompletableDeferred()
        val viewModel = vm()
        viewModel.fillValid()

        viewModel.submit()
        runCurrent()
        viewModel.submit() // second tap while in flight - must be ignored
        runCurrent()
        assertEquals(1, repo.submitCalls)

        repo.deferred!!.complete(
            ApiResult.Success(
                DmcaClaimCreateResponse(claimId = "dmca_x"),
            ),
        )
        advanceUntilIdle()
        assertTrue(viewModel.uiState.value is DmcaUiState.Submitted)
    }

    // 422 -> field error routed by loc tail; form preserved (AC-5).
    @Test
    fun submit_422_mapsFieldError_preservesForm() = runTest {
        repo.deferred = null
        repo.result = ApiResult.Failure(
            ApiError(
                status = 422,
                message = "validation",
                raw = """{"detail":[{"loc":["body","claimant_email"],"msg":"value is not a valid email address","type":"value_error"}]}""",
            ),
        )
        val viewModel = vm()
        viewModel.fillValid()
        viewModel.submit()
        advanceUntilIdle()

        val state = viewModel.uiState.value
        assertTrue(state is DmcaUiState.Editing)
        val f = (state as DmcaUiState.Editing).form
        assertEquals(
            "value is not a valid email address",
            f.fieldErrors[DmcaField.ClaimantEmail],
        )
        // Form values preserved.
        assertEquals("Jane Doe", f.claimantName)
    }

    // 401 -> Auth kind, distinct message, form preserved.
    @Test
    fun submit_401_mapsToAuthError() = runTest {
        repo.deferred = null
        repo.result = ApiResult.Failure(ApiError(status = 401, message = "unauth"))
        val viewModel = vm()
        viewModel.fillValid()
        viewModel.submit()
        advanceUntilIdle()

        val state = viewModel.uiState.value
        assertTrue(state is DmcaUiState.Error)
        assertEquals(DmcaErrorKind.Auth, (state as DmcaUiState.Error).kind)
        assertEquals(DmcaViewModel.AUTH_MESSAGE, state.message)
        assertEquals("Jane Doe", state.form.claimantName)
    }

    // 429 -> RateLimited kind.
    @Test
    fun submit_429_mapsToRateLimited() = runTest {
        repo.deferred = null
        repo.result = ApiResult.Failure(ApiError(status = 429, message = "slow"))
        val viewModel = vm()
        viewModel.fillValid()
        viewModel.submit()
        advanceUntilIdle()
        val state = viewModel.uiState.value
        assertTrue(state is DmcaUiState.Error)
        assertEquals(DmcaErrorKind.RateLimited, (state as DmcaUiState.Error).kind)
    }

    // Network error -> Network kind with the "not submitted" copy.
    @Test
    fun submit_networkError_mapsToNetwork() = runTest {
        repo.deferred = null
        repo.result = ApiResult.NetworkError(java.io.IOException("boom"), isTimeout = true)
        val viewModel = vm()
        viewModel.fillValid()
        viewModel.submit()
        advanceUntilIdle()
        val state = viewModel.uiState.value
        assertTrue(state is DmcaUiState.Error)
        assertEquals(DmcaErrorKind.Network, (state as DmcaUiState.Error).kind)
        assertEquals(DmcaViewModel.NETWORK_MESSAGE, state.message)
    }

    // Pre-targeted entry prefills + locks the content reference (AC-1).
    @Test
    fun preTargeted_prefillsAndLocksContent() = runTest {
        val saved = SavedStateHandle(
            mapOf(
                DmcaViewModel.ARG_CONTENT_TYPE to DmcaContentType.FEED_POST,
                DmcaViewModel.ARG_CONTENT_ID to "abc123",
                DmcaViewModel.ARG_URL to "https://testlogon.app/p/abc123",
            ),
        )
        val viewModel = vm(saved)
        advanceUntilIdle()
        val f = form(viewModel.uiState.value)
        assertEquals(DmcaContentType.FEED_POST, f.contentType)
        assertEquals("abc123", f.contentId)
        assertEquals("https://testlogon.app/p/abc123", f.contentUrl)
        assertTrue(f.contentLocked)
    }

    // Draft restore (standalone): cached text is restored, attestations/signature stay empty.
    @Test
    fun draftRestore_restoresTextNotAttestations() = runTest {
        repo.seededDraft = DmcaDraft(
            originalWorkDescription = "restored description text here",
            claimantName = "Jane Doe",
            claimantEmail = "jane@example.com",
        )
        val viewModel = vm()
        advanceUntilIdle()
        val f = form(viewModel.uiState.value)
        assertEquals("restored description text here", f.originalWorkDescription)
        assertEquals("Jane Doe", f.claimantName)
        // Attestations + signature are never restored.
        assertFalse(f.swornStatement)
        assertFalse(f.goodFaithBelief)
        assertEquals("", f.signature)
    }

    /** Controllable fake repository. */
    private class FakeDmcaRepository : DmcaRepository {
        var result: ApiResult<DmcaClaimCreateResponse> =
            ApiResult.Success(DmcaClaimCreateResponse(claimId = "dmca_default"))
        var deferred: CompletableDeferred<ApiResult<DmcaClaimCreateResponse>>? = null
        var submitCalls = 0
            private set
        var seededDraft: DmcaDraft? = null
        val clearedDraftKeys = mutableListOf<String>()

        override suspend fun submit(request: DmcaClaimRequest): ApiResult<DmcaClaimCreateResponse> {
            submitCalls++
            return deferred?.await() ?: result
        }

        override suspend fun loadDraft(targetKey: String): DmcaDraft? = seededDraft

        override suspend fun saveDraft(targetKey: String, draft: DmcaDraft) {}

        override suspend fun clearDraft(targetKey: String) {
            clearedDraftKeys += targetKey
        }

        override suspend fun clearAllDrafts() {}
    }
}
