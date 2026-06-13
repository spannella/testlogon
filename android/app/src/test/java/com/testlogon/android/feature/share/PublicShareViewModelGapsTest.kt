package com.testlogon.android.feature.share

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.share.data.DownloadOutcome
import com.testlogon.android.feature.share.data.ShareDownloader
import com.testlogon.android.feature.share.data.ShareRepository
import com.testlogon.android.feature.share.model.PublicShare
import com.testlogon.android.feature.share.model.PublicShareState
import com.testlogon.android.feature.share.model.ShareLink
import com.testlogon.android.feature.share.model.ShareLinkOptions
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-338 - additional [PublicShareViewModel] coverage beyond [PublicShareViewModelTest].
 *
 * These ADD: a blank link id resolves straight to a Terminal(UNAVAILABLE) panel; onPasswordChange edits
 * the gate field and clears the prior password error; the download double-send guard ignores a second tap
 * while one is in flight; the in-flight download projects fractional progress; a non-auth download error
 * on a NON-password share surfaces inline (it does NOT re-raise a password gate); and a resolve Failure
 * with a 5xx status derives a retryable Error.
 *
 * ANTI-HANG: no poll loop; runCurrent() only - NEVER advanceUntilIdle. The downloader flow is bounded or
 * explicitly parked on a gate the test releases. No nested runTest; distinct fake-helper names.
 */
class PublicShareViewModelGapsTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class GapsRepo(
        var resolveResult: ApiResult<PublicShare> =
            ApiResult.Success(gapsShare(PublicShareState.AVAILABLE, passwordRequired = false)),
    ) : ShareRepository {
        override suspend fun listLinks(fileId: String): ApiResult<List<ShareLink>> =
            throw UnsupportedOperationException()
        override suspend fun createLink(fileId: String, options: ShareLinkOptions): ApiResult<ShareLink> =
            throw UnsupportedOperationException()
        override suspend fun revokeLink(linkId: String): ApiResult<Unit> =
            throw UnsupportedOperationException()
        override suspend fun resolvePublic(linkId: String, password: String?): ApiResult<PublicShare> =
            resolveResult
    }

    private class GapsDownloader(
        var flowFactory: () -> Flow<DownloadOutcome> = { flow {} },
    ) : ShareDownloader {
        var calls = 0
        override fun downloadPublic(
            linkId: String,
            password: String?,
            fileName: String?,
            contentType: String?,
        ): Flow<DownloadOutcome> {
            calls++
            return flowFactory()
        }
    }

    private fun vm(
        repo: ShareRepository,
        downloader: ShareDownloader,
        linkId: String? = "lnk_1",
    ): PublicShareViewModel =
        PublicShareViewModel(
            repo,
            downloader,
            SavedStateHandle(
                if (linkId == null) emptyMap() else mapOf(PublicShareViewModel.ARG_LINK_ID to linkId),
            ),
        )

    @Test
    fun blankLinkId_resolvesToTerminalUnavailable() = runTest {
        val sheet = vm(GapsRepo(), GapsDownloader(), linkId = null)
        runCurrent()
        val state = sheet.uiState.value
        assertTrue(state is PublicShareUiState.Terminal)
        assertEquals(PublicShareState.UNAVAILABLE, (state as PublicShareUiState.Terminal).state)
    }

    @Test
    fun onPasswordChange_updatesField_andClearsPriorError() = runTest {
        val repo = GapsRepo(
            ApiResult.Success(gapsShare(PublicShareState.AVAILABLE, passwordRequired = true)),
        )
        // a wrong-password download re-raises the gate with an error first.
        val downloader = GapsDownloader {
            flow { emit(DownloadOutcome.Error(ApiError(403, "forbidden"), retryable = false)) }
        }
        val sheet = vm(repo, downloader)
        runCurrent()
        sheet.onPasswordChange("wrong")
        sheet.submitPassword()
        runCurrent()
        assertTrue((sheet.uiState.value as PublicShareUiState.Info).passwordError != null)

        // typing again clears the error and updates the field.
        sheet.onPasswordChange("retry")
        val info = sheet.uiState.value as PublicShareUiState.Info
        assertEquals("retry", info.password)
        assertNull(info.passwordError)
    }

    @Test
    fun download_doubleSendGuard_ignoresSecondTapWhileInFlight() = runTest {
        val gate = CompletableDeferred<Unit>()
        val downloader = GapsDownloader {
            flow {
                emit(DownloadOutcome.InProgress(1L, 10L))
                gate.await() // hold the download open.
            }
        }
        val sheet = vm(GapsRepo(), downloader)
        runCurrent()

        sheet.download()
        runCurrent()
        assertTrue((sheet.uiState.value as PublicShareUiState.Info).downloading)

        sheet.download() // ignored: a download is in flight.
        runCurrent()
        assertEquals(1, downloader.calls)

        gate.complete(Unit) // release the parked collector so the scope can finish.
    }

    @Test
    fun download_inProgress_projectsFractionalProgress() = runTest {
        val gate = CompletableDeferred<Unit>()
        val downloader = GapsDownloader {
            flow {
                emit(DownloadOutcome.InProgress(25L, 100L))
                gate.await()
            }
        }
        val sheet = vm(GapsRepo(), downloader)
        runCurrent()
        sheet.download()
        runCurrent()
        val info = sheet.uiState.value as PublicShareUiState.Info
        assertTrue(info.downloading)
        assertEquals(0.25f, info.progress)
        gate.complete(Unit)
    }

    @Test
    fun download_nonAuthError_onNonPasswordShare_surfacesInline_withoutGate() = runTest {
        val downloader = GapsDownloader {
            flow { emit(DownloadOutcome.Error(ApiError(500, "server"), retryable = true)) }
        }
        val sheet = vm(GapsRepo(), downloader) // share is NOT password-protected.
        runCurrent()
        sheet.download()
        runCurrent()
        val info = sheet.uiState.value as PublicShareUiState.Info
        // a 500 is not an auth error -> the inline error shows, no password gate is raised.
        assertFalse(info.needsPassword)
        assertEquals("server", info.passwordError)
        assertFalse(info.downloading)
    }

    @Test
    fun resolveFailure_5xx_isRetryableError() = runTest {
        val repo = GapsRepo(ApiResult.Failure(ApiError(status = 503, message = "down")))
        val sheet = vm(repo, GapsDownloader())
        runCurrent()
        val state = sheet.uiState.value as PublicShareUiState.Error
        assertEquals("down", state.message)
        assertTrue(state.retryable)
    }

    @Test
    fun resolveFailure_4xx_isNotRetryableError() = runTest {
        val repo = GapsRepo(ApiResult.Failure(ApiError(status = 404, message = "missing")))
        val sheet = vm(repo, GapsDownloader())
        runCurrent()
        val state = sheet.uiState.value as PublicShareUiState.Error
        assertFalse(state.retryable)
    }
}

/** AND-338 - distinct top-level fake-helper names for this gaps suite. */
private fun gapsShare(state: PublicShareState, passwordRequired: Boolean) = PublicShare(
    linkId = "lnk_1",
    fileName = "report.pdf",
    sizeBytes = 1234L,
    contentType = "application/pdf",
    expiresAt = null,
    passwordRequired = passwordRequired,
    state = state,
)
