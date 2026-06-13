package com.testlogon.android.feature.share

import android.net.Uri
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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-335 - unit tests for [PublicShareViewModel] with a fake repo + fake downloader. init resolve -> Info;
 * password gate; download -> progress -> success; wrong password re-raises the gate; terminal states.
 * MainDispatcherRule + runCurrent (NO advanceUntilIdle); org.junit.Test; distinct fake-helper names.
 */
class PublicShareViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo(
        var resolveResult: ApiResult<PublicShare> =
            ApiResult.Success(publicShare(PublicShareState.AVAILABLE, passwordRequired = false)),
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

    private class FakeDownloader(
        var outcomes: List<DownloadOutcome> = emptyList(),
    ) : ShareDownloader {
        var calls = 0
        var lastPassword: String? = null
        override fun downloadPublic(
            linkId: String,
            password: String?,
            fileName: String?,
            contentType: String?,
        ): Flow<DownloadOutcome> = flow {
            calls++
            lastPassword = password
            outcomes.forEach { emit(it) }
        }
    }

    private fun vm(repo: ShareRepository, downloader: ShareDownloader): PublicShareViewModel =
        PublicShareViewModel(
            repo,
            downloader,
            SavedStateHandle(mapOf(PublicShareViewModel.ARG_LINK_ID to "lnk_1")),
        )

    @Test
    fun init_resolvesToInfo() = runTest {
        val sheet = vm(FakeRepo(), FakeDownloader())
        runCurrent()
        val state = sheet.uiState.value
        assertTrue(state is PublicShareUiState.Info)
        assertEquals("report.pdf", (state as PublicShareUiState.Info).share.fileName)
        assertEquals(false, state.needsPassword)
    }

    @Test
    fun passwordRequired_showsGate_thenSubmitDownloads() = runTest {
        val repo = FakeRepo(
            ApiResult.Success(publicShare(PublicShareState.AVAILABLE, passwordRequired = true)),
        )
        val savedUri = uri()
        val downloader = FakeDownloader(
            outcomes = listOf(
                DownloadOutcome.InProgress(50L, 100L),
                DownloadOutcome.Success(savedUri, "report.pdf"),
            ),
        )
        val sheet = vm(repo, downloader)
        runCurrent()
        assertTrue((sheet.uiState.value as PublicShareUiState.Info).needsPassword)

        sheet.onPasswordChange("secret")
        sheet.submitPassword()
        runCurrent()

        val state = sheet.uiState.value as PublicShareUiState.Info
        assertEquals("secret", downloader.lastPassword)
        assertEquals(false, state.needsPassword)
        assertEquals(false, state.downloading)
        assertEquals("report.pdf", state.savedFileName)
    }

    @Test
    fun download_emitsProgress_thenSuccess() = runTest {
        val downloader = FakeDownloader(
            outcomes = listOf(
                DownloadOutcome.InProgress(25L, 100L),
                DownloadOutcome.Success(uri(), "report.pdf"),
            ),
        )
        val sheet = vm(FakeRepo(), downloader)
        runCurrent()
        sheet.download()
        runCurrent()
        val state = sheet.uiState.value as PublicShareUiState.Info
        assertEquals(1, downloader.calls)
        assertEquals("report.pdf", state.savedFileName)
        assertEquals(false, state.downloading)
    }

    @Test
    fun wrongPassword_reRaisesGate() = runTest {
        val repo = FakeRepo(
            ApiResult.Success(publicShare(PublicShareState.AVAILABLE, passwordRequired = true)),
        )
        val downloader = FakeDownloader(
            outcomes = listOf(DownloadOutcome.Error(ApiError(403, "forbidden"), retryable = false)),
        )
        val sheet = vm(repo, downloader)
        runCurrent()
        sheet.onPasswordChange("wrong")
        sheet.submitPassword()
        runCurrent()
        val state = sheet.uiState.value as PublicShareUiState.Info
        assertTrue(state.needsPassword)
        assertTrue(state.passwordError != null)
    }

    @Test
    fun terminalStates_render() = runTest {
        listOf(
            PublicShareState.EXPIRED,
            PublicShareState.REVOKED,
            PublicShareState.EXHAUSTED,
        ).forEach { terminal ->
            val repo = FakeRepo(ApiResult.Success(publicShare(terminal, passwordRequired = false)))
            val sheet = vm(repo, FakeDownloader())
            runCurrent()
            val state = sheet.uiState.value
            assertTrue(state is PublicShareUiState.Terminal)
            assertEquals(terminal, (state as PublicShareUiState.Terminal).state)
        }
    }

    @Test
    fun resolveFailure_showsError() = runTest {
        val repo = FakeRepo(ApiResult.NetworkError(java.io.IOException("offline")))
        val sheet = vm(repo, FakeDownloader())
        runCurrent()
        assertTrue(sheet.uiState.value is PublicShareUiState.Error)
    }
}

/** AND-335 - distinct fake-helper names (top-level). */
private fun publicShare(state: PublicShareState, passwordRequired: Boolean) = PublicShare(
    linkId = "lnk_1",
    fileName = "report.pdf",
    sizeBytes = 1234L,
    contentType = "application/pdf",
    expiresAt = null,
    passwordRequired = passwordRequired,
    state = state,
)

/** A throwaway Uri stand-in (the VM only reads displayName from Success, never the Uri itself). */
private fun uri(): Uri = org.mockito.Mockito.mock(Uri::class.java)
